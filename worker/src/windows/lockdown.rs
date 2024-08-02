#![allow(non_snake_case)]
#![allow(clippy::upper_case_acronyms)]

use core::ffi::c_void;
use core::ptr::{null, null_mut};
use core::sync::atomic::compiler_fence;
use iris_ipc::os::{Handle, IpcChannel};
use iris_ipc::{CrossPlatformHandle, CrossPlatformIpcChannel, IPC_MESSAGE_MAX_SIZE};
use iris_ipc_messages::os::{IPCRequest, IPCResponse};
use log::{debug, info};
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use winapi::shared::basetsd::ULONG_PTR;
use winapi::shared::minwindef::{BYTE, DWORD, WORD};
use winapi::shared::ntdef::{
    HANDLE, NTSTATUS, OBJECT_ATTRIBUTES, PULONG, PVOID, ULONG, UNICODE_STRING,
};
use winapi::shared::ntstatus::{STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect, VirtualQuery};
use winapi::um::processthreadsapi::{FlushInstructionCache, GetCurrentProcess};
use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
use winapi::um::winnt::{
    ACCESS_MASK, IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386,
    IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, LARGE_INTEGER,
    MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ,
    PAGE_READWRITE,
};

// Constants from winternl.h not yet exported by winapi
const FILE_OPEN: u32 = 1;

// From WDK headers
#[repr(C)]
struct IO_STATUS_BLOCK {
    Status: NTSTATUS,
    Information: ULONG_PTR,
}

const fn NtCurrentProcess() -> HANDLE {
    usize::MAX as HANDLE
}
const STATUS_SUCCESS: NTSTATUS = 0;
const IMAGE_DOS_HDR_MAGIC: WORD = 0x5A4D; // "MZ" in ASCII
const IMAGE_PE_HDR_MAGIC: DWORD = 0x00004550; // "PE\0\0" in ASCII

// From https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
#[repr(u32)]
enum PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
}
#[repr(C)]
struct LIST_ENTRY {
    Flink: *const c_void,
    Blink: *const c_void,
}
#[repr(C)]
#[allow(non_camel_case_types)]
struct LDR_DATA_TABLE_ENTRY {
    Reserved1: [PVOID; 2],
    InMemoryOrderLinks: LIST_ENTRY,
    Reserved2: [PVOID; 2],
    DllBase: PVOID,
}
#[repr(C)]
struct PEB_LDR_DATA {
    Reserved1: [BYTE; 8],
    Reserved2: [PVOID; 3],
    InMemoryOrderModuleList: LIST_ENTRY,
}
#[repr(C)]
struct PEB {
    Reserved1: [BYTE; 2],
    BeingDebugged: BYTE,
    Reserved2: BYTE,
    Reserved3: [PVOID; 2],
    Ldr: *const PEB_LDR_DATA,
}
#[repr(C)]
struct PROCESS_BASIC_INFORMATION {
    Reserved1: PVOID,
    PebBaseAddress: *const PEB,
    Reserved2: PVOID,
    Reserved3: PVOID,
    UniqueProcessId: ULONG_PTR,
    Reserved4: PVOID,
}
#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: PROCESSINFOCLASS,
        ProcessInformation: PVOID,
        ProcessInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> NTSTATUS;
}

fn align_ptr<T>(unaligned: *mut T, align: usize) -> *mut T {
    unsafe { unaligned.add(unaligned.align_offset(align)) }
}

fn hook_function(dll_name: &str, func_name: &str, new_ptr: *const fn()) {
    // Get the unmodified address of NtCreateFile() in ntdll.dll
    let dll_name_cstr = CString::new(dll_name).unwrap();
    let h_dll = unsafe { LoadLibraryA(dll_name_cstr.as_ptr()) };
    if h_dll.is_null() {
        panic!(
            "Unable to get reference to {} : error {}",
            dll_name,
            unsafe { GetLastError() }
        );
    }
    let func_name_cstr = CString::new(func_name).unwrap();
    let orig_ptr = unsafe { GetProcAddress(h_dll, func_name_cstr.as_ptr()) };
    if orig_ptr.is_null() {
        panic!(
            "Unable to find function {} within {} : error {}",
            func_name,
            dll_name,
            unsafe { GetLastError() }
        );
    }
    debug!(
        "Hooking {} function {} : previously at {:?} , now at {:?}",
        dll_name, func_name, orig_ptr, new_ptr
    );

    // Get the PEB address. Using NtQueryInformationProcess avoid the need to use architecture-specific assembly
    // (e.g. read GS on x64) and is now even documented on MSDN. The syscall uses a hardcoded size and returns
    // STATUS_INFO_LENGTH_MISMATCH without telling how much it needs, though.
    let mut required_bytes: ULONG = 0;
    let mut basic_info: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let res = unsafe {
        NtQueryInformationProcess(
            NtCurrentProcess(),
            PROCESSINFOCLASS::ProcessBasicInformation,
            &mut basic_info as *mut _ as *mut _,
            std::mem::size_of_val(&basic_info) as u32,
            &mut required_bytes as *mut _,
        )
    };
    if res != STATUS_SUCCESS || basic_info.PebBaseAddress.is_null() {
        panic!("NtQueryInformationProcess() failed with code {res}");
    }
    let list_head = unsafe {
        &((*(*basic_info.PebBaseAddress).Ldr).InMemoryOrderModuleList) as *const LIST_ENTRY
    };
    let mut list_pos = unsafe { (*list_head).Flink as *const LIST_ENTRY };
    // Rust doesn't have offsetof() yet, so we have to make do
    let dummy: LDR_DATA_TABLE_ENTRY = unsafe { std::mem::zeroed() };
    let list_entry_to_dllbase_offset =
        (&dummy.DllBase as *const _ as usize) - (&dummy.InMemoryOrderLinks as *const _ as usize);

    // Enumerate all loaded DLLs and find their base address
    while list_pos != list_head {
        let dos_header = unsafe {
            *(((list_pos as *const u8).add(list_entry_to_dllbase_offset))
                as *const *const IMAGE_DOS_HEADER)
        };
        let pe_base = dos_header as *const i8;

        // Their DOS header is at the DLL base address
        let magic = unsafe { (*dos_header).e_magic };
        if magic != IMAGE_DOS_HDR_MAGIC {
            panic!("Invalid DOS header encountered at address {dos_header:?} : {magic}");
        }

        // Compute the address of the PE header
        let pe_header = unsafe {
            (dos_header as *const u8).offset((*dos_header).e_lfanew as isize)
                as *const IMAGE_NT_HEADERS32
        };
        let magic = unsafe { (*pe_header).Signature };
        if magic != IMAGE_PE_HDR_MAGIC {
            panic!("Invalid PE header encountered at address {pe_header:?} : {magic}");
        }

        // Compute the address of the data directories (their array offset depends on the architecture the DLL was compiled for)
        let arch = unsafe { (*pe_header).FileHeader.Machine };
        let data_directories = if arch == IMAGE_FILE_MACHINE_AMD64 {
            unsafe {
                &((*(pe_header as *const IMAGE_NT_HEADERS64))
                    .OptionalHeader
                    .DataDirectory) as *const IMAGE_DATA_DIRECTORY
            }
        } else if arch == IMAGE_FILE_MACHINE_I386 {
            unsafe { &((*pe_header).OptionalHeader.DataDirectory) as *const IMAGE_DATA_DIRECTORY }
        } else {
            panic!("DLL at {dos_header:?} uses unknown architecture ID {arch}");
        };

        // Patch exports before imports, so that there is no race condition: if a thread starts importing before we patch,
        // we will fix it during the imports fixup, and if it imports after we patch, it will have the right address.
        let exports_directory =
            unsafe { *(data_directories.offset(IMAGE_DIRECTORY_ENTRY_EXPORT as isize)) };
        if exports_directory.VirtualAddress != 0 && exports_directory.Size != 0 {
            let exports_directory = unsafe {
                pe_base.offset(exports_directory.VirtualAddress as isize)
                    as *const IMAGE_EXPORT_DIRECTORY
            };
            let module_original_name =
                unsafe { CStr::from_ptr(pe_base.offset((*exports_directory).Name as isize)) };
            debug!(
                "Checking if {} at {:?} exports functions to hook...",
                module_original_name.to_string_lossy(),
                pe_base
            );
            let number_of_exports = unsafe { (*exports_directory).NumberOfFunctions };
            let function_rvas = unsafe {
                pe_base.offset((*exports_directory).AddressOfFunctions as isize) as *mut u32
            };
            let mut trampoline_addr = None;
            for export_nb in 0..number_of_exports {
                let rva_address = unsafe { function_rvas.offset(export_nb as isize) };
                let exported_ptr = unsafe { pe_base.offset((*rva_address) as isize) };
                if exported_ptr == (orig_ptr as *const i8) {
                    debug!(
                        "Hooking export ordinal {}",
                        export_nb + unsafe { (*exports_directory).Base }
                    );
                    let (a, b) = (pe_base as usize, new_ptr as usize);
                    let hook_rva: u32 = if a < b && TryInto::<u32>::try_into(b - a).is_ok() {
                        (b - a).try_into().unwrap()
                    } else {
                        if trampoline_addr.is_none() {
                            // TODO: perform an IPC for the broker to do this setup (we might have ACG enabled and fail to do this)
                            debug!("Trampoline needed");
                            let alloc_granularity = {
                                let mut sysinfo: SYSTEM_INFO = unsafe { std::mem::zeroed() };
                                unsafe {
                                    GetSystemInfo(&mut sysinfo);
                                }
                                sysinfo.dwAllocationGranularity as usize
                            };
                            debug!("Allocation granularity: {} bytes", alloc_granularity);
                            let mut ptr_candidate =
                                align_ptr(pe_base as *mut i8, alloc_granularity);
                            let mut mem_info: MEMORY_BASIC_INFORMATION =
                                unsafe { std::mem::zeroed() };
                            loop {
                                ptr_candidate = unsafe {
                                    align_ptr(
                                        ptr_candidate.add(mem_info.RegionSize),
                                        alloc_granularity,
                                    )
                                };
                                let res = unsafe {
                                    VirtualQuery(
                                        ptr_candidate as *const _,
                                        &mut mem_info as *mut _,
                                        std::mem::size_of_val(&mem_info),
                                    )
                                };
                                if res == 0 {
                                    panic!(
                                        "VirtualQuery({:?}) failed with error {}",
                                        ptr_candidate,
                                        unsafe { GetLastError() }
                                    );
                                }
                                if mem_info.State != MEM_FREE {
                                    continue;
                                }
                                // TODO: randomize trampoline location within a larger allocation?
                                let res = unsafe {
                                    VirtualAlloc(
                                        ptr_candidate as *mut _,
                                        alloc_granularity,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE,
                                    )
                                };
                                if res.is_null() {
                                    panic!(
                                        "VirtualAlloc({:?}) failed with error {}",
                                        ptr_candidate,
                                        unsafe { GetLastError() }
                                    );
                                }
                                debug!("Trampoline at {:?}", ptr_candidate);
                                write_trampoline(ptr_candidate, new_ptr);
                                let mut unused: DWORD = 0;
                                let res = unsafe {
                                    VirtualProtect(
                                        ptr_candidate as *mut _,
                                        alloc_granularity,
                                        PAGE_EXECUTE_READ,
                                        &mut unused,
                                    )
                                };
                                if res == 0 {
                                    unsafe {
                                        VirtualFree(
                                            ptr_candidate as *mut _,
                                            alloc_granularity,
                                            MEM_RELEASE,
                                        )
                                    };
                                    panic!("VirtualProtect({:?}, PAGE_EXECUTE_READ) failed with error {}", ptr_candidate, unsafe { GetLastError() });
                                }
                                // Ensure instruction cache is coherent before making anyone jump into our trampoline
                                let res = unsafe {
                                    FlushInstructionCache(
                                        GetCurrentProcess(),
                                        ptr_candidate as *mut _,
                                        alloc_granularity,
                                    )
                                };
                                if res == 0 {
                                    unsafe {
                                        VirtualFree(
                                            ptr_candidate as *mut _,
                                            alloc_granularity,
                                            MEM_RELEASE,
                                        )
                                    };
                                    panic!(
                                        "FlushInstructionCache({:?}) failed with error {}",
                                        ptr_candidate,
                                        unsafe { GetLastError() }
                                    );
                                }
                                break;
                            }
                            trampoline_addr = Some(ptr_candidate);
                        }
                        (unsafe { trampoline_addr.unwrap().offset_from(pe_base) }) as u32
                    };

                    // Ensure the entire trampoline has been written out before making
                    // callers use it
                    compiler_fence(Ordering::Release);

                    hotpatch_u32(hook_rva, rva_address);

                    // Note: we keep looking for other exports with the same address instead of just stopping here.
                    // Some DLLs export the same function more than once with different names (e.g. ntdll!NtCreateFile == ntdll!ZwCreateFile)
                }
            }
        }

        // Patch imports (imports table can be NULL and 0-sized if the DLL does not import anything!)
        let imports_directory =
            unsafe { *(data_directories.offset(IMAGE_DIRECTORY_ENTRY_IMPORT as isize)) };
        if imports_directory.VirtualAddress != 0 && imports_directory.Size != 0 {
            let import_descriptors = unsafe {
                pe_base.offset(imports_directory.VirtualAddress as isize)
                    as *const IMAGE_IMPORT_DESCRIPTOR
            };
            for import_descriptor_nb in 0.. {
                let import_descriptor =
                    unsafe { *(import_descriptors.offset(import_descriptor_nb)) };

                // The end of the IMAGE_DIRECTORY_ENTRY_IMPORT array is marked by an entry with all fields set to 0
                if import_descriptor.FirstThunk == 0 || import_descriptor.Name == 0 {
                    break;
                }
                // Enumerate all functions imported, if any
                if import_descriptor.FirstThunk == 0 {
                    continue;
                }
                let thunks = unsafe { pe_base.offset(import_descriptor.FirstThunk as isize) };
                for thunk_nb in 0.. {
                    let thunk = if arch == IMAGE_FILE_MACHINE_AMD64 {
                        unsafe { *(thunks.offset(thunk_nb * 8) as *const u64) }
                    } else if arch == IMAGE_FILE_MACHINE_I386 {
                        unsafe { (*(thunks.offset(thunk_nb * 4) as *const u32)) as u64 }
                    } else {
                        panic!("DLL at {dos_header:?} uses unknown architecture ID {arch}");
                    };
                    // The end of the IMAGE_THUNK_DATA array is marked by an entry with all fields set to 0
                    if thunk == 0 {
                        break;
                    }
                    if thunk == orig_ptr as u64 {
                        debug!("Hooking import number {}", thunk_nb);
                        if arch == IMAGE_FILE_MACHINE_AMD64 {
                            hotpatch_u64(
                                (new_ptr as usize).try_into().expect("pointer too large"),
                                unsafe { thunks.offset(thunk_nb * 8) } as *mut u64,
                            );
                        } else if arch == IMAGE_FILE_MACHINE_I386 {
                            hotpatch_u32(
                                (new_ptr as usize).try_into().expect("pointer too large"),
                                unsafe { thunks.offset(thunk_nb * 4) } as *mut u32,
                            );
                        } else {
                            panic!("DLL at {dos_header:?} uses unknown architecture ID {arch}");
                        }
                    }
                }
            }
        }
        list_pos = unsafe { (*list_pos).Flink as *const LIST_ENTRY };
    }
}

#[cfg(all(target_arch = "x86", target_pointer_width = "32"))]
fn write_trampoline(location: *mut i8, target_function: *const fn()) {
    let jump_offset: i32 = unsafe {
        (target_function as *const i8)
            .offset_from(location.add(1 + 4) as *const i8) // JMP will be 5-byte-long, and a jump of 0 means the next instruction
            .try_into()
            .expect("hook too far away from original function")
    };
    let mut patch = vec![];
    // x86 32-bit relative jump
    patch.push(0xE9);
    patch.extend_from_slice(&jump_offset.to_le_bytes());
    // Applying the patch is safe as long as this functions is only called with a writable location
    // where a JMP patch is actually wanted.
    unsafe {
        std::ptr::copy_nonoverlapping(patch.as_ptr(), location as *mut _, patch.len());
    }
}

#[cfg(target_arch = "x86_64")]
fn write_trampoline(location: *mut i8, target_function: *const fn()) {
    let target_high = ((target_function as u64) >> 32) as u32;
    let target_low = (target_function as u64) as u32;
    // Note: we use memcpy instead of patching bytes using raw pointers to avoid memory write alignment issues
    let mut patch = vec![];
    // x64 PUSH with 32-bit immediate
    patch.push(0x68);
    patch.extend_from_slice(&target_low.to_le_bytes());
    // x64 MOV DWORD PTR [RSP+4], 32-bit immediate
    patch.extend_from_slice(&[0xC7, 0x44, 0x24, 0x04]);
    patch.extend_from_slice(&target_high.to_le_bytes());
    // x64 RET
    patch.push(0xC3);
    // Applying the patch is safe as long as this functions is only called with a writable location
    // where a JMP patch is actually wanted.
    unsafe {
        std::ptr::copy_nonoverlapping(patch.as_ptr(), location as *mut _, patch.len());
    }
}

fn hotpatch_u32(new_value: u32, location: *mut u32) {
    let old_protection = unprotect_memory_area(location as *const _, 4);
    let atomic = unsafe { &*(location as *const AtomicU32) };
    atomic.store(new_value, Ordering::Relaxed);
    reprotect_memory_area(location as *const _, 4, old_protection);
}

fn hotpatch_u64(new_value: u64, location: *mut u64) {
    let old_protection = unprotect_memory_area(location as *const _, 8);
    let atomic = unsafe { &*(location as *const AtomicU64) };
    atomic.store(new_value, Ordering::Relaxed);
    reprotect_memory_area(location as *const _, 8, old_protection);
}

fn unprotect_memory_area(location: *const u8, size: usize) -> DWORD {
    let mut before: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let res = unsafe {
        VirtualQuery(
            location as *const _,
            &mut before as *mut _,
            std::mem::size_of_val(&before),
        )
    };
    if res == 0 {
        panic!(
            "Failed to query memory protection of {:?} : error {}",
            location,
            unsafe { GetLastError() }
        );
    }
    let mut old_protection: DWORD = 0;
    let res = unsafe {
        VirtualProtect(
            location as *mut _,
            size,
            PAGE_READWRITE,
            &mut old_protection as *mut _,
        )
    };
    if res == 0 {
        panic!(
            "Failed to change memory protection of {:?} : error {}",
            location,
            unsafe { GetLastError() }
        );
    }
    old_protection
}

fn reprotect_memory_area(location: *const u8, size: usize, old_protection: DWORD) {
    let mut hotpatch_protection: DWORD = 0;
    let res = unsafe {
        VirtualProtect(
            location as *mut _,
            size,
            old_protection,
            &mut hotpatch_protection as *mut _,
        )
    };
    if res == 0 {
        panic!(
            "Failed to reset memory protection of {:?} : error {}",
            location,
            unsafe { GetLastError() }
        );
    }
}

extern "system" fn hook_ntcreatefile(
    file_handle: *mut HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    io_status_block: *mut IO_STATUS_BLOCK,
    allocation_size: *mut LARGE_INTEGER,
    file_attributes: ULONG,
    share_access: ULONG,
    create_disposition: ULONG,
    create_options: ULONG,
    ea_buffer: PVOID,
    ea_length: ULONG,
) -> NTSTATUS {
    if file_handle.is_null() || object_attributes.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        (*file_handle) = null_mut();
        (*io_status_block).Information = 0;
    }
    let h_rootdirectory = unsafe { (*object_attributes).RootDirectory };
    if !h_rootdirectory.is_null() || ea_length != 0 {
        return STATUS_NOT_SUPPORTED;
    }
    let path = unsafe { (*object_attributes).ObjectName };
    if path.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let path = unsafe {
        std::slice::from_raw_parts(
            (*path).Buffer,
            (*path).Length as usize / std::mem::size_of::<u16>(),
        )
    };
    let path = String::from_utf16_lossy(path);
    let allocation_size = if allocation_size.is_null() {
        0
    } else {
        unsafe { *(*allocation_size).QuadPart() }
    };
    let ea = unsafe {
        std::slice::from_raw_parts(
            // from_raw_parts() requires a non-null pointer, even for an empty slice when no EA is set.
            if ea_buffer.is_null() {
                NonNull::<u8>::dangling().as_ptr()
            } else {
                ea_buffer as *const u8
            },
            ea_length as usize,
        )
    };
    let request = IPCRequest::NtCreateFile {
        desired_access,
        path: &path,
        allocation_size,
        file_attributes,
        share_access,
        create_disposition,
        create_options,
        ea,
    };
    match send_recv(&request, None) {
        (IPCResponse::NtCreateFile { io_status, code }, handle) => {
            if let Some(handle) = handle {
                unsafe {
                    let handle: usize = handle
                        .into_raw()
                        .try_into()
                        .expect("invalid handle value returned from broker");
                    (*file_handle) = handle as HANDLE;
                }
            }
            unsafe {
                (*io_status_block).Information = io_status;
            };
            code as NTSTATUS
        }
        (IPCResponse::SyscallResult(code), None) => code as NTSTATUS,
        other => panic!("Unexpected response from broker to NtCreateFile request: {other:?}"),
    }
}

extern "system" fn hook_ntopenfile(
    file_handle: *mut HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    io_status_block: *mut IO_STATUS_BLOCK,
    share_access: ULONG,
    open_options: ULONG,
) -> NTSTATUS {
    if file_handle.is_null() || object_attributes.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        (*file_handle) = null_mut();
        (*io_status_block).Information = 0;
    }
    let h_rootdirectory = unsafe { (*object_attributes).RootDirectory };
    if !h_rootdirectory.is_null() {
        return STATUS_NOT_SUPPORTED;
    }
    let path = unsafe { (*object_attributes).ObjectName };
    if path.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let path = unsafe {
        std::slice::from_raw_parts(
            (*path).Buffer,
            (*path).Length as usize / std::mem::size_of::<u16>(),
        )
    };
    let path = String::from_utf16_lossy(path);
    let request = IPCRequest::NtCreateFile {
        desired_access,
        path: &path,
        allocation_size: 0,
        file_attributes: 0,
        share_access,
        create_disposition: FILE_OPEN,
        create_options: open_options,
        ea: &[],
    };
    match send_recv(&request, None) {
        (IPCResponse::NtCreateFile { io_status, code }, handle) => {
            if let Some(handle) = handle {
                unsafe {
                    let handle: usize = handle
                        .into_raw()
                        .try_into()
                        .expect("invalid handle value returned from broker");
                    (*file_handle) = handle as HANDLE;
                }
            }
            unsafe {
                (*io_status_block).Information = io_status;
            };
            code as NTSTATUS
        }
        (IPCResponse::SyscallResult(code), None) => code as NTSTATUS,
        other => panic!("Unexpected response from broker to NtCreateFile request: {other:?}"),
    }
}

extern "system" fn hook_ntcreatekey(
    key_handle: *mut HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    title_index: ULONG,
    class: *mut UNICODE_STRING,
    create_options: ULONG,
    out_disposition: *mut ULONG,
) -> NTSTATUS {
    if key_handle.is_null() || object_attributes.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        (*key_handle) = null_mut();
        if !out_disposition.is_null() {
            (*out_disposition) = 0;
        }
    }
    let h_rootdirectory = unsafe { (*object_attributes).RootDirectory };
    if !h_rootdirectory.is_null() || title_index != 0 {
        return STATUS_NOT_SUPPORTED;
    }
    let path = unsafe { (*object_attributes).ObjectName };
    if path.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let path = unsafe {
        std::slice::from_raw_parts(
            (*path).Buffer,
            (*path).Length as usize / std::mem::size_of::<u16>(),
        )
    };
    let path = String::from_utf16_lossy(path);
    let class = unsafe {
        if class.is_null() {
            None
        } else {
            Some(String::from_utf16_lossy(std::slice::from_raw_parts(
                (*class).Buffer,
                (*class).Length as usize / std::mem::size_of::<u16>(),
            )))
        }
    };
    let request = IPCRequest::NtCreateKey {
        desired_access,
        path: &path,
        title_index,
        class: class.as_deref(),
        create_options,
        do_create: true,
    };
    match send_recv(&request, None) {
        (IPCResponse::NtCreateKey { disposition, code }, handle) => {
            if let Some(handle) = handle {
                unsafe {
                    let handle: usize = handle
                        .into_raw()
                        .try_into()
                        .expect("invalid handle value returned from broker");
                    (*key_handle) = handle as HANDLE;
                }
            }
            if !out_disposition.is_null() {
                unsafe {
                    (*out_disposition) = disposition;
                };
            }
            code as NTSTATUS
        }
        (IPCResponse::SyscallResult(code), None) => code as NTSTATUS,
        other => panic!("Unexpected response from broker to NtCreateKey request: {other:?}"),
    }
}

// TODO: merge with Linux
fn send_recv(request: &IPCRequest, handle: Option<&Handle>) -> (IPCResponse, Option<Handle>) {
    let mut ipc = get_ipc_channel();
    debug!("Sending IPC request {:?} (handle: {:?})", &request, &handle);
    let mut buf = [0u8; IPC_MESSAGE_MAX_SIZE];
    ipc.send(&request, handle, &mut buf)
        .expect("unable to send IPC request to broker");
    let (resp, handle) = ipc
        .recv(&mut buf)
        .expect("unable to receive IPC response from broker")
        .expect("broker closed our IPC pipe while expecting its response");
    debug!("Received IPC response {:?} (handle: {:?})", &resp, &handle);
    (resp, handle)
}

// TODO: use a thread_local!{} pipe, and a global mutex-protected pipe to request new thread-specific ones
// OR: create a global pool of threads which wait on a global lock-free queue
// AND/OR: make the ipc pipe multiplexed by adding random transaction IDs
static mut IPC_CHANNEL_SINGLETON: *const Mutex<IpcChannel> = null();
fn get_ipc_channel() -> MutexGuard<'static, IpcChannel> {
    unsafe { (*IPC_CHANNEL_SINGLETON).lock().unwrap() }
}

pub(crate) fn lower_final_sandbox_privileges(ipc: IpcChannel) {
    // Initialization of globals. This is safe as long as we are only called once
    unsafe {
        // Store the IPC pipe to handle all future syscall requests
        IPC_CHANNEL_SINGLETON = Box::leak(Box::new(Mutex::new(ipc))) as *const _;
    }
    let resp = send_recv(&IPCRequest::InitializationRequest, None);
    match resp {
        (IPCResponse::InitializationResponse { .. }, None) => (),
        other => panic!("unexpected initial response received from broker: {other:?}"),
    }
    hook_function(
        "ntdll.dll",
        "NtCreateFile",
        hook_ntcreatefile as *const fn(),
    );
    hook_function("ntdll.dll", "NtOpenFile", hook_ntopenfile as *const fn());
    hook_function("ntdll.dll", "NtCreateKey", hook_ntcreatekey as *const fn());
    info!("Worker ready for work");
}
