#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(clippy::enum_variant_names)]

use core::ptr::null_mut;
use iris_broker::Worker;
use iris_ipc::{os::Handle, CrossPlatformHandle, HandleError};
use log::{debug, info, warn};
use std::convert::TryInto;
use std::ffi::CString;
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::os::windows::prelude::IntoRawHandle;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{BYTE, DWORD};
use winapi::shared::ntdef::{HANDLE, NTSTATUS, PULONG, PVOID, PWSTR, ULONG, USHORT, WCHAR};
use winapi::shared::ntstatus::{STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS};
use winapi::um::debugapi::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, WaitForDebugEvent,
};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::CreateFileW;
use winapi::um::fileapi::OPEN_EXISTING;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::handleapi::{CloseHandle, DuplicateHandle};
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::minwinbase::{DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT, STILL_ACTIVE};
use winapi::um::processthreadsapi::OpenProcessToken;
use winapi::um::processthreadsapi::SetThreadToken;
use winapi::um::processthreadsapi::{GetCurrentProcess, GetExitCodeProcess, OpenProcess};
use winapi::um::securitybaseapi::{DuplicateToken, RevertToSelf};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{INFINITE, WAIT_OBJECT_0};
use winapi::um::winnt::{
    SecurityImpersonation, DBG_CONTINUE, DUPLICATE_SAME_ACCESS, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, SYNCHRONIZE,
    TOKEN_DUPLICATE,
};

// NT paths are stored as UNICODE_STRINGs, which store their binary length in USHORTs
const MAX_NT_OBJECT_PATH_LEN: usize = 32767;
const SystemHandleInformation: ULONG = 16;

#[repr(u32)]
enum SYSTEM_INFORMATION_CLASS {
    SystemHandleInformation = 16,
}

#[repr(u32)]
enum OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2,
    ObjectAllInformation = 3,
}

#[derive(Debug, Clone)]
#[repr(C)]
struct SYSTEM_HANDLE {
    ProcessId: ULONG,
    ObjectTypeNumber: BYTE,
    Flags: BYTE,
    Handle: USHORT,
    Object: PVOID,
    GrantedAccess: DWORD,
}

#[repr(C)]
struct SYSTEM_HANDLE_INFORMATION {
    HandleCount: ULONG,
    Handles: [SYSTEM_HANDLE; 1],
}

#[repr(C)]
struct UNICODE_STRING {
    Length: USHORT,
    MaximumLength: USHORT,
    Buffer: PWSTR,
}

#[repr(C)]
struct PUBLIC_OBJECT_TYPE_INFORMATION {
    TypeName: UNICODE_STRING,
    Reserved: [ULONG; 22],
}

#[repr(C)]
struct OBJECT_NAME_INFORMATION {
    Name: UNICODE_STRING,
    Buffer: [WCHAR; MAX_NT_OBJECT_PATH_LEN],
}

#[repr(C)]
struct OBJECT_TYPE_INFORMATION {
    Name: UNICODE_STRING,
    Opaque: [u8; 88], // these struct are stored consecutively as an array, so we need to get their size right
}

#[repr(C)]
struct OBJECT_TYPES_INFORMATION {
    NumberOfObjectTypes: ULONG,
    ObjectTypes: [OBJECT_TYPE_INFORMATION; 256], // types are indexed in the kernel using a UCHAR so there can be only 256
    Opaque: [u8; 256 * 65536], // room for the UNICODE_STRING buffers from ObjectTypes[], whose size is indexed on USHORT (max 65536 bytes)
}

type FnNtQuerySystemInformation = unsafe extern "system" fn(
    SystemInformationClass: SYSTEM_INFORMATION_CLASS,
    SystemInformation: PVOID,
    SystemInformationLength: ULONG,
    ReturnLength: PULONG,
) -> NTSTATUS;
type FnNtQueryObject = unsafe extern "system" fn(
    Handle: HANDLE,
    ObjectInformationClass: OBJECT_INFORMATION_CLASS,
    ObjectInformation: PVOID,
    ObjectInformationLength: ULONG,
    ReturnLength: PULONG,
) -> NTSTATUS;

pub fn file_as_handle(f: &File) -> u64 {
    f.as_raw_handle() as u64
}

#[macro_export]
macro_rules! get_proc_address {
    ($dll_name:expr, $proc_name:expr) => {{
        let name_nul = std::ffi::CString::new($dll_name).expect("invalid DLL name");
        let h_dll = unsafe { winapi::um::libloaderapi::GetModuleHandleA(name_nul.as_ptr()) };
        assert_ne!(
            h_dll,
            core::ptr::null_mut(),
            "could not load DLL {}",
            $dll_name
        );
        let name_nul = std::ffi::CString::new($proc_name).expect("invalid DLL import name");
        let res = unsafe { winapi::um::libloaderapi::GetProcAddress(h_dll, name_nul.as_ptr()) };
        assert_ne!(
            res,
            core::ptr::null_mut(),
            "could not find {} in imported DLL {}",
            $proc_name,
            $dll_name
        );
        unsafe { std::mem::transmute(res) }
    }};
}
pub use get_proc_address;

pub fn check_worker_handles(worker: &Worker) {
    // Freeze the worker process, so that we can atomically inspect its handles
    // Do it as early as possible, so that if we panic!(), the worker dies with us
    let res = unsafe { DebugActiveProcess(worker.get_pid().try_into().unwrap()) };
    assert_ne!(
        res,
        0,
        "DebugActiveProcess({}) failed with error {}",
        worker.get_pid(),
        unsafe { GetLastError() }
    );

    let hworker = unsafe {
        OpenProcess(
            PROCESS_DUP_HANDLE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            0,
            worker.get_pid().try_into().unwrap(),
        )
    };
    assert_ne!(
        hworker,
        null_mut(),
        "OpenProcess(PROCESS_DUP_HANDLE, worker) failed with error {}",
        unsafe { GetLastError() }
    );

    // Wait for the worker to DebugBreak(), so that we know the process is fully initialized and in main()
    debug!("Waiting for child to break into debugger...");
    let mut dbg_event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
    loop {
        let res = unsafe { WaitForDebugEvent(&mut dbg_event as *mut _, INFINITE) };
        assert_ne!(res, 0, "WaitForDebugEvent() failed with error {}", unsafe {
            GetLastError()
        });
        if dbg_event.dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT {
            let expected = CString::new("Ready for inspection").unwrap().into_bytes();
            let mut bytes_read = vec![0u8; expected.len()];
            let ptr = unsafe { dbg_event.u.DebugString().lpDebugStringData };
            let res = unsafe {
                ReadProcessMemory(
                    hworker,
                    ptr as *const _,
                    bytes_read.as_mut_ptr() as *mut _,
                    expected.len(),
                    null_mut(),
                )
            };
            if res != 0 && expected == bytes_read {
                debug!("Worker signaled us it is ready, beginning inspection");
                break;
            }
        }
        // Resume the worker, otherwise it will hang at the first event (process creation) and never reach its main()
        unsafe {
            ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, DBG_CONTINUE);
        }
    }

    // Get pointers to NtQuerySystemInformation() and NtQueryObject() (undocumented, required to properly enumerate handles)
    let ntquerysysteminformation: FnNtQuerySystemInformation =
        get_proc_address!("ntdll.dll", "NtQuerySystemInformation");
    let ntqueryobject: FnNtQueryObject = get_proc_address!("ntdll.dll", "NtQueryObject");

    // Fetch object type names (undocumented, but eases debugging by printing each handle's object type instead of an integer)
    // We can't just call NtQueryObject(NULL, ObjectAllInformation, NULL, 0, &getMeTheSize)
    // because the first 4 userland bytes are directly used as the final counter by the kernel,
    // so it needs them be allocated... Plus the returned "required buffer size" is not
    // computed correctly, which often triggers 16-byte heap overflows/corruption...
    // This syscall is so broken, at this point it's safer to use a "larger than will ever be
    // necessary" hardcoded buffer size.
    let mut return_length: ULONG = 0;
    let mut object_types: Vec<String> = vec![];
    unsafe {
        let mut buffer = vec![0u8; std::mem::size_of::<OBJECT_TYPES_INFORMATION>()];
        let res = ntqueryobject(
            null_mut(),
            OBJECT_INFORMATION_CLASS::ObjectAllInformation,
            buffer.as_mut_ptr() as *mut _,
            buffer.len().try_into().unwrap(),
            &mut return_length as *mut _,
        );
        assert_eq!(
            res, STATUS_SUCCESS,
            "NtQueryObject(ObjectAllInformation) failed with status 0x{res:X}"
        );
        let buffer = buffer.as_ptr() as *const OBJECT_TYPES_INFORMATION;
        let number_of_object_types = (*buffer).NumberOfObjectTypes as usize;
        let mut ptr = &((*buffer).ObjectTypes) as *const OBJECT_TYPE_INFORMATION;
        for _ in 0..number_of_object_types {
            let slice =
                std::slice::from_raw_parts((*ptr).Name.Buffer, (*ptr).Name.Length as usize / 2);
            object_types.push(String::from_utf16_lossy(slice));
            let offset_to_next =
                ((*ptr).Name.MaximumLength as usize + std::mem::size_of::<PVOID>() - 1)
                    & !(std::mem::size_of::<PVOID>() - 1);
            ptr = ((*ptr).Name.Buffer as *const u8).add(offset_to_next)
                as *const OBJECT_TYPE_INFORMATION;
        }
    }

    let mut buffer = vec![0u8; 0x10000];
    let mut res = STATUS_INFO_LENGTH_MISMATCH;
    // The required buffer size returned by each call is obsolete as soon as it reaches us
    // (handles come and go). Grow exponentially until it fits, so that we have the guarantee
    // that the loop terminates in finite (log(N)) time
    while buffer.len() <= 1024 * 1024 * 10 {
        res = unsafe {
            ntquerysysteminformation(
                SYSTEM_INFORMATION_CLASS::SystemHandleInformation,
                buffer.as_mut_ptr() as *mut _,
                buffer.len().try_into().unwrap(),
                &mut return_length as *mut _,
            )
        };
        if res != STATUS_INFO_LENGTH_MISMATCH {
            break;
        }
        buffer.resize(buffer.len() * 2, 0);
    }
    buffer.truncate(return_length.try_into().unwrap());
    assert_eq!(res, STATUS_SUCCESS);

    let handle_info = buffer.as_ptr() as *const SYSTEM_HANDLE_INFORMATION;
    let handle_count = unsafe { (*handle_info).HandleCount } as usize;
    assert!(
        buffer.len()
            >= std::mem::size_of::<ULONG>() + handle_count * std::mem::size_of::<SYSTEM_HANDLE>()
    );
    info!(
        "Checking {} handles reported by NtQuerySystemInformation...",
        handle_count
    );

    let mut handles = vec![
        SYSTEM_HANDLE {
            ProcessId: 0,
            ObjectTypeNumber: 0,
            Flags: 0,
            Handle: 0,
            Object: null_mut(),
            GrantedAccess: 0,
        };
        handle_count
    ];
    unsafe {
        std::ptr::copy_nonoverlapping(
            &((*handle_info).Handles[0]) as *const SYSTEM_HANDLE,
            handles.as_mut_ptr(),
            handle_count,
        );
    }

    // Find the worker process kernel object address, so that we can distinguish process handles to
    // itself and to other processes
    let mut worker_process_object = None;
    for handle in &handles {
        if handle.ProcessId == std::process::id()
            && handle.Handle == (hworker as usize).try_into().unwrap()
        {
            worker_process_object = Some(handle.Object);
            break;
        }
    }
    let worker_process_object = worker_process_object
        .expect("failed to enumerate system handles: handle to worker process not found");

    // Get a copy of the worker's token, so that we can check whether it was able to open
    // each handle on its own or if there was a leak
    let himpersonationtoken = unsafe {
        let mut hworkertoken: HANDLE = null_mut();
        let res = OpenProcessToken(hworker, TOKEN_DUPLICATE, &mut hworkertoken as *mut _);
        let err = GetLastError();
        assert_ne!(res, 0, "OpenProcessToken() failed with error {err}");
        let mut himpersonationtoken: HANDLE = null_mut();
        let res = DuplicateToken(
            hworkertoken,
            SecurityImpersonation,
            &mut himpersonationtoken as *mut _,
        );
        let err = GetLastError();
        assert_ne!(res, 0, "DuplicateToken() failed with error {err}");
        CloseHandle(hworkertoken);
        himpersonationtoken
    };

    for handle in &handles {
        if u64::from(handle.ProcessId) != worker.get_pid() {
            continue;
        }
        // Get as much information as possible about that handle
        let obj_type = object_types[handle.ObjectTypeNumber as usize - 2].to_lowercase();
        let mut name: Option<String> = None;
        let mut copy: Option<HANDLE> = None;
        let mut other_holder_processes = Vec::new();
        for other_handle in &handles {
            if other_handle.Object != handle.Object || other_handle.ProcessId == handle.ProcessId {
                continue;
            }
            other_holder_processes.push(other_handle.ProcessId);
        }
        unsafe {
            let mut h_tmp: HANDLE = null_mut();
            let res = DuplicateHandle(
                hworker,
                handle.Handle as HANDLE,
                GetCurrentProcess(),
                &mut h_tmp as *mut _,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            );
            if res != 0 {
                copy = Some(h_tmp);
            }
        }
        if let Some(copy) = copy {
            // Get object names as a best effort
            let mut buf = vec![0u8; std::mem::size_of::<OBJECT_NAME_INFORMATION>()];
            let mut res_len: ULONG = 0;
            let res = unsafe {
                ntqueryobject(
                    copy,
                    OBJECT_INFORMATION_CLASS::ObjectNameInformation,
                    buf.as_mut_ptr() as *mut _,
                    buf.len().try_into().unwrap(),
                    &mut res_len as *mut _,
                )
            };
            if res == STATUS_SUCCESS && res_len > 0 {
                unsafe {
                    let name_len = (*(buf.as_ptr() as *const OBJECT_NAME_INFORMATION))
                        .Name
                        .Length;
                    let name_buf = (*(buf.as_ptr() as *const OBJECT_NAME_INFORMATION))
                        .Name
                        .Buffer;
                    if name_len > 0 {
                        name = Some(String::from_utf16_lossy(std::slice::from_raw_parts(
                            name_buf,
                            name_len as usize / 2,
                        )));
                    }
                }
            }
        }

        // Start impersonating the worker for cases where we want to reopen the object ourselves
        let res = unsafe { SetThreadToken(null_mut(), himpersonationtoken) };
        assert_ne!(res, 0, "SetThreadToken() failed with error {}", unsafe {
            GetLastError()
        });

        debug!(
            "Has handle to {} (name: {:?}) (shared with {:?})",
            obj_type, name, other_holder_processes
        );
        // Only tolerate an allow-list of types, each with type-specific conditions
        if obj_type == "event" {
            // Only tolerate anonymous events, if they are not shared with outside processes
            assert!(name.is_none(), "named event opened");
            assert_eq!(
                other_holder_processes,
                vec![],
                "anonymous event {} shared with other processes: {:?}",
                handle.Handle,
                other_holder_processes
            );
        } else if obj_type == "waitcompletionpacket" || obj_type == "iocompletion" {
            // Exposed to userland through I/O completion ports (see NtCreateIoCompletionPort() and NtOpenIoCompletionPort())
            // Tolerate them as long as they are purely internal to our process (otherwise we might fire events in another process)
            assert_eq!(
                other_holder_processes,
                vec![],
                "completion port shared with other processes: {other_holder_processes:?}"
            );
        } else if obj_type == "tpworkerfactory" {
            // We should not hold a handle to another process' thread pool, otherwise we could create arbitrary threads in it.
            // (even though documented APIs only allow creating a thread pool in the calling process, DuplicateHandle() works
            // on TpWorkerFactory handles, and NtCreateWorkerFactory() takes an abritrary process ID
            // (see https://www.microsoftpressstore.com/articles/article.aspx?p=2233328&seqNum=6)
            assert_eq!(
                other_holder_processes,
                vec![],
                "thread pool shared with other processes: {other_holder_processes:?}"
            );
        } else if obj_type == "irtimer" {
            // NtCreateIRTimer() calls are redirected in the kernel to NtCreateTimer2()
            // (see https://processhacker.sourceforge.io/doc/ntexapi_8h_source.html for an undocumented prototype)
            // Tolerate them as long as they are purely internal to our process (otherwise we might fire events in another process)
            assert_eq!(
                other_holder_processes,
                vec![],
                "irtimer shared with other processes: {other_holder_processes:?}"
            );
        } else if obj_type == "etwregistration" {
            // This object type cannot be duplicated between processes, so we cannot inspect it further.
            // Just make sure it stays this way.
            assert!(
                copy.is_some(),
                "EtwRegistration handles should not be duplicatable between processes"
            );
        } else if obj_type == "alpc port" {
            // ALPC port access usually isn't filtered, the identity of callers is checked at runtime instead
            // Check that the ALPC port can be opened with the worker's token
            warn!("/!\\ FIXME alpc");
        } else if obj_type == "directory" {
            // /!\ This is a kernel object directory, not a file directory
            // Since this is a named object (can be opened by NtOpenDirectoryObject()), just check
            // that the process token allows opening it
            warn!("/!\\ FIXME directory");
        } else if obj_type == "file" {
            // This can be a file, file directory, or named pipe
            let name = name.expect("unexpected unnamed file opened by process");
            let win32_path: Vec<u16> = format!("\\\\?\\GLOBALROOT{name}")
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let hsameobject = unsafe {
                CreateFileW(
                    win32_path.as_ptr(),
                    handle.GrantedAccess,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    null_mut(),
                    OPEN_EXISTING,
                    0,
                    null_mut(),
                )
            };
            let err = unsafe { GetLastError() };
            assert_ne!(
                hsameobject, INVALID_HANDLE_VALUE,
                "worker has handle to file {} with rights {} but could not have opened it (error {})",
                name, handle.GrantedAccess, err
            );
            unsafe {
                CloseHandle(hsameobject);
            }
        } else if obj_type == "key" {
            // A named registry key can be opened by name via NtCreateKey(), just check that the
            // process token allows opening it
            warn!("/!\\ FIXME key");
        } else if obj_type == "process" {
            // Only accept process handles to the worker process itself
            assert_eq!(
                handle.Object, worker_process_object,
                "worker should not hold a handle to another process"
            );
        } else {
            panic!(
                "unexpected object type {} (name: {}) (duplicatable: {})",
                obj_type,
                if let Some(name) = &name {
                    name
                } else {
                    "(none)"
                },
                copy.is_some()
            );
        }
        if let Some(copy) = copy {
            unsafe {
                CloseHandle(copy);
            }
        }

        // Stop impersonating
        let res = unsafe { RevertToSelf() };
        assert_ne!(res, 0, "RevertToSelf() failed with error {}", unsafe {
            GetLastError()
        });
    }

    unsafe {
        CloseHandle(hworker);
    }

    // Unfreeze the worker process before we wait() for it to exit, otherwise we will hang
    //unsafe { ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, DBG_CONTINUE); }
    let res = unsafe { DebugActiveProcessStop(worker.get_pid().try_into().unwrap()) };
    assert_ne!(
        res,
        0,
        "DebugActiveProcessStop({}) failed with error {}",
        worker.get_pid(),
        unsafe { GetLastError() }
    );
}

pub fn wait_for_worker_exit(worker: &Worker) -> Result<u64, String> {
    let pid = worker.get_pid() as u32;
    info!("Waiting for worker PID {} to exit", pid);
    let h_process = unsafe {
        let res = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, 0, pid);
        if res.is_null() {
            return Err(format!(
                "OpenProcess({}) failed with error {}",
                pid,
                GetLastError()
            ));
        }
        Handle::from_raw(res as u64).unwrap()
    };
    let mut exit_code: DWORD = STILL_ACTIVE;
    loop {
        let res = unsafe {
            GetExitCodeProcess(h_process.as_raw() as *mut c_void, &mut exit_code as *mut _)
        };
        if res == 0 {
            return Err(format!(
                "GetExitCodeProcess() failed with error {}",
                unsafe { GetLastError() }
            ));
        }
        if exit_code != STILL_ACTIVE {
            return Ok(exit_code.into());
        }
        let res = unsafe { WaitForSingleObject(h_process.as_raw() as *mut c_void, INFINITE) };
        if res != WAIT_OBJECT_0 {
            return Err(format!(
                "WaitForSingleObject() failed with error {}",
                unsafe { GetLastError() }
            ));
        }
    }
}

pub fn downcast_to_handle<T: IntoRawHandle>(resource: T) -> Handle {
    unsafe { Handle::from_raw(resource.into_raw_handle() as u64) }
        .expect("unable to downcast to handle")
}

pub fn set_unmanaged_handle_inheritable<T: AsRawHandle>(
    resource: &T,
    allow_inherit: bool,
) -> Result<(), HandleError> {
    // This block is safe because the file descriptor held by `resource` lives at least
    // for the duration of the block, and we don't take ownership of it
    unsafe {
        let mut handle = Handle::from_raw(resource.as_raw_handle() as u64)?; // returning here is safe since the handle was not created thus won't be drop()ped
        let res = handle.set_inheritable(allow_inherit);
        let _ = handle.into_raw(); // leak voluntarily
        res
    }
}
