use crate::os::get_proc_address::get_proc_address;
use core::ptr::null_mut;
use iris_policy::{Policy, PolicyVerdict, os::PolicyRequest};
use iris_ipc::CrossPlatformHandle;
use iris_ipc::os::Handle;
use iris_ipc_messages::os::IPCResponse;
use winapi::shared::basetsd::ULONG_PTR;
use winapi::shared::ntdef::{
    InitializeObjectAttributes, NTSTATUS, NT_SUCCESS, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE,
    PVOID, ULONG, UNICODE_STRING,
};
use winapi::shared::ntstatus::STATUS_ACCESS_DENIED;
use winapi::um::winbase::FILE_FLAG_OPEN_REPARSE_POINT;
use winapi::um::winnt::{
    SecurityIdentification, ACCESS_MASK, HANDLE, LARGE_INTEGER, LONGLONG, REG_OPENED_EXISTING_KEY,
    SECURITY_DYNAMIC_TRACKING, SECURITY_QUALITY_OF_SERVICE, WCHAR,
};

// From WDK headers
#[allow(non_snake_case)]
#[repr(C)]
pub(crate) struct IO_STATUS_BLOCK {
    Status: NTSTATUS,
    Information: ULONG_PTR,
}

pub(crate) type PNtCreateFile = unsafe extern "system" fn(
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
) -> NTSTATUS;

type PNtCreateKey = unsafe extern "system" fn(
    key_handle: *mut HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    title_index: ULONG,
    class: *mut UNICODE_STRING,
    create_options: ULONG,
    out_disposition: *mut ULONG,
) -> NTSTATUS;

type PNtOpenKey = unsafe extern "system" fn(
    key_handle: *mut HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: *mut OBJECT_ATTRIBUTES,
) -> NTSTATUS;

pub(crate) fn proxied_ntcreatefile(
    policy: &Policy,
    desired_access: ACCESS_MASK,
    path: &str,
    allocation_size: LONGLONG,
    file_attributes: ULONG,
    share_access: ULONG,
    create_disposition: ULONG,
    create_options: ULONG,
    ea: &[u8],
) -> (IPCResponse, Option<Handle>) {
    let create_options = create_options | FILE_FLAG_OPEN_REPARSE_POINT; // never follow reparse points
    let req = PolicyRequest::FileOpen {
        path,
        desired_access,
        file_attributes,
        share_access,
        create_disposition,
        create_options,
        ea,
    };
    if policy.evaluate_request(&req) != PolicyVerdict::Granted {
        return (IPCResponse::SyscallResult(STATUS_ACCESS_DENIED), None);
    }
    let p_ntcreatefile = match get_proc_address("ntdll.dll", "NtCreateFile") {
        ptr if ptr.is_null() => panic!("Could not locate NtCreateFile in ntdll"),
        ptr => unsafe { std::mem::transmute::<PVOID, PNtCreateFile>(ptr) },
    };
    let mut unicode_name: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let unicode_bytes = (unicode_name.len() - 1) * std::mem::size_of::<WCHAR>();
    let mut unicode_name = UNICODE_STRING {
        Length: unicode_bytes as u16,
        MaximumLength: unicode_bytes as u16,
        Buffer: unicode_name.as_mut_ptr(),
    };
    let mut sec_qos = SECURITY_QUALITY_OF_SERVICE {
        Length: std::mem::size_of::<SECURITY_QUALITY_OF_SERVICE>() as u32,
        ImpersonationLevel: SecurityIdentification,
        ContextTrackingMode: SECURITY_DYNAMIC_TRACKING,
        EffectiveOnly: 1,
    };
    let mut obj_attr = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: null_mut(),
        ObjectName: &mut unicode_name as *mut UNICODE_STRING,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: null_mut(),
        SecurityQualityOfService: &mut sec_qos as *mut SECURITY_QUALITY_OF_SERVICE as *mut _,
    };
    let (code, io_status, handle) = unsafe {
        let mut handle = null_mut();
        let mut io_status: IO_STATUS_BLOCK = std::mem::zeroed();
        let mut alloc_size: LARGE_INTEGER = std::mem::zeroed();
        *(alloc_size.QuadPart_mut()) = allocation_size;
        let status = p_ntcreatefile(
            &mut handle as *mut _,
            desired_access,
            &mut obj_attr as *mut _,
            &mut io_status as *mut _,
            &mut alloc_size as *mut _,
            winapi::um::winnt::FILE_ATTRIBUTE_NORMAL, //file_attributes,
            share_access,
            create_disposition,
            create_options,
            ea.as_ptr() as *mut _,
            ea.len() as u32,
        );
        if NT_SUCCESS(status) {
            (
                status,
                io_status.Information,
                Some(Handle::from_raw(handle as u64).unwrap()),
            )
        } else {
            (status, io_status.Information, None)
        }
    };
    (IPCResponse::NtCreateFile { io_status, code }, handle)
}

pub(crate) fn proxied_ntcreatekey(
    policy: &Policy,
    desired_access: ACCESS_MASK,
    path: &str,
    title_index: ULONG,
    class: Option<&str>,
    create_options: ULONG,
    do_create: bool,
) -> (IPCResponse, Option<Handle>) {
    let req = PolicyRequest::RegKeyOpen {
        path: &path,
        desired_access,
        create_options,
        do_create,
    };
    if policy.evaluate_request(&req) != PolicyVerdict::Granted {
        return (IPCResponse::SyscallResult(STATUS_ACCESS_DENIED), None);
    }
    let mut unicode_name: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let unicode_bytes = (unicode_name.len() - 1) * std::mem::size_of::<WCHAR>();
    let mut unicode_name = UNICODE_STRING {
        Length: unicode_bytes as u16,
        MaximumLength: unicode_bytes as u16,
        Buffer: unicode_name.as_mut_ptr(),
    };
    let mut class_unicode = if let Some(ref s) = class {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    } else {
        vec![0]
    };
    let mut class_unicode = UNICODE_STRING {
        Length: ((class_unicode.len() - 1) * std::mem::size_of::<WCHAR>()) as u16,
        MaximumLength: ((class_unicode.len() - 1) * std::mem::size_of::<WCHAR>()) as u16,
        Buffer: class_unicode.as_mut_ptr(),
    };
    let ntopenkey = match get_proc_address("ntdll.dll", "NtOpenKey") {
        ptr if ptr.is_null() => panic!("Could not locate NtOpenKey in ntdll"),
        ptr => unsafe { std::mem::transmute::<PVOID, PNtOpenKey>(ptr) },
    };
    let ntcreatekey = match get_proc_address("ntdll.dll", "NtCreateKey") {
        ptr if ptr.is_null() => panic!("Could not locate NtCreateKey in ntdll"),
        ptr => unsafe { std::mem::transmute::<PVOID, PNtCreateKey>(ptr) },
    };
    let (disposition, code, handle) = unsafe {
        if do_create {
            let mut handle = null_mut();
            let mut disposition: ULONG = 0;
            let mut obj_attr: OBJECT_ATTRIBUTES = std::mem::zeroed();
            InitializeObjectAttributes(
                &mut obj_attr as *mut _,
                &mut unicode_name as *mut _,
                OBJ_CASE_INSENSITIVE,
                null_mut(),
                null_mut(),
            );
            let status = ntcreatekey(
                &mut handle,
                desired_access,
                &mut obj_attr as *mut _,
                title_index,
                if class.is_some() {
                    &mut class_unicode as *mut _
                } else {
                    null_mut()
                },
                create_options,
                &mut disposition,
            );
            if NT_SUCCESS(status) {
                (
                    disposition,
                    status,
                    Some(Handle::from_raw(handle as u64).unwrap()),
                )
            } else {
                (0, status, None)
            }
        } else {
            let mut handle = null_mut();
            let mut obj_attr: OBJECT_ATTRIBUTES = std::mem::zeroed();
            InitializeObjectAttributes(
                &mut obj_attr as *mut _,
                &mut unicode_name as *mut _,
                OBJ_CASE_INSENSITIVE,
                null_mut(),
                null_mut(),
            );
            let status = ntopenkey(&mut handle, desired_access, &mut obj_attr as *mut _);
            if NT_SUCCESS(status) {
                (
                    REG_OPENED_EXISTING_KEY,
                    status,
                    Some(Handle::from_raw(handle as u64).unwrap()),
                )
            } else {
                (0, status, None)
            }
        }
    };
    (IPCResponse::NtCreateKey { disposition, code }, handle)
}
