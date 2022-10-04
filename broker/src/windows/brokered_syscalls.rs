use crate::os::get_proc_address::get_proc_address;
use core::ptr::null_mut;
use iris_ipc::{IPCRequest, IPCResponse};
use iris_policy::{CrossPlatformHandle, Handle, Policy};
use log::{error, warn};
use winapi::shared::basetsd::ULONG_PTR;
use winapi::shared::ntdef::{
    InitializeObjectAttributes, NTSTATUS, NT_SUCCESS, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE,
    PVOID, ULONG, UNICODE_STRING,
};
use winapi::shared::ntstatus::{
    STATUS_ACCESS_DENIED, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED,
};
use winapi::um::winnt::{
    SecurityIdentification, ACCESS_MASK, DELETE, FILE_APPEND_DATA, FILE_READ_ATTRIBUTES,
    FILE_READ_DATA, FILE_READ_EA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, HANDLE, KEY_CREATE_SUB_KEY,
    KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_32KEY,
    KEY_WOW64_64KEY, LARGE_INTEGER, LONGLONG, READ_CONTROL, REG_OPENED_EXISTING_KEY,
    REG_OPTION_NON_VOLATILE, REG_OPTION_VOLATILE, SECURITY_DYNAMIC_TRACKING,
    SECURITY_QUALITY_OF_SERVICE, SYNCHRONIZE, WCHAR, WRITE_DAC, WRITE_OWNER,
};

// Constants from winternl.h not yet exported by winapi
const FILE_SUPERSEDE: u32 = 0x00000000;
const FILE_OPEN: u32 = 0x00000001;
const FILE_CREATE: u32 = 0x00000002;
const FILE_OPEN_IF: u32 = 0x00000003;
const FILE_OVERWRITE: u32 = 0x00000004;
const FILE_OVERWRITE_IF: u32 = 0x00000005;

// From WDK headers
#[allow(non_snake_case)]
#[repr(C)]
pub(crate) struct IO_STATUS_BLOCK {
    Status: NTSTATUS,
    Information: ULONG_PTR,
}

// Mapping from policy-allowed rights to Windows access bits
const FILE_ALWAYS_GRANTED_RIGHTS: u32 = READ_CONTROL | SYNCHRONIZE;
const FILE_READ_RIGHTS: u32 = FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA;
const FILE_WRITE_ANYWHERE_RIGHTS: u32 =
    FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER;
const FILE_WRITE_APPEND_ONLY_RIGHTS: u32 = FILE_APPEND_DATA;
const KEY_ALWAYS_GRANTED_RIGHTS: u32 =
    READ_CONTROL | SYNCHRONIZE | KEY_NOTIFY | KEY_WOW64_32KEY | KEY_WOW64_64KEY;
const KEY_READ_RIGHTS: u32 = KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE;
const KEY_WRITE_RIGHTS: u32 = KEY_CREATE_SUB_KEY | KEY_SET_VALUE | DELETE | WRITE_DAC | WRITE_OWNER;

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

pub(crate) fn handle_os_specific_request(
    request: IPCRequest,
    policy: &Policy,
) -> (IPCResponse, Option<Handle>) {
    match request {
        IPCRequest::NtCreateFile {
            desired_access,
            path,
            allocation_size,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            ea,
        } => handle_ntcreatefile(
            policy,
            desired_access,
            &path,
            allocation_size,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            &ea,
        ),
        IPCRequest::NtCreateKey {
            desired_access,
            path,
            title_index,
            class,
            create_options,
            do_create,
        } => handle_ntcreatekey(
            policy,
            desired_access,
            path,
            title_index,
            class,
            create_options,
            do_create,
        ),
        unknown => {
            error!("Unexpected request from worker: {:?}", unknown);
            (IPCResponse::GenericError(STATUS_NOT_SUPPORTED), None)
        }
    }
}

fn handle_ntcreatefile(
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
    if path.is_empty() {
        return (IPCResponse::GenericError(STATUS_INVALID_PARAMETER), None);
    }
    // Validate desired_access
    let never_granted = desired_access
        & !(FILE_READ_RIGHTS
            | FILE_WRITE_ANYWHERE_RIGHTS
            | FILE_WRITE_APPEND_ONLY_RIGHTS
            | FILE_ALWAYS_GRANTED_RIGHTS);
    if never_granted != 0 {
        warn!(
            "Worker requested access rights 0x{:X} to {} but such access cannot be delegated",
            never_granted, path
        );
        return (IPCResponse::GenericError(STATUS_ACCESS_DENIED), None);
    }
    // TODO: validate all bit flags to only let through those we know are safe for a sandboxed process
    // TODO: DELETE_ON_CLOSE => write access required ?
    let requests_read = (desired_access & FILE_READ_RIGHTS) != 0
        && !(create_disposition == FILE_SUPERSEDE
            || create_disposition == FILE_CREATE
            || create_disposition == FILE_OVERWRITE
            || create_disposition == FILE_OVERWRITE_IF);
    let requests_write_anywhere = (desired_access & FILE_WRITE_ANYWHERE_RIGHTS) != 0
        || ea.len() > 0
        || create_disposition == FILE_SUPERSEDE
        || create_disposition == FILE_OVERWRITE
        || create_disposition == FILE_OVERWRITE_IF;
    let requests_write_append_only = (desired_access & FILE_WRITE_APPEND_ONLY_RIGHTS) != 0
        && (create_disposition == FILE_CREATE
            || create_disposition == FILE_OPEN
            || create_disposition == FILE_OPEN_IF);
    let (can_read, can_write, can_only_append) = policy.get_file_allowed_access(path);
    if !(requests_read || requests_write_anywhere || requests_write_append_only)
        || (requests_read && !can_read)
        || (requests_write_anywhere && (!can_write || can_only_append))
        || (requests_write_append_only && !can_write)
    {
        warn!(
            "Worker denied{}{}{} access to {} ({})",
            if requests_read && !can_read {
                " read"
            } else {
                ""
            },
            if requests_write_anywhere && (!can_write || can_only_append) {
                " write"
            } else {
                ""
            },
            if requests_write_append_only && !can_write {
                " append"
            } else {
                ""
            },
            path,
            if can_read || can_write {
                format!(
                    "can only{}{}{}",
                    if can_read { " read" } else { "" },
                    if can_write { " write" } else { "" },
                    if can_only_append {
                        " (append only)"
                    } else {
                        ""
                    }
                )
            } else {
                "has no access to that path".to_owned()
            }
        );
        return (IPCResponse::GenericError(STATUS_ACCESS_DENIED), None);
    }
    // Validate share_access
    if share_access != (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) {
        let (can_lock_readers, can_lock_writers, can_lock_deleters) =
            policy.get_file_allowed_lock(path);
        if ((share_access & FILE_SHARE_READ) == 0 && !can_lock_readers)
            || ((share_access & FILE_SHARE_WRITE) == 0 && !can_lock_writers)
            || ((share_access & FILE_SHARE_DELETE) == 0 && !can_lock_deleters)
        {
            warn!(
                "Worker denied from locking other processes from{}{}{} {} ({})",
                if (share_access & FILE_SHARE_READ) == 0 {
                    " reading"
                } else {
                    ""
                },
                if (share_access & FILE_SHARE_WRITE) == 0 {
                    " writing"
                } else {
                    ""
                },
                if (share_access & FILE_SHARE_DELETE) == 0 {
                    " deleting"
                } else {
                    ""
                },
                path,
                if can_lock_readers || can_lock_writers || can_lock_deleters {
                    format!(
                        "can only lock from{}{}{}",
                        if can_lock_readers { " reading" } else { "" },
                        if can_lock_writers { " writing" } else { "" },
                        if can_lock_deleters { " deleting" } else { "" }
                    )
                } else {
                    "cannot lock that path".to_owned()
                }
            );
            return (IPCResponse::GenericError(STATUS_ACCESS_DENIED), None);
        }
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
        Length: std::mem::size_of::<SECURITY_QUALITY_OF_SERVICE> as u32,
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
            file_attributes,
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
                Some(Handle::new(handle as u64).unwrap()),
            )
        } else {
            (status, io_status.Information, None)
        }
    };
    return (IPCResponse::NtCreateFile { io_status, code }, handle);
}

fn handle_ntcreatekey(
    policy: &Policy,
    desired_access: ACCESS_MASK,
    path: String,
    title_index: ULONG,
    class: Option<String>,
    create_options: ULONG,
    do_create: bool,
) -> (IPCResponse, Option<Handle>) {
    if path.is_empty() {
        return (IPCResponse::GenericError(STATUS_INVALID_PARAMETER), None);
    }
    let never_granted =
        desired_access & !(KEY_READ_RIGHTS | KEY_WRITE_RIGHTS | KEY_ALWAYS_GRANTED_RIGHTS);
    if never_granted != 0 {
        warn!(
            "Worker requested access rights 0x{:X} to {} but such access cannot be delegated",
            never_granted, path
        );
        return (IPCResponse::GenericError(STATUS_ACCESS_DENIED), None);
    }
    if create_options & !(REG_OPTION_VOLATILE | REG_OPTION_NON_VOLATILE) != 0 {
        warn!(
            "Worker requested unsupported registry key options 0x{:X} on {}",
            create_options & !(REG_OPTION_VOLATILE | REG_OPTION_NON_VOLATILE),
            path
        );
        return (IPCResponse::GenericError(STATUS_NOT_SUPPORTED), None);
    }
    let (can_read, can_write) = policy.get_regkey_allowed_access(&path);
    let (wants_read, wants_write) = (
        (desired_access & KEY_READ_RIGHTS) != 0,
        (desired_access & KEY_WRITE_RIGHTS) != 0,
    );
    if (wants_read && !can_read)
        || (wants_write && !can_write)
        || (!wants_read && !wants_write && !can_read && !can_write)
    {
        warn!(
            "Worker denied {}{} access (0x{:X}) to registry key {}",
            if wants_read { "read" } else { "" },
            if wants_write { "write" } else { "" },
            desired_access,
            &path
        );
        return (IPCResponse::GenericError(STATUS_ACCESS_DENIED), None);
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
        if !do_create || !can_write {
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
                    Some(Handle::new(handle as u64).unwrap()),
                )
            } else {
                (0, status, None)
            }
        } else {
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
                    Some(Handle::new(handle as u64).unwrap()),
                )
            } else {
                (0, status, None)
            }
        }
    };
    return (IPCResponse::NtCreateKey { disposition, code }, handle);
}
