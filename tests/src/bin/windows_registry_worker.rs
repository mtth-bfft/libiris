#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use log::info;

#[cfg(unix)]
fn main() {
    info!("There's no registry on Unix");
}

#[cfg(windows)]
fn main() {
    use common::common_test_setup;
    use core::ptr::null_mut;
    use iris_worker::lower_final_sandbox_privileges_asap;
    use std::ffi::CString;
    use winapi::shared::minwindef::FARPROC;
    use winapi::shared::ntdef::{
        InitializeObjectAttributes, HANDLE, NTSTATUS, NT_SUCCESS, OBJECT_ATTRIBUTES, ULONG,
        UNICODE_STRING, WCHAR,
    };
    use winapi::shared::ntstatus::STATUS_ACCESS_DENIED;
    use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
    use winapi::um::winnt::{
        ACCESS_MASK, DELETE, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY,
        KEY_QUERY_VALUE, KEY_SET_VALUE, READ_CONTROL, REG_OPTION_NON_VOLATILE, WRITE_DAC,
        WRITE_OWNER,
    };

    #[allow(non_camel_case_types)]
    type pntcreatekey = unsafe extern "system" fn(
        key_handle: *mut HANDLE,
        desired_access: ACCESS_MASK,
        object_attributes: *mut OBJECT_ATTRIBUTES,
        title_index: ULONG,
        class: *mut UNICODE_STRING,
        create_options: ULONG,
        out_disposition: *mut ULONG,
    ) -> NTSTATUS;

    lower_final_sandbox_privileges_asap();
    common_test_setup();

    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 7);
    let test_function = args[1].parse::<u8>().unwrap();
    let path = CString::new(args[2].as_str()).unwrap();
    let readable = args[3] == "1";
    let writable = args[4] == "1";
    let request_read = args[5] == "1";
    let request_write = args[6] == "1";
    info!(
        "{} should be {}readable {}writable",
        args[2],
        if readable { "" } else { "non-" },
        if writable { "" } else { "non-" },
    );
    info!(
        "Checking if it is{}{}",
        if request_read { " readable" } else { "" },
        if request_write { " writable" } else { "" },
    );

    let dllname = CString::new("ntdll.dll").unwrap();
    let hntdll = unsafe { LoadLibraryA(dllname.as_ptr()) };
    assert_ne!(hntdll, null_mut());
    let funcname = CString::new("NtCreateKey").unwrap();
    let ntcreatekey = unsafe { GetProcAddress(hntdll, funcname.as_ptr()) };
    assert_ne!(ntcreatekey, null_mut());
    let ntcreatekey = unsafe { std::mem::transmute::<FARPROC, pntcreatekey>(ntcreatekey) };

    let requested_rights = if request_read {
        KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | KEY_QUERY_VALUE
    } else {
        0
    } | if request_write {
        KEY_CREATE_SUB_KEY | KEY_SET_VALUE | DELETE | WRITE_DAC | WRITE_OWNER
    } else {
        0
    } | READ_CONTROL;

    let path = path.to_string_lossy();
    let mut obj_attr: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
    let mut us_obj_name: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let buffer_len: u16 = ((us_obj_name.len() - 1) * std::mem::size_of::<WCHAR>())
        .try_into()
        .unwrap();
    let mut us_obj_name = UNICODE_STRING {
        Buffer: us_obj_name.as_mut_ptr(),
        Length: buffer_len,
        MaximumLength: buffer_len,
    };
    let h_directory: HANDLE = null_mut();
    unsafe {
        InitializeObjectAttributes(
            &mut obj_attr as *mut _,
            &mut us_obj_name as *mut _,
            0,
            h_directory,
            null_mut(),
        )
    };
    let should_work =
        (!request_read || readable) && (!request_write || writable) && (readable || writable);

    let mut hkey: HANDLE = null_mut();
    if test_function == 1 {
        let mut disposition = 0;
        let res = unsafe {
            ntcreatekey(
                &mut hkey as *mut _,
                requested_rights,
                &mut obj_attr as *mut _,
                0,
                null_mut(),
                REG_OPTION_NON_VOLATILE,
                &mut disposition,
            )
        };
        assert!(
            (should_work && NT_SUCCESS(res) && !hkey.is_null() && disposition != 0)
                || (!should_work && res == STATUS_ACCESS_DENIED && hkey.is_null()),
            "NtCreateKey({}, 0x{:X}) = 0x{:X}",
            path,
            requested_rights,
            res
        );
    } else {
        panic!("Invalid test function number");
    }
}
