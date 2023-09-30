use common::os::wait_for_worker_exit;
use common::{
    cleanup_tmp_file, common_test_setup, get_worker_abs_path, open_tmp_file, read_tmp_file,
};
use iris_broker::{ProcessConfig, Worker};
use iris_ipc::downcast_to_handle;
use iris_policy::Policy;
use log::info;
use std::ffi::CString;
use std::io::Write;

#[cfg(target_family = "unix")]
fn transform_path(path: &str) -> String {
    path.to_owned()
}

#[cfg(windows)]
fn transform_path(path: &str) -> String {
    use common::os::get_proc_address;
    use core::ptr::null_mut;
    use winapi::shared::ntdef::{NTSTATUS, NT_SUCCESS, UNICODE_STRING};
    use winapi::um::winnt::{PCWSTR, PVOID, WCHAR};

    #[allow(non_camel_case_types)]
    type PRtlDosPathNameToRelativeNtPathName_U_WithStatus = unsafe extern "system" fn(
        DosName: PCWSTR,
        NtName: *mut UNICODE_STRING,
        PartName: PCWSTR,
        RelativeName: PVOID,
    )
        -> NTSTATUS;

    #[allow(non_snake_case)]
    let RtlDosPathNameToRelativeNtPathName_U_WithStatus: PRtlDosPathNameToRelativeNtPathName_U_WithStatus = get_proc_address!("ntdll.dll", "RtlDosPathNameToRelativeNtPathName_U_WithStatus");
    let dos_path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut us_nt_path = UNICODE_STRING {
        Buffer: null_mut(),
        Length: 0,
        MaximumLength: 0,
    };
    let status = unsafe {
        RtlDosPathNameToRelativeNtPathName_U_WithStatus(
            dos_path.as_ptr(),
            &mut us_nt_path as *mut _,
            null_mut(),
            null_mut(),
        )
    };
    assert!(
        NT_SUCCESS(status),
        "RtlDosPathNameToRelativeNtPathName_U_WithStatus() failed with status 0x{status:08X}"
    );

    let str_len = us_nt_path.Length as usize / std::mem::size_of::<WCHAR>();
    let resolved = unsafe { std::slice::from_raw_parts(us_nt_path.Buffer, str_len) };
    String::from_utf16(resolved).expect("non-unicode resolved NT path")
}

#[test]
fn file_path_open() {
    common_test_setup();
    let worker_binary = get_worker_abs_path("file_path_open_worker");
    for readable in [true, false] {
        for writable in [true, false] {
            let (tmpout, tmpoutpath) = open_tmp_file();
            let tmpout = downcast_to_handle(tmpout);
            let (mut tmpok, tmpokpath) = open_tmp_file();
            tmpok.write_all(b"OK").unwrap();
            drop(tmpok);
            info!(
                "Testing access to {} with policy {}readable {}writable",
                tmpokpath.to_string_lossy(),
                if readable { "" } else { "non-" },
                if writable { "" } else { "non-" }
            );
            let mut policy = Policy::nothing_allowed();
            if readable {
                policy
                    .allow_file_read(&tmpokpath.to_string_lossy())
                    .unwrap();
            }
            if writable {
                policy
                    .allow_file_write(&tmpokpath.to_string_lossy())
                    .unwrap();
            }
            let mut proc_config = ProcessConfig::new(
                worker_binary.clone(),
                &[
                    worker_binary.clone(),
                    CString::new(transform_path(
                        tmpokpath.to_str().expect("invalid tmp path"),
                    ))
                    .unwrap(),
                    CString::new(if readable { "1" } else { "0" }).unwrap(),
                    CString::new(if writable { "1" } else { "0" }).unwrap(),
                ],
            );
            proc_config
                .redirect_stdout(Some(&tmpout))
                .unwrap()
                .redirect_stderr(Some(&tmpout))
                .unwrap();
            let worker = Worker::new(&proc_config, &policy).expect("worker creation failed");
            assert_eq!(
                wait_for_worker_exit(&worker),
                Ok(0),
                "worker reported an error, see its output log:\n{}",
                read_tmp_file(&tmpoutpath)
            );
            cleanup_tmp_file(&tmpoutpath);
            cleanup_tmp_file(&tmpokpath);
        }
    }
}
