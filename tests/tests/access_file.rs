use common::{cleanup_tmp_file, get_worker_bin_path, open_tmp_file};
use iris_broker::{downcast_to_handle, Policy, Worker};
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
        "RtlDosPathNameToRelativeNtPathName_U_WithStatus() failed with status 0x{:08X}",
        status
    );

    let str_len = us_nt_path.Length as usize / std::mem::size_of::<WCHAR>();
    let resolved = unsafe { std::slice::from_raw_parts(us_nt_path.Buffer, str_len) };
    let resolved = String::from_utf16(&resolved).expect("non-unicode resolved NT path");

    resolved
}

#[test]
fn access_file() {
    let worker_binary = get_worker_bin_path();
    for test_function in 1..=2 {
        for readable in vec![true, false] {
            for writable in vec![true, false] {
                for restrict_to_append_only in vec![true, false] {
                    if !writable && restrict_to_append_only {
                        continue; // nonsensical case
                    }
                    for request_read in vec![true, false] {
                        for request_write in vec![true, false] {
                            for request_only_append in vec![true, false] {
                                if !request_write && request_only_append {
                                    continue; // nonsensical case
                                }
                                let (tmpout, tmpoutpath) = open_tmp_file();
                                let tmpout = downcast_to_handle(tmpout);
                                let (mut tmpok, tmpokpath) = open_tmp_file();
                                tmpok.write_all(b"OK").unwrap();
                                let mut policy = Policy::new();
                                policy
                                    .allow_file_access(
                                        &tmpokpath.to_string_lossy(),
                                        readable,
                                        writable,
                                        restrict_to_append_only,
                                    )
                                    .unwrap();
                                let mut worker = Worker::new(
                                    &policy,
                                    &worker_binary,
                                    &[
                                        &worker_binary,
                                        &CString::new(format!("{}", test_function)).unwrap(),
                                        &CString::new(transform_path(
                                            tmpokpath.to_str().expect("invalid tmp path"),
                                        ))
                                        .unwrap(),
                                        &CString::new(if readable { "1" } else { "0" }).unwrap(),
                                        &CString::new(if writable { "1" } else { "0" }).unwrap(),
                                        &CString::new(if restrict_to_append_only {
                                            "1"
                                        } else {
                                            "0"
                                        })
                                        .unwrap(),
                                        &CString::new(if request_read { "1" } else { "0" })
                                            .unwrap(),
                                        &CString::new(if request_write { "1" } else { "0" })
                                            .unwrap(),
                                        &CString::new(if request_only_append { "1" } else { "0" })
                                            .unwrap(),
                                    ],
                                    &[],
                                    None,
                                    Some(&tmpout),
                                    Some(&tmpout),
                                )
                                .expect("worker creation failed");
                                assert_eq!(
                                    worker.wait_for_exit(),
                                    Ok(0),
                                    "worker reported an error, see its output log:\n{}",
                                    std::fs::read_to_string(tmpoutpath)
                                        .unwrap_or("<unable to read log>".to_owned())
                                );
                                cleanup_tmp_file(&tmpoutpath);
                                cleanup_tmp_file(&tmpokpath);
                            }
                        }
                    }
                }
            }
        }
    }
}
