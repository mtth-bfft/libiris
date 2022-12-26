#![cfg(windows)]
use common::{cleanup_tmp_file, common_test_setup, get_worker_abs_path, open_tmp_file};
use core::ptr::null_mut;
use iris_broker::{downcast_to_handle, Policy, ProcessConfig, Worker};
use iris_policy::derive_all_reg_key_paths_from_path;
use std::ffi::CString;
use winapi::shared::winerror::ERROR_SUCCESS;
use winapi::um::winreg::{RegCloseKey, RegCreateKeyA, RegDeleteTreeA, HKEY_CURRENT_USER};

fn setup_tmp_reg_key() {
    let path = CString::new("test1").unwrap();
    let mut hkey = null_mut();
    let res = unsafe { RegCreateKeyA(HKEY_CURRENT_USER, path.as_ptr(), &mut hkey) };
    assert_eq!(
        res, ERROR_SUCCESS as i32,
        "RegCreateKeyA(HKCU\\test1) failed with code {}",
        res
    );
    unsafe {
        RegCloseKey(hkey);
    }
}

fn teardown_tmp_reg_key() {
    let path = CString::new("test1").unwrap();
    let res = unsafe { RegDeleteTreeA(HKEY_CURRENT_USER, path.as_ptr()) };
    assert_eq!(
        res, ERROR_SUCCESS as i32,
        "RegDeleteTree(HKCU\\test1) failed with code {}",
        res
    );
}

#[test]
fn reg_read_write_works() {
    common_test_setup();
    let worker_binary = get_worker_abs_path("windows_registry_worker");
    let nt_key_path = derive_all_reg_key_paths_from_path("HKEY_CURRENT_USER\\test1")
        .unwrap()
        .pop()
        .unwrap();
    let test_function = 1;
    for readable in vec![true, false] {
        for writable in vec![true, false] {
            for request_read in vec![true, false] {
                for request_write in vec![true, false] {
                    setup_tmp_reg_key();
                    let (tmpout, tmpoutpath) = open_tmp_file();
                    let tmpout = downcast_to_handle(tmpout);
                    let mut policy = Policy::nothing_allowed();
                    if readable || writable {
                        policy
                            .allow_regkey_access("HKEY_CURRENT_USER\\test1", readable, writable)
                            .unwrap();
                    }
                    let proc_conf = ProcessConfig::new(
                        worker_binary.clone(),
                        &[
                            worker_binary.clone(),
                            CString::new(format!("{}", test_function)).unwrap(),
                            CString::new(nt_key_path.clone()).unwrap(),
                            CString::new(if readable { "1" } else { "0" }).unwrap(),
                            CString::new(if writable { "1" } else { "0" }).unwrap(),
                            CString::new(if request_read { "1" } else { "0" }).unwrap(),
                            CString::new(if request_write { "1" } else { "0" }).unwrap(),
                        ],
                    )
                    .with_stdout_redirected(&tmpout)
                    .unwrap();
                    let mut worker =
                        Worker::new(&proc_conf, &policy).expect("worker creation failed");
                    assert_eq!(
                        worker.wait_for_exit(),
                        Ok(0),
                        "worker reported an error, see its output log:\n{}",
                        std::fs::read_to_string(tmpoutpath)
                            .unwrap_or("<unable to read log>".to_owned())
                    );
                    teardown_tmp_reg_key();
                    cleanup_tmp_file(&tmpoutpath);
                }
            }
        }
    }
}
