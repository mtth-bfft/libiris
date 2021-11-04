use common::{check_worker_handles, cleanup_tmp_file, get_worker_bin_path, open_tmp_file};
use iris_broker::{Policy, Worker};
use iris_policy::{downcast_to_handle, CrossPlatformHandle};
use std::path::PathBuf;
use std::sync::Arc;

// Voluntarily set up resources (opened handles and file descriptors)
// ready to be leaked into our children. This could be the result of
// e.g. a poorly written parent program, or a poorly written plugin/AV
// injected into the worker or its parents.

fn common_setup() -> (Worker, PathBuf) {
    let (tmpleak, tmpleakpath) = open_tmp_file();
    let mut tmpleak = downcast_to_handle(tmpleak);
    tmpleak
        .set_inheritable(true)
        .expect("unable to set handle as inheritable");

    let worker_binary = get_worker_bin_path();
    let mut policy = Policy::new();
    policy
        .allow_inherit_handle(Arc::new(tmpleak))
        .expect("unable to allow handle inheritance");
    let worker = Worker::new(
        &policy,
        &worker_binary,
        &[&worker_binary],
        &[],
        None,
        None,
        None,
    )
    .expect("worker creation failed");

    (worker, tmpleakpath)
}

fn common_teardown(worker: Worker, tmpleakpath: PathBuf) {
    check_worker_handles(&worker);
    cleanup_tmp_file(&tmpleakpath);
}

#[test]
#[cfg(unix)]
#[should_panic(expected = "File descriptor leaked")]
fn inherited_resources_detects_leak_file() {
    let (worker, tmpleakpath) = common_setup();
    common_teardown(worker, tmpleakpath);
}

#[test]
#[cfg(windows)]
#[should_panic(expected = "handle to file")]
fn inherited_resources_detects_leak_file() {
    use core::ptr::null_mut;
    use iris_policy::Handle;
    use std::convert::TryInto;
    use std::ffi::CString;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
    use winapi::um::handleapi::{DuplicateHandle, INVALID_HANDLE_VALUE};
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess};
    use winapi::um::winnt::{
        FILE_ALL_ACCESS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, HANDLE,
        PROCESS_DUP_HANDLE,
    };

    let (worker, tmpleakpath) = common_setup();

    let h_worker = unsafe {
        let res = OpenProcess(PROCESS_DUP_HANDLE, 0, worker.get_pid().try_into().unwrap());
        assert_ne!(
            res,
            null_mut(),
            "OpenProcess(worker) failed with error {}",
            GetLastError()
        );
        Handle::new(res as u64).unwrap()
    };

    let tmpleakpath_nul = CString::new(tmpleakpath.to_str().unwrap()).unwrap();
    let h_file = unsafe {
        let res = CreateFileA(
            tmpleakpath_nul.as_ptr(),
            FILE_ALL_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null_mut(),
            OPEN_EXISTING,
            0,
            null_mut(),
        );
        assert_ne!(
            res,
            INVALID_HANDLE_VALUE,
            "CreateFile() failed with error {}",
            GetLastError()
        );
        Handle::new(res as u64).unwrap()
    };
    // Voluntarily inject a full-privilege handle on a file into the worker
    // /!\ NEVER DO THIS, THIS COMPLETELY BREAKS SANDBOXING BOUNDARIES
    let res = unsafe {
        let mut _voluntarily_leaked: HANDLE = null_mut();
        DuplicateHandle(
            GetCurrentProcess(),
            h_file.as_raw() as HANDLE,
            h_worker.as_raw() as HANDLE,
            &mut _voluntarily_leaked as *mut _,
            FILE_ALL_ACCESS,
            0,
            0,
        )
    };
    assert_ne!(res, 0, "DuplicateHandle() failed with error {}", unsafe {
        GetLastError()
    });

    common_teardown(worker, tmpleakpath);
}

#[test]
#[cfg(windows)]
#[should_panic(expected = "handle to another process")]
fn inherited_resources_detects_leak_process() {
    use core::ptr::null_mut;
    use iris_policy::Handle;
    use std::convert::TryInto;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::handleapi::DuplicateHandle;
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess};
    use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS, PROCESS_DUP_HANDLE};

    let (worker, tmpleakpath) = common_setup();

    let h_worker = unsafe {
        let res = OpenProcess(PROCESS_DUP_HANDLE, 0, worker.get_pid().try_into().unwrap());
        assert_ne!(
            res,
            null_mut(),
            "OpenProcess(worker) failed with error {}",
            GetLastError()
        );
        Handle::new(res as u64).unwrap()
    };
    // Voluntarily inject a full-privilege handle to ourselves into the worker
    // /!\ NEVER DO THIS, THIS COMPLETELY BREAKS SANDBOXING BOUNDARIES
    let res = unsafe {
        let mut _voluntarily_leaked: HANDLE = null_mut();
        DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentProcess(),
            h_worker.as_raw() as HANDLE,
            &mut _voluntarily_leaked as *mut _,
            PROCESS_ALL_ACCESS,
            0,
            0,
        )
    };
    assert_ne!(res, 0, "DuplicateHandle() failed with error {}", unsafe {
        GetLastError()
    });
    common_teardown(worker, tmpleakpath);
}
