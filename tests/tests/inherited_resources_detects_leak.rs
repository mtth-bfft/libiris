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
#[should_panic(expected = "file handle")]
fn inherited_resources_detects_leak_file() {
    use core::ptr::null_mut;
    use std::convert::TryInto;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::handleapi::{CloseHandle, DuplicateHandle};
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess};
    use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS, PROCESS_DUP_HANDLE};

    let (worker, tmpleakpath) = common_setup();

    let h_worker =
        unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, worker.get_pid().try_into().unwrap()) };
    assert_ne!(
        h_worker,
        null_mut(),
        "OpenProcess(worker) failed with error {}",
        unsafe { GetLastError() }
    );
    // Voluntarily inject a full-privilege handle to ourselves into the worker
    // /!\ NEVER DO THIS, THIS COMPLETELY BREAKS SANDBOXING BOUNDARIES
    let mut _voluntarily_leaked: HANDLE = null_mut();
    let res = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentProcess(),
            h_worker,
            &mut _voluntarily_leaked as *mut _,
            PROCESS_ALL_ACCESS,
            0,
            0,
        )
    };
    assert_ne!(res, 0, "DuplicateHandle() failed with error {}", unsafe {
        GetLastError()
    });
    unsafe { CloseHandle(h_worker) };

    common_teardown(worker, tmpleakpath);
}

#[test]
#[cfg(windows)]
#[should_panic(expected = "process handle")]
fn inherited_resources_detects_leak_process() {
    use core::ptr::null_mut;
    use std::convert::TryInto;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::handleapi::{CloseHandle, DuplicateHandle};
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess};
    use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS, PROCESS_DUP_HANDLE};

    let (worker, tmpleakpath) = common_setup();

    let h_worker =
        unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, worker.get_pid().try_into().unwrap()) };
    assert_ne!(
        h_worker,
        null_mut(),
        "OpenProcess(worker) failed with error {}",
        unsafe { GetLastError() }
    );
    // Voluntarily inject a full-privilege handle to ourselves into the worker
    // /!\ NEVER DO THIS, THIS COMPLETELY BREAKS SANDBOXING BOUNDARIES
    let mut _voluntarily_leaked: HANDLE = null_mut();
    let res = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentProcess(),
            h_worker,
            &mut _voluntarily_leaked as *mut _,
            PROCESS_ALL_ACCESS,
            0,
            0,
        )
    };
    assert_ne!(res, 0, "DuplicateHandle() failed with error {}", unsafe {
        GetLastError()
    });
    unsafe { CloseHandle(h_worker) };

    common_teardown(worker, tmpleakpath);
}
