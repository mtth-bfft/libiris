use common::{check_worker_handles, common_test_setup, get_worker_abs_path, open_tmp_file};
use iris_broker::{ProcessConfig, Worker};
use iris_ipc::downcast_to_handle;
use iris_policy::Policy;

// Voluntarily set up resources (opened handles and file descriptors)
// ready to be leaked into our children. This could be the result of
// e.g. a poorly written parent program, or a poorly written plugin/AV
// injected into it or into its parents.

#[cfg(unix)]
fn os_specific_setup(_worker: &Worker) {
    // TODO: set up file descriptors to be leaked
}

#[cfg(windows)]
fn os_specific_setup(worker: &Worker) {
    use core::ptr::null_mut;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::handleapi::{CloseHandle, DuplicateHandle};
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess};
    use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS, PROCESS_DUP_HANDLE};

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
    let mut voluntarily_leaked: HANDLE = null_mut();
    let res = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentProcess(),
            h_worker,
            &mut voluntarily_leaked as *mut _,
            PROCESS_ALL_ACCESS,
            0,
            0,
        )
    };
    assert_ne!(res, 0, "DuplicateHandle() failed with error {}", unsafe {
        GetLastError()
    });
    unsafe { CloseHandle(h_worker) };
}

#[ignore] // not ready for now
#[test]
#[should_panic(expected = "process")]
fn inherited_resources_detects_leak() {
    common_test_setup();
    let worker_binary = get_worker_abs_path("inherited_resources_detects_leak_worker");
    let (tmpout, _) = open_tmp_file();
    let tmpout = downcast_to_handle(tmpout);
    let mut proc_config = ProcessConfig::new(worker_binary.clone(), &[worker_binary]);
    proc_config
        .redirect_stdout(Some(&tmpout))
        .unwrap()
        .redirect_stderr(Some(&tmpout))
        .unwrap();
    let policy = Policy::nothing_allowed(); // don't allow any resource to be inherited, check that it receives nothing
    let worker = Worker::new(&proc_config, &policy).expect("worker creation failed");
    os_specific_setup(&worker);
    check_worker_handles(&worker);
}
