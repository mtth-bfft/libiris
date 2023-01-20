use common::os::wait_for_worker_exit;
use common::{
    check_worker_handles, cleanup_tmp_file, common_test_setup, get_worker_abs_path, open_tmp_file,
    read_tmp_file,
};
use iris_broker::{downcast_to_handle, CrossPlatformHandle, Policy, ProcessConfig, Worker};
use std::fs::File;

// Voluntarily set up resources (opened handles and file descriptors)
// ready to be leaked into our children. This could be the result of
// e.g. a poorly written parent program, or a poorly written plugin/AV
// injected into it or into its parents.

#[cfg(unix)]
fn os_specific_setup() {
    use std::net::TcpListener;

    let file = File::open("/etc/hosts").expect("opening generic test file failed");
    let mut handle = downcast_to_handle(file);
    handle.set_inheritable(true).unwrap();

    let sock = TcpListener::bind("127.0.0.1:0").expect("opening generic test socket failed");
    let mut handle = downcast_to_handle(sock);
    handle.set_inheritable(true).unwrap();
}

#[cfg(windows)]
fn os_specific_setup() {
    let file = File::open("C:\\Windows\\System32\\drivers\\etc\\hosts")
        .expect("opening generic test file failed");
    let mut handle = downcast_to_handle(file);
    handle.set_inheritable(true).unwrap();
}

#[ignore] // not ready for now
#[test]
fn inherited_resources_no_leak() {
    common_test_setup();
    os_specific_setup();

    let worker_binary = get_worker_abs_path("inherited_resources_no_leak_worker");
    // TODO: remove stdout redirection to avoid it showing up in the test results? Or find a better solution
    let (tmpout, tmpoutpath) = open_tmp_file();
    let tmpout = downcast_to_handle(tmpout);
    let policy = Policy::nothing_allowed(); // don't allow anything to be inherited, check that it receives nothing
    let proc_config = ProcessConfig::new(worker_binary.clone(), &[worker_binary])
        .with_stdout_redirected(&tmpout)
        .unwrap()
        .with_stderr_redirected(&tmpout)
        .unwrap();
    let worker = Worker::new(&proc_config, &policy).expect("worker creation failed");
    check_worker_handles(&worker);
    assert_eq!(
        wait_for_worker_exit(&worker),
        Ok(0),
        "worker reported an error, see its output log:\n{}",
        read_tmp_file(&tmpoutpath)
    );
    cleanup_tmp_file(&tmpoutpath);
}
