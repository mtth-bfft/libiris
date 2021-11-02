use common::{check_worker_handles, get_worker_bin_path};
use iris_broker::{downcast_to_handle, CrossPlatformHandle, Policy, Worker};
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

#[test]
fn inherited_resources_no_leak() {
    os_specific_setup();

    // Don't allow any resource to be inherited by the worker process, to check that it does not get unexpected ones
    let policy = Policy::new();

    let worker_binary = get_worker_bin_path();
    // TODO: remove stdout redirection to avoid it showing up in the test results? Or find a better solution
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
    check_worker_handles(&worker);
    assert_eq!(worker.wait_for_exit(), Ok(0), "worker reported an error");
}
