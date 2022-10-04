use common::common_test_setup;
use iris_broker::{Policy, Worker};
use std::ffi::CString;

#[test]
fn failed_execve_reports_to_parent() {
    common_test_setup();
    let worker_binary = CString::new("nonexistent").unwrap();
    let worker = Worker::new(
        &Policy::nothing_allowed(),
        &worker_binary,
        &[&worker_binary],
        &[],
        None,
        None,
        None,
    );
    assert!(worker.is_err(), "worker creation should have failed");
}
