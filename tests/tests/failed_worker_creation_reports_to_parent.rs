use iris_broker::{Policy, Worker};
use std::ffi::CString;

#[test]
fn failed_execve_reports_to_parent() {
    let worker_binary = CString::new("nonexistent").unwrap();
    let policy = Policy::new();
    let worker = Worker::new(
        &policy,
        &worker_binary,
        &[&worker_binary],
        &[],
        None,
        None,
        None,
    );
    assert!(worker.is_err(), "worker creation should have failed");
}
