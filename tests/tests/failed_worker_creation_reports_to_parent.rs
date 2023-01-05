use common::common_test_setup;
use iris_broker::{Policy, ProcessConfig, Worker, BrokerError};
use std::ffi::CString;

#[test]
fn failed_execve_reports_to_parent() {
    common_test_setup();
    let worker_binary = CString::new("nonexistent").unwrap();
    let proc_config = ProcessConfig::new(worker_binary.clone(), &[worker_binary]);
    let policy = Policy::nothing_allowed();
    let worker = Worker::new(&proc_config, &policy);
    let worker = worker.expect_err("worker creation should have failed");
    assert_eq!(worker, BrokerError::InternalOsOperationFailed { description: "execve()".to_owned(), os_code: libc::ENOENT as u64 }, "worker creation errno not propagated correctly");
}
