use common::get_worker_bin_path;
use iris_broker::{Policy, Worker};

#[test]
fn failed_process_initialization_reports_to_parent() {
    let worker_binary = get_worker_bin_path();
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
