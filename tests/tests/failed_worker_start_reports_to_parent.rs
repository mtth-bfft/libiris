use iris_broker::{Policy, Worker};
use common::{cleanup_tmp_file, get_worker_bin_path, open_tmp_file};

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
