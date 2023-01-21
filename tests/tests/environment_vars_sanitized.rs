use common::os::wait_for_worker_exit;
use common::{common_test_setup, get_worker_abs_path};
use iris_broker::{Policy, ProcessConfig, Worker};

#[test]
fn environment_vars_sanitized() {
    common_test_setup();
    let worker_binary = get_worker_abs_path("environment_vars_sanitized_worker");
    let proc_config = ProcessConfig::new(worker_binary.clone(), &[worker_binary]);
    let worker =
        Worker::new(&proc_config, &Policy::nothing_allowed()).expect("worker creation failed");
    assert_eq!(
        wait_for_worker_exit(&worker),
        Ok(0),
        "worker wait_for_exit failed"
    );
}
