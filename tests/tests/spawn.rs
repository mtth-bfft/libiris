use common::os::wait_for_worker_exit;
use common::{cleanup_tmp_file, common_test_setup, get_worker_abs_path, open_tmp_file};
use iris_broker::{downcast_to_handle, Policy, ProcessConfig, Worker};

#[test]
fn spawn() {
    common_test_setup();
    let worker_binary = get_worker_abs_path("spawn_worker");
    let (tmpout, tmpoutpath) = open_tmp_file();
    let tmpout = downcast_to_handle(tmpout);
    let proc_config = ProcessConfig::new(worker_binary.clone(), &[worker_binary])
        .with_stdout_redirected(&tmpout)
        .unwrap()
        .with_stderr_redirected(&tmpout)
        .unwrap();

    let worker =
        Worker::new(&proc_config, &Policy::nothing_allowed()).expect("worker creation failed");
    assert_eq!(
        wait_for_worker_exit(&worker),
        Ok(42),
        "worker wait_for_exit failed"
    );
    cleanup_tmp_file(&tmpoutpath);
}
