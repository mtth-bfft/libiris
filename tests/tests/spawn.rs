use common::{cleanup_tmp_file, common_test_setup, get_worker_abs_path, open_tmp_file};
use common::os::{wait_for_worker_exit, downcast_to_handle};
use iris_broker::{ProcessConfig, Worker};
use iris_policy::Policy;

#[test]
fn spawn() {
    common_test_setup();
    let worker_binary = get_worker_abs_path("spawn_worker");
    let (tmpout, tmpoutpath) = open_tmp_file();
    let tmpout = downcast_to_handle(tmpout);
    let mut proc_config = ProcessConfig::new(worker_binary.clone(), &[worker_binary]);
    proc_config
        .redirect_stdout(Some(&tmpout))
        .unwrap()
        .redirect_stderr(Some(&tmpout))
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
