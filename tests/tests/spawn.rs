use common::{cleanup_tmp_file, common_test_setup, get_worker_abs_path, open_tmp_file};
use iris_broker::{downcast_to_handle, Policy, Worker};

#[test]
fn spawn() {
    common_test_setup();
    let worker_binary = get_worker_abs_path("spawn_worker");
    let (tmpout, tmpoutpath) = open_tmp_file();
    let tmpout = downcast_to_handle(tmpout);
    let mut worker = Worker::new(
        &Policy::nothing_allowed(),
        &worker_binary,
        &[&worker_binary],
        &[],
        None,
        Some(&tmpout),
        Some(&tmpout),
    )
    .expect("worker creation failed");
    assert_eq!(
        worker.wait_for_exit(),
        Ok(42),
        "worker wait_for_exit failed"
    );
    cleanup_tmp_file(&tmpoutpath);
}
