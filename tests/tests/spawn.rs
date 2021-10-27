use common::{cleanup_tmp_file, get_worker_bin_path, open_tmp_file};
use iris_broker::{downcast_to_handle, Policy, Worker};
use std::sync::Arc;

#[test]
fn spawn() {
    let policy = Policy::new();
    let worker_binary = get_worker_bin_path();
    let (tmpout, tmpoutpath) = open_tmp_file();
    let tmpout = Arc::new(downcast_to_handle(tmpout));
    let mut worker = Worker::new(
        &policy,
        &worker_binary,
        &[&worker_binary],
        &[],
        None,
        Some(Arc::clone(&tmpout)),
        Some(Arc::clone(&tmpout)),
    )
    .expect("worker creation failed");
    assert_eq!(
        worker.wait_for_exit(),
        Ok(42),
        "worker wait_for_exit failed"
    );
    cleanup_tmp_file(&tmpoutpath);
}
