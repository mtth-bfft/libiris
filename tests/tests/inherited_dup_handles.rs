use common::{cleanup_tmp_file, get_worker_bin_path, open_tmp_file};
use iris_broker::{downcast_to_handle, Policy, Worker};
use std::sync::Arc;

#[test]
fn inherited_dup_handles() {
    let (tmpout, tmpoutpath) = open_tmp_file(); // duplicate tmpout as stdout and stderr and a handle to be inherited
    let (tmpin, tmpinpath) = open_tmp_file(); // duplicate tmpin as stdin and a handle to be inherited
    let mut policy = Policy::new();
    let (tmpout, tmpin) = (Arc::new(downcast_to_handle(tmpout)), Arc::new(downcast_to_handle(tmpin)));
    policy.allow_inherit_handle(Arc::clone(&tmpout)).unwrap();
    policy.allow_inherit_handle(Arc::clone(&tmpin)).unwrap();

    let worker_binary = get_worker_bin_path();
    let mut worker = Worker::new(
        &policy,
        &worker_binary,
        &[&worker_binary],
        &[],
        Some(Arc::clone(&tmpin)),
        Some(Arc::clone(&tmpout)),
        Some(Arc::clone(&tmpout)),
    )
    .expect("worker creation failed");
    assert_eq!(worker.wait_for_exit(), Ok(0), "worker reported an error");
    cleanup_tmp_file(&tmpoutpath);
    cleanup_tmp_file(&tmpinpath);
}
