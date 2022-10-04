use common::{cleanup_tmp_file, common_test_setup, get_worker_bin_path, open_tmp_file};
use iris_broker::{downcast_to_handle, Policy, Worker};

#[test]
fn inherited_dup_handles() {
    common_test_setup();
    let (tmpout, tmpoutpath) = open_tmp_file(); // duplicate tmpout as stdout and stderr and a handle to be inherited
    let (tmpin, tmpinpath) = open_tmp_file(); // duplicate tmpin as stdin and a handle to be inherited
    let (tmpout, tmpin) = (downcast_to_handle(tmpout), downcast_to_handle(tmpin));
    let mut policy = Policy::nothing_allowed();
    policy.allow_inherit_handle(&tmpout).unwrap();
    policy.allow_inherit_handle(&tmpin).unwrap();

    let worker_binary = get_worker_bin_path();
    let mut worker = Worker::new(
        &policy,
        &worker_binary,
        &[&worker_binary],
        &[],
        Some(&tmpin),
        Some(&tmpout),
        Some(&tmpout),
    )
    .expect("worker creation failed");
    assert_eq!(worker.wait_for_exit(), Ok(0), "worker reported an error");
    cleanup_tmp_file(&tmpoutpath);
    cleanup_tmp_file(&tmpinpath);
}
