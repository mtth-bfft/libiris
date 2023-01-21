use common::os::wait_for_worker_exit;
use common::{cleanup_tmp_file, common_test_setup, get_worker_abs_path, open_tmp_file};
use iris_broker::{downcast_to_handle, Policy, ProcessConfig, Worker};

#[test]
fn inherited_dup_handles() {
    common_test_setup();
    let (tmpout, tmpoutpath) = open_tmp_file(); // duplicate tmpout as stdout and stderr and a handle to be inherited
    let (tmpin, tmpinpath) = open_tmp_file(); // duplicate tmpin as stdin and a handle to be inherited
    let (tmpout, tmpin) = (downcast_to_handle(tmpout), downcast_to_handle(tmpin));

    let mut policy = Policy::nothing_allowed();
    policy.allow_inherit_handle(&tmpout).unwrap();
    policy.allow_inherit_handle(&tmpin).unwrap();

    let worker_binary = get_worker_abs_path("inherited_dup_handles_worker");
    let proc_conf = ProcessConfig::new(worker_binary.clone(), &[worker_binary])
        .with_stdin_redirected(&tmpin)
        .unwrap();

    let worker = Worker::new(&proc_conf, &policy).expect("worker creation failed");
    assert_eq!(
        wait_for_worker_exit(&worker),
        Ok(0),
        "worker reported an error"
    );
    cleanup_tmp_file(&tmpoutpath);
    cleanup_tmp_file(&tmpinpath);
}
