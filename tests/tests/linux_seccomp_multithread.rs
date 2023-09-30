#![cfg(target_os = "linux")]

use common::os::wait_for_worker_exit;
use common::{
    cleanup_tmp_file, common_test_setup, get_worker_abs_path, open_tmp_file, read_tmp_file,
};
use iris_broker::{ProcessConfig, Worker};
use iris_ipc::downcast_to_handle;
use iris_policy::Policy;

#[test]
fn linux_seccomp_multithread() {
    common_test_setup();
    let worker_binary = get_worker_abs_path("linux_seccomp_multithread_worker");
    println!(" TMP STDOUT:");
    let (tmpout, tmpoutpath) = open_tmp_file();
    println!(" END OF TMP STDOUT");
    let tmpout = downcast_to_handle(tmpout);
    let mut proc_config = ProcessConfig::new(worker_binary.clone(), &[worker_binary]);
    proc_config
        .redirect_stdout(Some(&tmpout))
        .unwrap()
        .redirect_stderr(Some(&tmpout))
        .unwrap();
    let policy = Policy::nothing_allowed();

    let worker = Worker::new(&proc_config, &policy).expect("worker creation failed");
    assert_eq!(
        wait_for_worker_exit(&worker),
        Ok(0),
        "worker reported an error, see its output log:\n{}",
        read_tmp_file(&tmpoutpath)
    );
    cleanup_tmp_file(&tmpoutpath);
}
