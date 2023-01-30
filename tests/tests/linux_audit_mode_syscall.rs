#![cfg(target_os = "linux")]

use common::os::wait_for_worker_exit;
use common::{
    cleanup_tmp_file, common_test_setup, get_worker_abs_path, open_tmp_file, read_tmp_file,
};
use iris_broker::{downcast_to_handle, Policy, ProcessConfig, Worker};
use iris_policy::{PolicyRequest, PolicyVerdict};
use std::sync::{Arc, Mutex};

#[test]
fn linux_audit_mode_syscall() {
    common_test_setup();
    let worker_binary = get_worker_abs_path("linux_audit_mode_syscall_worker");
    let (tmpout, tmpoutpath) = open_tmp_file();
    let tmpout = downcast_to_handle(tmpout);
    let mut proc_config = ProcessConfig::new(worker_binary.clone(), &[worker_binary]);
    proc_config
        .redirect_stdout(Some(&tmpout))
        .unwrap()
        .redirect_stderr(Some(&tmpout))
        .unwrap();
    let mut policy = Policy::unsafe_testing_audit_only();

    let called = Arc::new(Mutex::new(false));
    let called2 = called.clone();
    policy.add_log_callback(Box::new(
        move |request: &PolicyRequest, _verdict: &PolicyVerdict| {
            if let PolicyRequest::Syscall { nb, args, .. } = request {
                if *nb == 999 && args == &[1, 2, 3, 4, 5, 6] {
                    *called.lock().unwrap() = true;
                }
            }
        },
    ));

    let worker = Worker::new(&proc_config, &policy).expect("worker creation failed");
    assert_eq!(
        wait_for_worker_exit(&worker),
        Ok(0),
        "worker reported an error, see its output log:\n{}",
        read_tmp_file(&tmpoutpath)
    );
    assert!(
        *called2.lock().unwrap(),
        "policy log callback did not receive a denied syscall event"
    );
    cleanup_tmp_file(&tmpoutpath);
}
