use common::{common_test_setup, open_tmp_file, read_tmp_file, get_worker_abs_path, os::wait_for_worker_exit};
use iris_policy::{Policy, PolicyRequest, PolicyVerdict, downcast_to_handle};
use iris_broker::{ProcessConfig, Worker};
use std::io::Write;
use std::sync::{Arc, Mutex};

#[test]
fn policy_log_callback() {
    common_test_setup();
    let (tmpout, tmpoutpath) = open_tmp_file();
    let tmpout = downcast_to_handle(tmpout);
    let (mut tmpok, tmpokpath) = open_tmp_file();
    tmpok.write_all(b"OK").unwrap();
    drop(tmpok);
    let mut policy = Policy::nothing_allowed();
    policy.allow_file_read(&tmpokpath.to_string_lossy()).unwrap();
    let state = Arc::new(Mutex::new(0u64));
    let closure_state = state.clone();
    policy.add_log_callback(Box::new(move |request: &PolicyRequest, verdict: &PolicyVerdict| {
        println!("Request: {:?}", request);
        println!("Verdict: {:?}", verdict);
        let mut lock = closure_state.lock().expect("failed to acquire lock in closure");
        if *lock == 0 {
            assert_eq!(*verdict, PolicyVerdict::Granted);
        } else if *lock == 1 {
            assert!(matches!(verdict, PolicyVerdict::DeniedByPolicy { .. }));
        } else {
            panic!("Callback called too many times");
        }
        *lock += 1;
    }));

    let worker_binary = get_worker_abs_path("policy_log_callback_worker");
    let proc_config = ProcessConfig::new(
        worker_binary.clone(),
        &[
            worker_binary,
            tmpokpath,
        ]
    )
    .with_stdout_redirected(&tmpout)
    .unwrap()
    .with_stderr_redirected(&tmpout)
    .unwrap();
    let worker = Worker::new(&proc_config, &policy)
        .expect("worker creation failed");
    assert_eq!(
        wait_for_worker_exit(&worker),
        Ok(0),
        "worker reported an error, see its output log:\n{}",
        read_tmp_file(&tmpoutpath)
    );
    // Re-acquire the state to check it ended with the expected value
    let lock = state.lock().unwrap();
    assert_eq!(*lock, 2);
}
