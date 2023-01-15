use common::{common_test_setup, open_tmp_file, read_tmp_file, get_worker_abs_path, os::wait_for_worker_exit};
use iris_policy::{Policy, PolicyRequest, PolicyVerdict, downcast_to_handle};
use iris_broker::{ProcessConfig, Worker};
use std::io::Write;
use std::sync::{Arc, Mutex};
use core::ffi::c_void;

extern "C" fn test_callback(request: &PolicyRequest, verdict: &PolicyVerdict, ctx: *const c_void) {
    println!("Request: {:?}", request);
    println!("Verdict: {:?}", verdict);
    let state = unsafe { Box::from_raw(ctx as *mut c_void as *mut Arc<Mutex<u64>>) };
    let mut lock = state.lock().unwrap();
    if *lock == 0 {
        assert_eq!(*verdict, PolicyVerdict::Granted);
    } else if *lock == 1 {
        assert!(matches!(verdict, PolicyVerdict::DeniedByPolicy { .. }));
    } else {
        panic!("Callback called too many times");
    }
    *lock = *lock + 1;
    drop(lock);
    Box::leak(Box::new(state));
}

#[test]
fn policy_log_callback() {
    common_test_setup();
    let (tmpout, tmpoutpath) = open_tmp_file();
    let tmpout = downcast_to_handle(tmpout);
    let (mut tmpok, tmpokpath) = open_tmp_file();
    tmpok.write_all(b"OK").unwrap();
    drop(tmpok);
    let worker_binary = get_worker_abs_path("policy_log_callback_worker");
    let state = Arc::new(Mutex::new(0u64));
    let state_ptr: *mut Arc<Mutex<u64>> = Box::leak(Box::new(state)) as *mut _;
    let mut policy = Policy::nothing_allowed();
    policy.allow_file_read(&tmpokpath.to_string_lossy()).unwrap();
    policy.add_log_callback(test_callback, state_ptr as *const c_void);
    let proc_config = ProcessConfig::new(
        worker_binary.clone(),
        &[
            worker_binary.clone(),
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
    let state = unsafe { Box::from_raw(state_ptr) };
    let lock = state.lock().unwrap();
    assert_eq!(*lock, 2);
}
