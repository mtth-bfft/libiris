use common::os::{downcast_to_handle, wait_for_worker_exit};
use common::{common_test_setup, get_worker_abs_path, open_tmp_file, read_tmp_file};
use iris_broker::{ProcessConfig, Worker};
use iris_policy::os::PolicyRequest;
use iris_policy::{Policy, PolicyVerdict};
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
    policy
        .allow_file_read(&tmpokpath.to_string_lossy())
        .unwrap();
    let state = Arc::new(Mutex::new(0u64));
    let closure_state = state.clone();
    // The callback gets called with NT file paths on Windows, so we can't simply
    // compare the FileOpen { path } with tmpokpath to make sure we're talking about
    // the same file. Compare file names, which are unique enough.
    let tmpfilename: String = tmpokpath
        .to_string_lossy()
        .rsplit_once(['/', '\\'])
        .unwrap()
        .1
        .to_owned();
    policy.add_log_callback(Box::new(
        move |request: &PolicyRequest, verdict: &PolicyVerdict| {
            println!("Request: {request:?}");
            println!("Verdict: {verdict:?}");
            let mut lock = closure_state
                .lock()
                .expect("failed to acquire lock in closure");
            if let PolicyRequest::FileOpen { path, .. } = request {
                let requested_filename = path.rsplit_once(['/', '\\']).unwrap().1;
                if requested_filename == tmpfilename
                    && *lock == 0
                    && *verdict == PolicyVerdict::Granted
                {
                    *lock += 1;
                }
                if let PolicyVerdict::DeniedByPolicy { .. } = verdict {
                    if requested_filename == tmpfilename && *lock == 1 {
                        *lock += 1;
                    }
                }
            }
        },
    ));

    let worker_binary = get_worker_abs_path("policy_log_callback_worker");
    let mut proc_config = ProcessConfig::new(worker_binary.clone(), &[worker_binary, tmpokpath]);
    proc_config
        .redirect_stdout(Some(&tmpout))
        .unwrap()
        .redirect_stderr(Some(&tmpout))
        .unwrap();
    let worker = Worker::new(&proc_config, &policy).expect("worker creation failed");
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
