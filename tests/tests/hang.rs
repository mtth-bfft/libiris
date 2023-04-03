use common::os::wait_for_worker_exit;
use common::{common_test_setup, get_worker_abs_path, open_tmp_file};
use iris_broker::{downcast_to_handle, Policy, ProcessConfig, Worker};

// Test not run by default: it will hang forever, on purpose.
// This is just to easily have a sandboxed process to run tests on.
#[ignore]
#[test]
fn spawn() {
    common_test_setup();
    let worker_binary = get_worker_abs_path("hang_worker");
    let (tmpout, _) = open_tmp_file();
    let tmpout = downcast_to_handle(tmpout);
    let mut proc_config = ProcessConfig::new(worker_binary.clone(), &[worker_binary]);
    proc_config
        .redirect_stdout(Some(&tmpout))
        .unwrap()
        .redirect_stderr(Some(&tmpout))
        .unwrap();

    let worker =
        Worker::new(&proc_config, &Policy::nothing_allowed()).expect("worker creation failed");
    let res = wait_for_worker_exit(&worker);
    panic!(
        "wait_for_worker_exit() returned {:?}, should have hung forever",
        res
    );
}
