use common::os::wait_for_worker_exit;
use common::{cleanup_tmp_file, common_test_setup, get_worker_abs_path, open_tmp_file};
use iris_broker::{ProcessConfig, Worker};
use iris_ipc::downcast_to_handle;
use iris_policy::Policy;
use std::env;
use log::info;

#[test]
fn spawn_with_shared_dep() {
    common_test_setup();
    let worker_binary = get_worker_abs_path("spawn_with_shared_dep_worker");
    let (tmpout, tmpoutpath) = open_tmp_file();
    let tmpout = downcast_to_handle(tmpout);
    let mut proc_config = ProcessConfig::new(worker_binary.clone(), &[worker_binary]);
    proc_config
        .redirect_stdout(Some(&tmpout))
        .unwrap()
        .redirect_stderr(Some(&tmpout))
        .unwrap();

    let mut policy = Policy::nothing_allowed();
    let dll_dir = env::var("DLL_DIR").unwrap();
    let dll_path = format!("{}\\libdummy.dll", dll_dir);

    info!("Allowing file read: {}", dll_path);
    policy.allow_file_read(&dll_path).unwrap();

    let worker =
        Worker::new(&proc_config, &policy).expect("worker creation failed");
    assert_eq!(
        wait_for_worker_exit(&worker),
        Ok(42),
        "worker wait_for_exit failed"
    );
    cleanup_tmp_file(&tmpoutpath);
}
