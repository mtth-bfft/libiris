use common::os::{downcast_to_handle, wait_for_worker_exit};
use common::{cleanup_tmp_file, common_test_setup, get_worker_abs_path, open_tmp_file};
use iris_broker::{ProcessConfig, Worker};
use iris_policy::Policy;

#[test]
fn spawn() {
    common_test_setup();
    let worker_binary = get_worker_abs_path("spawn_with_dynamically_loaded_library_worker");
    let (tmpout, tmpoutpath) = open_tmp_file();
    let tmpout = downcast_to_handle(tmpout);
    let mut proc_config = ProcessConfig::new(worker_binary.clone(), &[worker_binary.clone()]);
    proc_config
        .redirect_stdout(Some(&tmpout))
        .unwrap()
        .redirect_stderr(Some(&tmpout))
        .unwrap();

    // Windows searches the .exe's directory for DLLs, but Unix dynamic
    // linkers don't. Tell them manually that the library is in the same directory.
    #[cfg(target_family = "unix")]
    {
        let lib_dir = std::path::Path::new(worker_binary.to_str().unwrap())
            .parent()
            .unwrap()
            .to_str()
            .unwrap();
        proc_config
            .set_environment_variable(
                std::ffi::CString::new(format!("LD_LIBRARY_PATH={}", lib_dir)).unwrap(),
            )
            .expect("failed to set LD_LIBRARY_PATH");
    }

    let policy = Policy::nothing_allowed();
    let worker = Worker::new(&proc_config, &policy).expect("worker creation failed");
    assert_eq!(
        wait_for_worker_exit(&worker),
        Ok(42),
        "worker wait_for_exit failed"
    );
    cleanup_tmp_file(&tmpoutpath);
}
