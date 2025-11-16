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

    // Windows searches the worker EXE's directory for DLLs. However, dummy_library.dll
    // is not a first-class build target, so it ends up in target\<profile>\deps instead
    // of target\<profile>\ . Copy it, so that it is found and so that its ACL is patched
    // to allow the worker to load it.
    if cfg!(windows) {
        let lib_dir = std::path::Path::new(worker_binary.to_str().unwrap())
            .parent()
            .unwrap();
        let dll_path = lib_dir.join("deps").join("dummy_library.dll");
        assert!(dll_path.is_file());
        let target_path = lib_dir.join("dummy_library.dll");
        if !target_path.is_file() {
            std::fs::copy(dll_path, target_path).unwrap();
        }
    }
    // Unix dynamic linkers don't search the executable's directory. Tell them manually
    // that the library is in the same directory.
    else {
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
