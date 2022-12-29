#[cfg(target_family = "windows")]
#[test]
fn fcntl_fsetfd_blocked() {
    use log::info;

    info!("There is no fcntl() on Windows");
}

#[cfg(target_family = "unix")]
#[test]
fn fcntl_fsetfd_blocked() {
    use common::{cleanup_tmp_file, common_test_setup, get_worker_abs_path, open_tmp_file};
    use common::os::wait_for_worker_exit;
    use iris_broker::{downcast_to_handle, Policy, ProcessConfig, Worker};
    use std::ffi::CString;

    common_test_setup();
    let worker_binary = get_worker_abs_path("fcntl_fsetfl_blocked_worker");
    let (tmpout, tmpoutpath) = open_tmp_file();
    let tmpout = downcast_to_handle(tmpout);
    let (_, tmpwritablepath) = open_tmp_file();
    let mut policy = Policy::nothing_allowed();
    // Make the file append-only
    policy
        .allow_file_access(&tmpwritablepath.to_string_lossy(), true, true, true)
        .unwrap();
    let proc_config = ProcessConfig::new(
        worker_binary.clone(),
        &[
            worker_binary,
            CString::new(tmpwritablepath.to_str().unwrap()).unwrap(),
        ],
    )
    .with_stdout_redirected(&tmpout)
    .unwrap()
    .with_stderr_redirected(&tmpout)
    .unwrap();
    let worker = Worker::new(&proc_config, &policy).expect("worker creation failed");
    assert_eq!(
        wait_for_worker_exit(&worker),
        Ok(0),
        "worker reported an error, see its output log"
    );
    cleanup_tmp_file(&tmpoutpath);
    cleanup_tmp_file(&tmpwritablepath);
}
