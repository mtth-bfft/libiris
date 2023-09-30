use common::os::wait_for_worker_exit;
use common::{
    cleanup_tmp_file, common_test_setup, get_worker_abs_path, open_tmp_file, read_tmp_file,
};
use iris_broker::{ProcessConfig, Worker};
use iris_ipc::downcast_to_handle;
use iris_policy::Policy;
use std::io::{Seek, Write};

#[test]
fn stdout_stderr() {
    common_test_setup();
    let (mut tmpin, tmpinpath) = open_tmp_file();
    let (tmpout, tmpoutpath) = open_tmp_file();
    let (tmperr, tmperrpath) = open_tmp_file();
    tmpin.write_all(b"OK_STDIN").unwrap();
    tmpin.rewind().unwrap();
    let worker_binary = get_worker_abs_path("stdout_stderr_worker");
    let tmpin = downcast_to_handle(tmpin);
    let tmpout = downcast_to_handle(tmpout);
    let tmperr = downcast_to_handle(tmperr);
    let mut proc_config = ProcessConfig::new(worker_binary.clone(), &[worker_binary]);
    proc_config
        .redirect_stdin(Some(&tmpin))
        .unwrap()
        .redirect_stdout(Some(&tmpout))
        .unwrap()
        .redirect_stderr(Some(&tmperr))
        .unwrap();
    let worker =
        Worker::new(&proc_config, &Policy::nothing_allowed()).expect("worker creation failed");
    assert_eq!(
        wait_for_worker_exit(&worker),
        Ok(0),
        "worker wait_for_exit failed"
    );
    assert!(
        read_tmp_file(&tmpoutpath).contains("OK_STDOUT\n"),
        "unexpected value from stdout"
    );
    assert!(
        read_tmp_file(&tmperrpath).contains("OK_STDERR\n"),
        "unexpected value from stderr"
    );
    cleanup_tmp_file(&tmpinpath);
    cleanup_tmp_file(&tmpoutpath);
    cleanup_tmp_file(&tmperrpath);
}
