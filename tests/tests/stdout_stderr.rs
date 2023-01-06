use common::os::wait_for_worker_exit;
use common::{cleanup_tmp_file, common_test_setup, get_worker_abs_path, open_tmp_file, read_tmp_file};
use iris_broker::{downcast_to_handle, Policy, ProcessConfig, Worker};
use std::io::{Seek, SeekFrom, Write};

#[test]
fn stdout_stderr() {
    common_test_setup();
    let (mut tmpin, tmpinpath) = open_tmp_file();
    let (tmpout, tmpoutpath) = open_tmp_file();
    let (tmperr, tmperrpath) = open_tmp_file();
    tmpin.write_all(b"OK_STDIN").unwrap();
    tmpin.seek(SeekFrom::Start(0)).unwrap();
    let worker_binary = get_worker_abs_path("stdout_stderr_worker");
    let tmpin = downcast_to_handle(tmpin);
    let tmpout = downcast_to_handle(tmpout);
    let tmperr = downcast_to_handle(tmperr);
    let proc_config = ProcessConfig::new(worker_binary.clone(), &[worker_binary])
        .with_stdin_redirected(&tmpin)
        .unwrap()
        .with_stdout_redirected(&tmpout)
        .unwrap()
        .with_stderr_redirected(&tmperr)
        .unwrap();
    let worker =
        Worker::new(&proc_config, &Policy::nothing_allowed()).expect("worker creation failed");
    assert_eq!(
        wait_for_worker_exit(&worker),
        Ok(0),
        "worker wait_for_exit failed"
    );
    assert_eq!(
        read_tmp_file(&tmpoutpath),
        "OK_STDOUT\n".to_owned(),
        "unexpected value from stdout"
    );
    assert_eq!(
        read_tmp_file(&tmperrpath),
        "OK_STDERR\n".to_owned(),
        "unexpected value from stderr"
    );
    cleanup_tmp_file(&tmpinpath);
    cleanup_tmp_file(&tmpoutpath);
    cleanup_tmp_file(&tmperrpath);
}
