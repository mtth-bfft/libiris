use common::{cleanup_tmp_file, get_worker_bin_path, open_tmp_file};
use iris_broker::{downcast_to_handle, Policy, Worker};
use std::io::{Seek, SeekFrom, Write};

#[test]
fn stdout_stderr() {
    let (mut tmpin, tmpinpath) = open_tmp_file();
    let (tmpout, tmpoutpath) = open_tmp_file();
    let (tmperr, tmperrpath) = open_tmp_file();
    tmpin.write_all(b"OK_STDIN").unwrap();
    tmpin.seek(SeekFrom::Start(0)).unwrap();
    let worker_binary = get_worker_bin_path();
    let mut worker = Worker::new(
        &Policy::nothing_allowed(),
        &worker_binary,
        &[&worker_binary],
        &[],
        Some(&downcast_to_handle(tmpin)),
        Some(&downcast_to_handle(tmpout)),
        Some(&downcast_to_handle(tmperr)),
    )
    .expect("worker creation failed");
    assert_eq!(worker.wait_for_exit(), Ok(0), "worker wait_for_exit failed");
    assert_eq!(
        std::fs::read_to_string(&tmpoutpath).expect("failed to read stdout"),
        "OK_STDOUT\n".to_owned(),
        "unexpected value from stdout"
    );
    assert_eq!(
        std::fs::read_to_string(&tmperrpath).expect("failed to read stderr"),
        "OK_STDERR\n".to_owned(),
        "unexpected value from stderr"
    );
    cleanup_tmp_file(&tmpinpath);
    cleanup_tmp_file(&tmpoutpath);
    cleanup_tmp_file(&tmperrpath);
}
