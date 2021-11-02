use common::{cleanup_tmp_file, get_worker_bin_path, open_tmp_file};
use iris_broker::{downcast_to_handle, Policy, Worker};
use std::io::{Seek, SeekFrom, Write};
use std::sync::Arc;

#[test]
fn stdout_stderr() {
    let policy = Policy::new();
    let (mut tmpin, tmpinpath) = open_tmp_file();
    let (tmpout, tmpoutpath) = open_tmp_file();
    let (tmperr, tmperrpath) = open_tmp_file();
    tmpin.write_all(b"OK_STDIN").unwrap();
    tmpin.seek(SeekFrom::Start(0)).unwrap();
    let (tmpin, tmpout, tmperr) = (
        downcast_to_handle(tmpin),
        downcast_to_handle(tmpout),
        downcast_to_handle(tmperr),
    );
    let (tmpin, tmpout, tmperr) = (Arc::new(tmpin), Arc::new(tmpout), Arc::new(tmperr));
    let worker_binary = get_worker_bin_path();
    let worker = Worker::new(
        &policy,
        &worker_binary,
        &[&worker_binary],
        &[],
        Some(Arc::clone(&tmpin)),
        Some(Arc::clone(&tmpout)),
        Some(Arc::clone(&tmperr)),
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
