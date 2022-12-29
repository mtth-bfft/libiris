use common::{cleanup_tmp_file, common_test_setup, get_worker_abs_path, open_tmp_file};
use common::os::wait_for_worker_exit;
use iris_broker::{downcast_to_handle, Policy, ProcessConfig, Worker};
use log::info;
use std::ffi::CString;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::thread;

#[ignore] // not ready yet
#[test]
fn network_connect_loopback() {
    common_test_setup();
    let listener = TcpListener::bind("127.0.0.1:0").expect("unable to bind port on localhost");
    let port = match listener.local_addr() {
        Ok(SocketAddr::V4(addr)) => addr.port(),
        _ => panic!("Unable to query socket port"),
    };
    info!("Waiting for connection on 127.0.0.1:{}", port);
    thread::spawn(move || match listener.accept() {
        Ok((_sock, addr)) => info!("Ok, received connect from {:?}", addr),
        Err(e) => panic!("Could not accept() incoming connections: {}", e),
    });

    let policy = Policy::nothing_allowed();
    let worker_binary = get_worker_abs_path("network_connect_worker");
    let (tmpout, tmpoutpath) = open_tmp_file();
    let tmpout = downcast_to_handle(tmpout);
    let proc_config = ProcessConfig::new(
        worker_binary.clone(),
        &[
            worker_binary,
            CString::new("127.0.0.1").unwrap(),
            CString::new(format!("{}", port)).unwrap(),
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
        "worker reported an error, check its output logs"
    );
    cleanup_tmp_file(&tmpoutpath);
}
