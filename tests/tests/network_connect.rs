use common::{cleanup_tmp_file, get_worker_bin_path, open_tmp_file};
use iris_broker::{downcast_to_handle, Policy, Worker};
use std::ffi::CString;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

#[ignore] // not ready yet
#[test]
fn network_connect_loopback() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("unable to bind port on localhost");
    let port = match listener.local_addr() {
        Ok(SocketAddr::V4(addr)) => addr.port(),
        _ => panic!("Unable to query socket port"),
    };
    println!(" [.] Waiting for connection on 127.0.0.1:{}", port);
    thread::spawn(move || match listener.accept() {
        Ok((_sock, addr)) => println!(" [+] Ok, received connect from {:?}", addr),
        Err(e) => println!(" [!] ERROR when accepting connection: {}", e),
    });

    let policy = Policy::new();
    let worker_binary = get_worker_bin_path();
    let (tmpout, tmpoutpath) = open_tmp_file();
    let tmpout = Arc::new(downcast_to_handle(tmpout));
    let worker = Worker::new(
        &policy,
        &worker_binary,
        &[
            &worker_binary,
            &CString::new("127.0.0.1").unwrap(),
            &CString::new(format!("{}", port)).unwrap(),
        ],
        &[],
        None,
        Some(Arc::clone(&tmpout)),
        Some(Arc::clone(&tmpout)),
    )
    .expect("worker creation failed");
    assert_eq!(
        worker.wait_for_exit(),
        Ok(0),
        "worker reported an error, check its output logs"
    );
    cleanup_tmp_file(&tmpoutpath);
}
