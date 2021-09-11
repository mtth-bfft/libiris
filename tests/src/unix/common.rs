use iris_broker::Worker;

pub fn check_worker_handles(worker: &Worker) {
    let mut sandbox_ipc_socket_found = false;
    for entry in std::fs::read_dir(format!("/proc/{}/fd/", worker.get_pid()))
        .expect("unable to read /proc/x/fd/ directory")
    {
        let entry = entry.expect("unable to read /proc/x/fd/ entry");
        let mut path = entry.path();
        loop {
            match std::fs::read_link(&path) {
                Ok(target) => path = target,
                Err(_) => break,
            }
        }
        let path = path.to_string_lossy();
        // Stdin, stdout, and stderr can be redirected to /dev/null (harmless)
        if path == "/dev/null" {
            continue;
        }
        if path.starts_with("socket:[") && !sandbox_ipc_socket_found {
            sandbox_ipc_socket_found = true; // ignore exactly one Unix socket, the one we use to communicate with our broker
            continue;
        }
        panic!("File descriptor leaked into worker process: {}", path);
    }
}
