use iris_broker::Worker;

pub fn check_worker_handles(worker: &Worker) {
    let mut sandbox_ipc_socket_found = false;
    for entry in std::fs::read_dir(format!("/proc/{}/fd/", worker.get_pid()))
        .expect("unable to read /proc/x/fd/ directory")
    {
        let entry = entry.expect("unable to read /proc/x/fd/ entry");
        let mut path = entry.path();
        while let Ok(target) = std::fs::read_link(&path) {
            path = target;
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

pub fn wait_for_worker_exit(worker: &Worker) -> Result<u64, String> {
    let pid: i32 = worker.get_pid().try_into().map_err(|_| "Invalid PID".to_owned())?;
    let mut wstatus: libc::c_int = 0;
    loop {
        let res =
            unsafe { libc::waitpid(pid, &mut wstatus as *mut _, libc::__WALL) };
        if res == -1 {
            return Err(format!(
                "waitpid({}) failed with code {}",
                pid,
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            ));
        }
        if libc::WIFEXITED(wstatus) {
            return Ok(libc::WEXITSTATUS(wstatus).try_into().unwrap());
        }
        if libc::WIFSIGNALED(wstatus) {
            return Ok((128 + libc::WTERMSIG(wstatus)).try_into().unwrap());
        }
    }
}

