use iris_broker::Worker;
use iris_ipc::{CrossPlatformHandle, HandleError, os::Handle};
use std::os::fd::{IntoRawFd, AsRawFd};

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
        panic!("File descriptor leaked into worker process: {path}");
    }
}

pub fn wait_for_worker_exit(worker: &Worker) -> Result<u64, String> {
    let pid: i32 = worker
        .get_pid()
        .try_into()
        .map_err(|_| "Invalid PID".to_owned())?;
    let mut wstatus: libc::c_int = 0;
    loop {
        let res = unsafe { libc::waitpid(pid, &mut wstatus as *mut _, libc::__WALL) };
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

pub fn downcast_to_handle<T: IntoRawFd>(resource: T) -> Handle {
    unsafe { Handle::from_raw(resource.into_raw_fd() as u64) }
        .expect(&format!("could not downcast into Handle"))
}

pub fn set_unmanaged_handle_inheritable<T: AsRawFd>(
    resource: &T,
    allow_inherit: bool,
) -> Result<(), HandleError> {
    // This block is safe because the file descriptor held by `resource` lives at least
    // for the duration of the block, and we don't take ownership of it
    let fd = resource.as_raw_fd().try_into().unwrap();
    unsafe {
        let mut handle = Handle::from_raw(fd).unwrap();
        let res = handle.set_inheritable(allow_inherit);
        let _ = handle.into_raw(); // leak voluntarily
        res
    }
}
