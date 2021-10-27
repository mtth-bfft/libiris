#[cfg(target_family = "windows")]
fn main() {}

#[cfg(target_family = "unix")]
fn main() {
    use iris_worker::initialize_sandbox_as_soon_as_possible;
    use libc::c_int;
    use std::convert::TryInto;
    use std::ffi::CString;

    initialize_sandbox_as_soon_as_possible();
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 2);
    let path = CString::new(args[1].as_str()).unwrap();

    let fd = unsafe {
        libc::syscall(
            libc::SYS_open,
            path.as_ptr(),
            libc::O_WRONLY | libc::O_APPEND,
            0,
            0,
            0,
            0,
        )
    };
    let fd: c_int = fd.try_into().unwrap();
    assert!(
        fd >= 0,
        "syscall(open, {}, O_WRONLY | O_APPEND) = {} (errno {})",
        path.to_string_lossy(),
        fd,
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    );

    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    unsafe {
        *(libc::__errno_location()) = 0;
    }
    let res = unsafe {
        libc::syscall(
            libc::SYS_fcntl,
            fd,
            libc::F_SETFL,
            flags & !libc::O_APPEND,
            0,
            0,
        )
    };
    let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    assert_eq!(res, -1, "fcntl(F_SETFL) = {} (errno {})", res, err);
    assert_eq!(err, libc::EPERM, "fcntl(F_SETFL) = {} (errno {})", res, err);

    assert_eq!(
        unsafe { libc::close(fd) },
        0,
        "failed to close file descriptor after test"
    );
}
