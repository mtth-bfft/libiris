use libc::c_int;

pub(crate) static mut DEBUG_FD: Option<c_int> = None;

pub(crate) fn set_debug_fd(fd: c_int) {
    unsafe {
        DEBUG_FD = Some(fd);
    }
}

pub(crate) fn errno() -> c_int {
    unsafe { *(libc::__errno_location()) }
}

pub(crate) fn reset_errno() {
    unsafe {
        *(libc::__errno_location()) = 0;
    }
}

macro_rules! log_fatal {
    ($($stuff: expr),+) => {{
        if let Some(debug_fd) = unsafe { crate::error::DEBUG_FD } {
            use core::fmt::Write;
            let line = core::line!() as i32;
            let mut buf = iris_ipc::StackBuffer::<200>::new();
            let _ = write!(&mut buf, "Error in clone() entrypoint at line {}: ", line);
            let s = if let Err(_) = write!(&mut buf, $($stuff),+) {
                "unable to format error message"
            } else {
                core::str::from_utf8(buf.as_bytes()).unwrap_or("unable to format error to UTF-8")
            };
            unsafe {
                libc::write(debug_fd, s.as_ptr() as *const _, s.len());
                libc::write(debug_fd, b"\n".as_ptr() as *const _, 1);
            }
        }
        unsafe { libc::exit(1); }
    }}
}

macro_rules! log_nonfatal {
    ($($stuff: expr),+) => {{
        if let Some(debug_fd) = unsafe { crate::error::DEBUG_FD } {
            use core::fmt::Write;
            let line = core::line!() as i32;
            let mut buf = iris_ipc::StackBuffer::<200>::new();
            let _ = write!(&mut buf, "Warning in clone() entrypoint at line {}: ", line);
            let s = if let Err(_) = write!(&mut buf, $($stuff),+) {
                "unable to format error message"
            } else {
                core::str::from_utf8(buf.as_bytes()).unwrap_or("unable to format error to UTF-8")
            };
            unsafe {
                libc::write(debug_fd, s.as_ptr() as *const _, s.len());
                libc::write(debug_fd, b"\n".as_ptr() as *const _, 1);
            }
        }
    }}
}
