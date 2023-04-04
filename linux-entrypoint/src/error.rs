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

// This is a no_std environment: we cannot allocate dynamic memory.
// Any formatted message need to fit into a stack buffer, the rest will
// be truncated.
pub(crate) struct StackBuffer {
    pub(crate) buf: [u8; 500],
    pub(crate) used_bytes: usize,
}

impl StackBuffer {
    pub(crate) fn new() -> Self {
        Self {
            buf: [0u8; 500],
            used_bytes: 0,
        }
    }
}

impl core::fmt::Write for StackBuffer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let capacity = self.buf.len() - 1; // always keep a null byte
        for (i, &b) in self.buf[self.used_bytes..capacity] // truncate the rest, don't panic!()
            .iter_mut()
            .zip(s.as_bytes().iter())
        {
            *i = b;
        }
        self.used_bytes = usize::min(capacity, self.used_bytes + s.as_bytes().len());
        Ok(())
    }
}

macro_rules! log_fatal {
    ($($stuff: expr),+) => {{
        if let Some(debug_fd) = unsafe { crate::error::DEBUG_FD } {
            use core::fmt::Write;
            let line = core::line!() as i32;
            let mut buf = crate::error::StackBuffer::new();
            let _ = write!(&mut buf, "Error in clone() entrypoint at line {}: ", line);
            let s = if let Err(_) = write!(&mut buf, $($stuff),+) {
                "unable to format error message"
            } else {
                core::str::from_utf8(&buf.buf[0..buf.used_bytes]).unwrap_or("unable to format error to UTF-8")
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
            let mut buf = crate::error::StackBuffer::new();
            let _ = write!(&mut buf, "Warning in clone() entrypoint at line {}: ", line);
            let s = if let Err(_) = write!(&mut buf, $($stuff),+) {
                "unable to format error message"
            } else {
                core::str::from_utf8(&buf.buf[0..buf.used_bytes]).unwrap_or("unable to format error to UTF-8")
            };
            unsafe {
                libc::write(debug_fd, s.as_ptr() as *const _, s.len());
                libc::write(debug_fd, b"\n".as_ptr() as *const _, 1);
            }
        }
    }}
}
