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
        let line = core::line!() as i32;
        let mut buf = crate::error::StackBuffer::new();
        let _ = write!(&mut buf, "Error in clone() entrypoint at line {}: ", line);
        let s = if let Err(_) = write!(&mut buf, $($stuff),+) {
            "unable to format error message"
        } else {
            core::str::from_utf8(&buf.buf[0..buf.used_bytes]).unwrap_or("unable to format error to UTF-8")
        };
        libc::write(libc::STDERR_FILENO, s.as_ptr() as *const _, s.len());
        libc::exit(1);
    }}
}

macro_rules! log_nonfatal {
    ($debug_fd: expr, $($stuff: expr),+) => {{
        if let Some(debug_fd) = $debug_fd {
            let line = core::line!() as i32;
            let mut buf = crate::error::StackBuffer::new();
            let _ = write!(&mut buf, "Warning in clone() entrypoint at line {}: ", line);
            let s = if let Err(_) = write!(&mut buf, $($stuff),+) {
                "unable to format error message"
            } else {
                core::str::from_utf8(&buf.buf[0..buf.used_bytes]).unwrap_or("unable to format error to UTF-8")
            };
            libc::write(debug_fd, s.as_ptr() as *const _, s.len());
        }
    }}
}
