use crate::handle::{CrossPlatformHandle, Handle};
use libc::{c_int, fcntl, FD_CLOEXEC, F_GETFD, F_SETFD};
use std::convert::TryInto;
use std::io::Error;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};

impl CrossPlatformHandle for Handle {
    unsafe fn new(raw_handle: u64) -> Result<Self, String> {
        let fd: c_int = match raw_handle.try_into() {
            Ok(n) => n,
            Err(_) => return Err(format!("Invalid file descriptor \"{}\"", raw_handle)),
        };
        Ok(Handle {
            val: Some(fd as u64),
        })
    }

    fn set_inheritable(&mut self, allow_inherit: bool) -> Result<(), String> {
        let fd = self.as_raw().try_into().unwrap();
        let current_flags = unsafe { fcntl(fd, F_GETFD) };
        if current_flags < 0 {
            return Err(format!(
                "fcntl(F_GETFD) failed with error {}",
                Error::last_os_error().raw_os_error().unwrap_or(0)
            ));
        }
        let res = unsafe {
            fcntl(
                fd,
                F_SETFD,
                (current_flags & !FD_CLOEXEC) | if allow_inherit { 0 } else { FD_CLOEXEC },
            )
        };
        if res < 0 {
            return Err(format!(
                "fcntl(F_SETFD, FD_CLOEXEC) failed with error {}",
                Error::last_os_error().raw_os_error().unwrap_or(0)
            ));
        }
        Ok(())
    }

    fn is_inheritable(&self) -> Result<bool, String> {
        let fd = self.as_raw().try_into().unwrap();
        let current_flags = unsafe { fcntl(fd, F_GETFD) };
        if current_flags < 0 {
            return Err(format!(
                "fcntl(F_GETFD) failed with error {}",
                Error::last_os_error().raw_os_error().unwrap_or(0)
            ));
        }
        Ok((current_flags & FD_CLOEXEC) == 0)
    }

    fn as_raw(&self) -> u64 {
        self.val.unwrap()
    }

    unsafe fn into_raw(mut self) -> u64
    where
        Self: Sized,
    {
        self.val.take().unwrap()
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if let Some(fd) = self.val {
            let res = unsafe { libc::close(fd.try_into().unwrap()) };
            if res < 0 {
                panic!(
                    "close(fd={}) failed with error {}",
                    fd,
                    Error::last_os_error().raw_os_error().unwrap_or(0)
                );
            }
        }
    }
}

impl FromRawFd for Handle {
    unsafe fn from_raw_fd(fd: i32) -> Self {
        Handle::new(fd.try_into().unwrap()).unwrap()
    }
}

impl IntoRawFd for Handle {
    fn into_raw_fd(self) -> i32 {
        self.as_raw().try_into().unwrap()
    }
}

pub fn downcast_to_handle<T: IntoRawFd>(resource: T) -> Handle {
    unsafe { Handle::from_raw_fd(resource.into_raw_fd()) }
}

pub fn set_unmanaged_handle_inheritable<T: AsRawFd>(
    resource: &T,
    allow_inherit: bool,
) -> Result<(), String> {
    // This block is safe because the file descriptor held by `resource` lives at least
    // for the duration of the block, and we don't take ownership of it
    let fd = resource.as_raw_fd().try_into().unwrap();
    unsafe {
        let mut handle = Handle::new(fd).unwrap();
        let res = handle.set_inheritable(allow_inherit);
        let _ = handle.into_raw(); // leak voluntarily
        res
    }
}

impl Clone for Handle {
    fn clone(&self) -> Self {
        let fd: i32 = self.as_raw().try_into().unwrap();
        unsafe {
            let res = libc::dup(fd);
            if res < 0 {
                panic!(
                    "dup() failed on file descriptor {}: error {}",
                    fd,
                    Error::last_os_error().raw_os_error().unwrap_or(0)
                );
            }
            Self::new(res.try_into().unwrap()).unwrap()
        }
    }
}
