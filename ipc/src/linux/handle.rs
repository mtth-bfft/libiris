use crate::error::HandleError;
use crate::handle::CrossPlatformHandle;
use crate::os::errno;
use core::convert::TryInto;
use libc::{c_int, fcntl, FD_CLOEXEC, F_GETFD, F_SETFD};
use log::error;

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct Handle {
    pub(crate) val: Option<c_int>,
}

impl CrossPlatformHandle for Handle {
    unsafe fn from_raw(raw_handle: u64) -> Result<Self, HandleError> {
        let fd: c_int = match raw_handle.try_into() {
            Ok(n) if n >= 0 => n,
            _ => {
                return Err(HandleError::InvalidHandleValue {
                    raw_value: raw_handle,
                })
            }
        };
        Ok(Handle { val: Some(fd) })
    }

    fn set_inheritable(&mut self, allow_inherit: bool) -> Result<(), HandleError> {
        let fd = self.as_raw().try_into().unwrap();
        let current_flags = unsafe { fcntl(fd, F_GETFD) };
        if current_flags < 0 {
            return Err(HandleError::InternalOsOperationFailed {
                description: "fcntl(F_GETFD) failed",
                raw_handle: self.as_raw(),
                os_code: errno() as u64,
            });
        }
        let res = unsafe {
            fcntl(
                fd,
                F_SETFD,
                (current_flags & !FD_CLOEXEC) | if allow_inherit { 0 } else { FD_CLOEXEC },
            )
        };
        if res < 0 {
            return Err(HandleError::InternalOsOperationFailed {
                description: "fcntl(F_SETFD, FD_CLOEXEC) failed",
                raw_handle: self.as_raw(),
                os_code: errno() as u64,
            });
        }
        Ok(())
    }

    fn is_inheritable(&self) -> Result<bool, HandleError> {
        let fd = self.as_raw().try_into().unwrap();
        let current_flags = unsafe { fcntl(fd, F_GETFD) };
        if current_flags < 0 {
            return Err(HandleError::InternalOsOperationFailed {
                description: "fcntl(F_GETFD) failed",
                raw_handle: self.as_raw(),
                os_code: errno() as u64,
            });
        }
        Ok((current_flags & FD_CLOEXEC) == 0)
    }

    fn as_raw(&self) -> u64 {
        self.val.unwrap() as u64
    }

    unsafe fn into_raw(mut self) -> u64
    where
        Self: Sized,
    {
        self.val.take().unwrap() as u64
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if let Some(fd) = self.val {
            let res = unsafe { libc::close(fd) };
            if res < 0 {
                error!("close(fd={}) failed with error {}", fd, errno());
                if cfg!(debug_assertions) {
                    panic!("close(fd={}) failed with error {}", fd, errno());
                }
            }
        }
    }
}

impl Clone for Handle {
    fn clone(&self) -> Self {
        let fd: i32 = self.as_raw().try_into().unwrap();
        unsafe {
            let res = libc::dup(fd);
            if res < 0 {
                // TODO: publish a try_clone() method instead, so we can avoid all panics
                panic!("dup() failed on file descriptor {}: error {}", fd, errno());
            }
            Self::from_raw(res.try_into().unwrap()).unwrap()
        }
    }
}
