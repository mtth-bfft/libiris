use crate::error::HandleError;
use crate::handle::CrossPlatformHandle;
use core::ptr::null_mut;
use log::error;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle};
use std::os::windows::prelude::RawHandle;
use winapi::shared::minwindef::DWORD;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{
    CloseHandle, DuplicateHandle, GetHandleInformation, SetHandleInformation,
};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winbase::HANDLE_FLAG_INHERIT;
use winapi::um::winnt::{DUPLICATE_SAME_ACCESS, HANDLE};

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct Handle {
    val: Option<u64>,
}

impl CrossPlatformHandle for Handle {
    unsafe fn new(raw_handle: u64) -> Result<Self, HandleError> {
        Ok(Handle {
            val: Some(raw_handle),
        })
    }

    fn set_inheritable(&mut self, allow_inherit: bool) -> Result<(), HandleError> {
        let res = unsafe {
            SetHandleInformation(
                self.as_raw() as *mut _,
                HANDLE_FLAG_INHERIT,
                if allow_inherit {
                    HANDLE_FLAG_INHERIT
                } else {
                    0
                },
            )
        };
        if res == 0 {
            return Err(HandleError::InternalOsOperationFailed {
                description: "SetHandleInformation() failed",
                raw_handle: self.as_raw(),
                os_code: unsafe { GetLastError() }.into(),
            });
        }
        Ok(())
    }

    fn is_inheritable(&self) -> Result<bool, HandleError> {
        let mut flags: DWORD = 0;
        let res = unsafe { GetHandleInformation(self.as_raw() as *mut _, &mut flags as *mut _) };
        if res == 0 {
            return Err(HandleError::InternalOsOperationFailed {
                description: "GetHandleInformation() failed",
                raw_handle: self.as_raw(),
                os_code: unsafe { GetLastError() }.into(),
            });
        }
        Ok((flags & HANDLE_FLAG_INHERIT) != 0)
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
        if let Some(handle) = self.val {
            let res = unsafe { CloseHandle(handle as *mut _) };
            if res < 0 {
                let msg = format!(
                    "CloseHandle(handle={:?}) failed with error {}",
                    handle,
                    unsafe { GetLastError() }
                );
                if cfg!(debug_assertions) {
                    panic!("{}", msg);
                } else {
                    error!("{}", msg);
                }
            }
        }
    }
}

impl FromRawHandle for Handle {
    unsafe fn from_raw_handle(handle: RawHandle) -> Self {
        Handle::new(handle as u64).unwrap()
    }
}

impl IntoRawHandle for Handle {
    fn into_raw_handle(self) -> RawHandle {
        self.as_raw() as *mut _
    }
}

pub fn downcast_to_handle<T: IntoRawHandle>(resource: T) -> Handle {
    unsafe { Handle::from_raw_handle(resource.into_raw_handle()) }
}

pub fn set_unmanaged_handle_inheritable<T: AsRawHandle>(
    resource: &T,
    allow_inherit: bool,
) -> Result<(), HandleError> {
    // This block is safe because the file descriptor held by `resource` lives at least
    // for the duration of the block, and we don't take ownership of it
    unsafe {
        let mut handle = Handle::new(resource.as_raw_handle() as u64)?; // returning here is safe since the handle was not created thus won't be drop()ped
        let res = handle.set_inheritable(allow_inherit);
        let _ = handle.into_raw(); // leak voluntarily
        res
    }
}

impl Clone for Handle {
    fn clone(&self) -> Self {
        let cur_raw = self.as_raw();
        unsafe {
            let mut new_raw: HANDLE = null_mut();
            let res = DuplicateHandle(
                GetCurrentProcess(),
                cur_raw as *mut _,
                GetCurrentProcess(),
                &mut new_raw as *mut _,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            );
            if res < 0 {
                panic!(
                    "DuplicateHandle() failed on {}: error {}",
                    cur_raw,
                    GetLastError()
                );
            }
            Self::new(res.try_into().unwrap()).unwrap()
        }
    }
}
