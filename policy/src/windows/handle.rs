use crate::handle::{CrossPlatformHandle, Handle};
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle};
use std::os::windows::prelude::RawHandle;
use winapi::shared::minwindef::DWORD;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, GetHandleInformation, SetHandleInformation};
use winapi::um::winbase::HANDLE_FLAG_INHERIT;

impl CrossPlatformHandle for Handle {
    unsafe fn new(raw_handle: u64) -> Result<Self, String> {
        Ok(Handle {
            val: Some(raw_handle),
        })
    }

    fn set_inheritable(&mut self, allow_inherit: bool) -> Result<(), String> {
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
            return Err(format!(
                "SetHandleInformation() failed with error {}",
                unsafe { GetLastError() }
            ));
        }
        Ok(())
    }

    fn is_inheritable(&self) -> Result<bool, String> {
        let mut flags: DWORD = 0;
        let res = unsafe { GetHandleInformation(self.as_raw() as *mut _, &mut flags as *mut _) };
        if res == 0 {
            return Err(format!(
                "GetHandleInformation() failed with error {}",
                unsafe { GetLastError() }
            ));
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
                panic!(
                    "CloseHandle(handle={}) failed with error {}",
                    handle,
                    unsafe { GetLastError() }
                );
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
) -> Result<(), String> {
    // This block is safe because the file descriptor held by `resource` lives at least
    // for the duration of the block, and we don't take ownership of it
    unsafe {
        let mut handle = Handle::new(resource.as_raw_handle() as u64)?; // returning here is safe since the handle was not created thus won't be drop()ped
        let res = handle.set_inheritable(allow_inherit);
        let _ = handle.into_raw(); // leak voluntarily
        res
    }
}
