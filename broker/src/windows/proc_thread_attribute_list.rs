use core::ffi::c_void;
use core::ptr::null_mut;
use winapi::shared::basetsd::{DWORD_PTR, SIZE_T};
use winapi::shared::minwindef::DWORD;
use winapi::shared::winerror::ERROR_INSUFFICIENT_BUFFER;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::processthreadsapi::{
    DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
};

pub(crate) struct ProcThreadAttributeList {
    buffer: Vec<u8>,
}

impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.buffer.as_mut_ptr() as *mut _);
        }
    }
}

impl ProcThreadAttributeList {
    pub(crate) fn new(max_attr_count: DWORD) -> Result<Self, String> {
        let mut required_bytes: SIZE_T = 0;
        let res = unsafe {
            InitializeProcThreadAttributeList(
                null_mut(),
                max_attr_count,
                0,
                &mut required_bytes as *mut _,
            )
        };
        if res != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            return Err(format!(
                "InitializeProcThreadAttributeList() failed with error {}",
                unsafe { GetLastError() }
            ));
        }
        let mut buffer = vec![0u8; required_bytes];
        let res = unsafe {
            InitializeProcThreadAttributeList(
                buffer.as_mut_ptr() as *mut _,
                max_attr_count,
                0,
                &mut required_bytes as *mut _,
            )
        };
        if res == 0 {
            return Err(format!(
                "InitializeProcThreadAttributeList() failed with error {}",
                unsafe { GetLastError() }
            ));
        }
        Ok(Self { buffer })
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.buffer.as_mut_ptr()
    }

    pub(crate) fn as_ptr(&self) -> *const u8 {
        self.buffer.as_ptr()
    }

    pub(crate) fn set(
        &mut self,
        attr: DWORD_PTR,
        new_val: *const c_void,
        new_val_size: SIZE_T,
    ) -> Result<(), String> {
        let res = unsafe {
            UpdateProcThreadAttribute(
                self.as_mut_ptr() as *mut _,
                0,
                attr,
                new_val as *mut _,
                new_val_size,
                null_mut(),
                null_mut(),
            )
        };
        if res == 0 {
            return Err(format!(
                "UpdateProcThreadAttribute({}) failed with error {}",
                attr,
                unsafe { GetLastError() }
            ));
        }
        Ok(())
    }
}
