use core::ffi::{c_char, c_int};
use iris_policy::PolicyRequest;
use std::ffi::CString;

#[repr(C, u8)]
pub enum IrisPolicyRequest {
    FileOpen { path: *const c_char, flags: c_int },
}

impl From<&PolicyRequest<'_>> for IrisPolicyRequest {
    fn from(rust_enum: &PolicyRequest) -> Self {
        match rust_enum {
            PolicyRequest::FileOpen { path, flags } => Self::FileOpen {
                path: CString::new(*path).unwrap().into_raw(),
                flags: *flags,
            },
        }
    }
}

impl Drop for IrisPolicyRequest {
    fn drop(&mut self) {
        match *self {
            IrisPolicyRequest::FileOpen { path, .. } => {
                drop(unsafe { CString::from_raw(path as *mut i8) })
            }
        }
    }
}
