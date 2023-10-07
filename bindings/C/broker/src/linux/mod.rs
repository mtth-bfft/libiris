use core::ffi::{c_char, c_int};
use iris_policy::os::PolicyRequest;
use std::ffi::CString;

#[repr(C, u8)]
pub enum IrisPolicyRequest {
    FileOpen {
        path: *const c_char,
        flags: c_int,
    },
    Syscall {
        nb: i64,
        arg0: i64,
        arg1: i64,
        arg2: i64,
        arg3: i64,
        arg4: i64,
        arg5: i64,
        ip: i64,
    },
}

impl From<&PolicyRequest<'_>> for IrisPolicyRequest {
    fn from(rust_enum: &PolicyRequest) -> Self {
        match rust_enum {
            PolicyRequest::FileOpen { path, flags } => Self::FileOpen {
                path: CString::new(*path).unwrap().into_raw(),
                flags: *flags,
            },
            PolicyRequest::Syscall { nb, args, ip } => Self::Syscall {
                nb: *nb,
                arg0: args[0],
                arg1: args[1],
                arg2: args[2],
                arg3: args[3],
                arg4: args[4],
                arg5: args[5],
                ip: *ip,
            },
        }
    }
}

impl Drop for IrisPolicyRequest {
    fn drop(&mut self) {
        match *self {
            Self::FileOpen { path, .. } => {
                drop(unsafe { CString::from_raw(path as *mut i8) });
            }
            Self::Syscall { .. } => (),
        }
    }
}
