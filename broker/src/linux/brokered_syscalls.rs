use iris_ipc::{IPCRequest, IPCResponse};
use iris_policy::{CrossPlatformHandle, Handle, Policy, PolicyRequest, PolicyVerdict};
use libc::c_int;
use log::warn;
use std::convert::TryInto;
use std::ffi::CString;

pub(crate) fn handle_os_specific_request(
    request: IPCRequest,
    policy: &Policy,
) -> (IPCResponse, Option<Handle>) {
    match request {
        IPCRequest::OpenFile {
            path,
            flags,
        } => handle_open_file(policy, path, flags),
        unknown => {
            warn!("Unexpected request from worker: {:?}", unknown);
            (IPCResponse::GenericCode(-(libc::EINVAL as i64)), None)
        }
    }
}

pub(crate) fn handle_open_file(
    policy: &Policy,
    path: String,
    flags: c_int,
) -> (IPCResponse, Option<Handle>) {
    let req = PolicyRequest::LinuxFileOpen {
        path: &path,
        flags,
    };
    if policy.evaluate_request(&req) != PolicyVerdict::Granted {
        return (IPCResponse::GenericCode((-libc::EACCES).into()), None);
    }
    let mode = libc::S_IRUSR | libc::S_IWUSR;
    let path = CString::new(path).unwrap();
    let handle = unsafe {
        let res = libc::open(path.as_ptr(), flags, mode);
        let fd: u64 = match res.try_into() {
            Ok(n) => n,
            _ => {
                // Returning here is safe and won't leak any file descriptor, open() did not
                // open one if it returned a negative error code
                let err = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EACCES) as i64;
                return (IPCResponse::GenericCode(-err), None);
            },
        };
        Handle::new(fd).unwrap()
    };
    (IPCResponse::GenericCode(0), Some(handle))
}
