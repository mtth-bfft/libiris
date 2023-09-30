use crate::os::messages::{IPCRequest, IPCResponse};
use iris_ipc::{CrossPlatformHandle, Handle};
use iris_policy::{Policy, PolicyRequest, PolicyVerdict};
use libc::c_int;
use log::warn;
use std::convert::TryInto;
use std::ffi::CString;

pub(crate) fn handle_os_specific_request(
    request: IPCRequest,
    policy: &Policy,
) -> (IPCResponse, Option<Handle>) {
    match request {
        IPCRequest::OpenFile { path, flags } => handle_open_file(policy, path, flags),
        IPCRequest::Syscall { nb, args, ip } => handle_syscall(policy, nb, args, ip),
        unknown => {
            warn!("Unexpected request from worker: {:?}", unknown);
            (IPCResponse::SyscallResult(-(libc::EINVAL as i64)), None)
        }
    }
}

pub(crate) fn handle_open_file(
    policy: &Policy,
    path: String,
    flags: c_int,
) -> (IPCResponse, Option<Handle>) {
    let req = PolicyRequest::FileOpen { path: &path, flags };
    if policy.evaluate_request(&req) != PolicyVerdict::Granted {
        return (IPCResponse::SyscallResult((-libc::EACCES).into()), None);
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
                return (IPCResponse::SyscallResult(-err), None);
            }
        };
        Handle::from_raw(fd).unwrap()
    };
    (IPCResponse::SyscallResult(0), Some(handle))
}

pub(crate) fn handle_syscall(
    policy: &Policy,
    nb: i64,
    args: [i64; 6],
    ip: i64,
) -> (IPCResponse, Option<Handle>) {
    let req = PolicyRequest::Syscall { nb, args, ip };
    policy.evaluate_request(&req);
    (IPCResponse::SyscallResult(-(libc::ENOSYS as i64)), None)
}
