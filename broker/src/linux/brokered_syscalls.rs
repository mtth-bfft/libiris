use iris_ipc::{CrossPlatformHandle, os::Handle};
use iris_ipc_messages::os::IPCResponse;
use iris_policy::{Policy, PolicyVerdict, os::PolicyRequest};
use libc::c_int;
use std::convert::TryInto;
use std::ffi::CString;

pub(crate) fn proxied_open_file<'a>(
    policy: &Policy,
    path: &str,
    flags: c_int,
) -> (IPCResponse<'a>, Option<Handle>) {
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

pub(crate) fn proxied_syscall<'a>(
    policy: &Policy,
    nb: i64,
    args: [i64; 6],
    ip: i64,
) -> (IPCResponse<'a>, Option<Handle>) {
    let req = PolicyRequest::Syscall { nb, args, ip };
    policy.evaluate_request(&req);
    (IPCResponse::SyscallResult(-(libc::ENOSYS as i64)), None)
}
