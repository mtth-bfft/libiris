use iris_ipc::{IPCRequest, IPCResponse};
use iris_policy::{CrossPlatformHandle, Handle, Policy};
use libc::{c_int, O_RDONLY, O_WRONLY, O_RDWR, O_TRUNC, O_CREAT, O_EXCL, O_DIRECTORY, O_APPEND, O_PATH, O_CLOEXEC};
use log::warn;
use std::convert::TryInto;
use std::ffi::CString;

const SUPPORTED_FILE_OPEN_FLAGS: c_int = O_RDONLY | O_WRONLY | O_RDWR | O_TRUNC | O_CREAT | O_EXCL | O_DIRECTORY | O_APPEND | O_PATH | O_CLOEXEC;

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
    path: CString,
    flags: c_int,
) -> (IPCResponse, Option<Handle>) {
    // Sanitize flags: only accept known ones
    if (flags & !SUPPORTED_FILE_OPEN_FLAGS) != 0 {
        warn!("Worker denied access to {:?} due to unsupported flag {:#X} in sandboxes", path, flags & !SUPPORTED_FILE_OPEN_FLAGS);
    }
    let flags = flags | O_CLOEXEC;
    // Ensure the access requested matches the worker's policy
    let requests_read = (flags & O_WRONLY) == 0 && (flags & O_PATH) == 0;
    let requests_write = ((flags & (O_WRONLY | O_RDWR)) != 0 && (flags & O_PATH) == 0) || ((flags & (O_TRUNC | O_CREAT | O_EXCL | O_APPEND)) != 0);
    let (can_read, can_write, _, _, _) = policy.get_path_allowed_access(&path, false);
    if !(can_read || can_write)
        || (requests_read && !can_read)
        || (requests_write && !can_write)
    {
        warn!(
            "Worker denied{}{} access to {:?} ({})",
            if requests_read && !can_read {
                " read"
            } else {
                ""
            },
            if requests_write && !can_write {
                " write"
            } else {
                ""
            },
            path,
            if can_read || can_write {
                format!(
                    "can only{}{}",
                    if can_read { " read" } else { "" },
                    if can_write { " write" } else { "" },
                )
            } else {
                "has no access to that path".to_owned()
            }
        );
        return (IPCResponse::GenericCode(-(libc::EACCES) as i64), None);
    }
    let mode = libc::S_IRUSR | libc::S_IWUSR | libc::S_IRGRP | libc::S_IWGRP;
    let handle = unsafe {
        let res = libc::open(path.as_ptr(), flags, mode);
        if res < 0 {
            // Returning here is safe and won't leak any file descriptor, open() did not
            // open one if it returned a negative error code
            let err = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EACCES) as i64;
            return (IPCResponse::GenericCode(-err), None);
        }
        Handle::new(res.try_into().unwrap()).unwrap()
    };
    (IPCResponse::GenericCode(0), Some(handle))
}
