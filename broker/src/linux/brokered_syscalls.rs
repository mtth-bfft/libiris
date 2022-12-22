use iris_ipc::{IPCRequest, IPCResponse};
use iris_policy::{CrossPlatformHandle, Handle, Policy};
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
            read,
            write,
            append_only,
        } => handle_open_file(policy, path, read, write, append_only),
        unknown => {
            warn!("Unexpected request from worker: {:?}", unknown);
            (IPCResponse::GenericCode(-(libc::EINVAL as i64)), None)
        }
    }
}

pub(crate) fn handle_open_file(
    policy: &Policy,
    path: String,
    requests_read: bool,
    requests_write: bool,
    requests_append_only: bool,
) -> (IPCResponse, Option<Handle>) {
    // Ensure the path is an absolute path
    if path.is_empty() || !path.starts_with('/') || (requests_append_only && !requests_write) {
        return (IPCResponse::GenericCode(-(libc::EINVAL as i64)), None);
    }
    // Ensure the path is already resolved
    if path.contains("/../") || path.contains("/./") {
        return (IPCResponse::GenericCode(-(libc::EINVAL as i64)), None);
    }
    // Ensure the path does not contain a NULL byte
    let path_nul = match CString::new(path.clone()) {
        Ok(s) => s,
        Err(_) => return (IPCResponse::GenericCode(-(libc::EINVAL as i64)), None),
    };
    // Ensure the access requested matches the worker's policy
    let (can_read, can_write, can_only_append) = policy.get_file_allowed_access(&path);
    if !(requests_read || requests_write)
        || (requests_read && !can_read)
        || (requests_write && (!can_write || (!requests_append_only && can_only_append)))
    {
        warn!(
            "Worker denied{}{}{} access to {} ({})",
            if requests_read && !can_read {
                " read"
            } else {
                ""
            },
            if requests_write && !requests_append_only && (!can_write || can_only_append) {
                " write"
            } else {
                ""
            },
            if requests_write && requests_append_only && !can_write {
                " append"
            } else {
                ""
            },
            path,
            if can_read || can_write {
                format!(
                    "can only{}{}{}",
                    if can_read { " read" } else { "" },
                    if can_write { " write" } else { "" },
                    if can_only_append {
                        " (append only)"
                    } else {
                        ""
                    }
                )
            } else {
                "has no access to that path".to_owned()
            }
        );
        return (IPCResponse::GenericCode(-(libc::EACCES) as i64), None);
    }
    let mut flags = libc::O_CLOEXEC;
    if requests_read && requests_write {
        flags |= libc::O_RDWR;
    } else if requests_read {
        flags |= libc::O_RDONLY;
    } else {
        flags |= libc::O_WRONLY;
    }
    if requests_write && requests_append_only {
        flags |= libc::O_APPEND;
    }
    let mode = libc::S_IRUSR | libc::S_IWUSR | libc::S_IRGRP | libc::S_IWGRP;
    let handle = unsafe {
        let res = libc::open(path_nul.as_ptr(), flags, mode);
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
