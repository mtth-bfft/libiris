use std::fs::File;
use std::ffi::CString;
use iris_policy::{Handle, Policy};

pub(crate) fn handle_syscall(arch: u32, nr: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64, policy: &Policy, proc_mem: &File) -> (i64, Option<Handle>) {
    (-libc::ENOSYS as i64, None)
}

/*

fn read_cstring_from_ptr(ptr: u64, proc_mem: &File) -> Result<CString, String> {
    let mut bytes = vec![0u8; 4096];
    match proc_mem.read_at(&mut bytes, bytes.len()) {
        Ok(n) => bytes.truncate(n),
        Err(e) => return Err(format!("Unable to read from worker memory at address {} : {}", ptr, e)),
    };
    let res = match CString::new(bytes) {
        Ok(s) => s,
        Err(e) => return Err(format!("Unable to read worker memory at address {} as string: {}", ptr, e)),
    };
    Ok(res)
}

    if nr == libc::SYS_openat as u64 {
        let path = read_cstring_from_ptr(arg2, proc_mem).unwrap();
        println!(" [+] openat({}, {})", arg1, path);
        return (-libc::ENOSYS as i64, None);
    }

pub(crate) fn handle_open_file(
    policy: &Policy,
    path: String,
    requests_read: bool,
    requests_write: bool,
    requests_append_only: bool,
) -> (IPCResponseV1, Option<Handle>) {
    // Ensure the path is an absolute path
    if path.is_empty()
        || path.chars().next() != Some('/')
        || (requests_append_only && !requests_write)
    {
        return (IPCResponseV1::GenericCode(-(libc::EINVAL as i64)), None);
    }
    // Ensure the path is already resolved
    if path.contains("/../") || path.contains("/./") {
        return (IPCResponseV1::GenericCode(-(libc::EINVAL as i64)), None);
    }
    // Ensure the path does not contain a NULL byte
    let path_nul = match CString::new(path.clone()) {
        Ok(s) => s,
        Err(_) => return (IPCResponseV1::GenericCode(-(libc::EINVAL as i64)), None),
    };
    // Ensure the access requested matches the worker's policy
    let (can_read, can_write, can_only_append) = policy.get_file_allowed_access(&path);
    if !(requests_read || requests_write)
        || (requests_read && !can_read)
        || (requests_write && (!can_write || (!requests_append_only && can_only_append)))
    {
        println!(
            " [!] Worker denied{}{}{} access to {} ({})",
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
        return (IPCResponseV1::GenericCode(-(libc::EACCES) as i64), None);
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
            return (IPCResponseV1::GenericCode(-err), None);
        }
        Handle::new(res.try_into().unwrap()).unwrap()
    };
    return (IPCResponseV1::GenericCode(0), Some(handle));
}*/
