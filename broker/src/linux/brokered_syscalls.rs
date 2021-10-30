use std::fs::File;
use std::ops::{Not, BitAnd};
use std::ffi::CString;
use std::sync::Arc;
use std::convert::TryInto;
use iris_policy::{Handle, Policy, CrossPlatformHandle};
use crate::os::process::OSSandboxedProcess;

const MAX_PATH_LEN: usize = 4096;

// Constants from linux/audit.h
const AUDIT_ARCH_X86_64: u32 = 0xC000003E;

pub(crate) fn handle_syscall(arch: u32, nr: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64, process: &Arc<OSSandboxedProcess>) -> (i64, Option<Handle>) {
    // Always make decisions based on architecture AND syscall number
    // Always read all arguments once, and then only make decisions based on them
    if arch == AUDIT_ARCH_X86_64 && nr == libc::SYS_open as u64 {
        let (arg1, arg2, arg3, arg4, arg5, arg6) = (
            process.read_cstring_from_ptr(arg1, MAX_PATH_LEN),
            arg2 as libc::c_int,
            arg3 as libc::mode_t,
            0, 0, 0
        );
        let (path, flags, mode) = match (arg1, arg2, arg3) {
            (Ok(path), flags, mode) => (path, flags, mode),
            _ => return (-libc::EINVAL as i64, None),
        };
        handle_open_file(path, flags, mode, &process.policy)
    }
    else if arch == AUDIT_ARCH_X86_64 && nr == libc::SYS_openat as u64 {
        let (arg1, arg2, arg3, arg4, arg5, arg6) = (
            arg1 as libc::c_int,
            process.read_cstring_from_ptr(arg2, MAX_PATH_LEN),
            arg3 as libc::c_int,
            arg4 as libc::mode_t,
            0, 0
        );
        let (path, flags, mode) = match (arg1, arg2, arg3, arg4) {
            (dirfd, Ok(path), flags, mode) if dirfd == libc::AT_FDCWD => (path, flags, mode),
            _ => return (-libc::EINVAL as i64, None),
        };
        handle_open_file(path, flags, mode, &process.policy)
    }
    else {
        println!(" [!] Unsupported syscall number {} (arch 0x{:X})", nr, arch);
        (-libc::ENOSYS as i64, None)
    }
}

fn consume_flag<T: Copy + PartialEq + Not<Output=T> + BitAnd<Output=T>>(needle: T, bitfield: &mut T) -> bool {
    // Does not check (a & b) != 0 because of multi-bit flags like O_RDWR
    let present = ((*bitfield) & needle) == needle;
    *bitfield = ((*bitfield) & !needle);
    present
}

fn handle_open_file(
    path: CString,
    flags: libc::c_int,
    mode: libc::mode_t,
    policy: &Policy,
) -> (i64, Option<Handle>) {
    // Ensure the path is an absolute path
    let path_utf8 = match path.to_str() {
        Ok(s) => s,
        Err(_) => return (-(libc::ENOSYS as i64), None),
    };
    if path_utf8.is_empty()
        || path_utf8.chars().next() != Some('/')
    {
        return (-(libc::EINVAL as i64), None);
    }
    // FIXME: ensure the path is already resolved (no /..)
    let mut flags_left = flags;
    let mut requests_read = false;
    let mut requests_write = false;
    let mut requests_append_only = false;
    if consume_flag(libc::O_RDWR, &mut flags_left) {
        requests_read = true;
        requests_write = true;
    }
    else if consume_flag(libc::O_WRONLY, &mut flags_left) {
        requests_write = true;
    }
    else {
        requests_read = true; // O_RDONLY == 0 is a pseudo-flag
    }
    if consume_flag(libc::O_CREAT, &mut flags_left) {
        requests_write = true;
    }
    if consume_flag(libc::O_APPEND, &mut flags_left) {
        requests_write = true;
        requests_append_only = true;
    }
    if consume_flag(libc::O_TRUNC, &mut flags_left) { // note: checked after O_APPEND
        requests_write = true;
        requests_append_only = false; // so that O_APPEND|O_TRUNC is NOT append-only
    }
    consume_flag(libc::O_EXCL, &mut flags_left);
    consume_flag(libc::O_CLOEXEC, &mut flags_left);
    // Also ensure we understand each flag that was asked.
    if flags_left != 0 {
        println!(
            " [!] Worker denied access to {} (unsupported flag 0x{:X} in 0x{:X})",
            path_utf8,
            flags,
            flags_left
        );
        return (-(libc::ENOSYS as i64), None);
    }
    // Ensure the access requested matches the worker's policy
    // Also ensure at least one form of access has been requested, so that one cannot ask
    // for e.g. a O_PATH file descriptor, which would leak file existence at any path.
    let (can_read, can_write, can_only_append) = policy.get_file_allowed_access(&path_utf8);
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
            path_utf8,
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
        return (-(libc::EACCES as i64), None);
    }
    let flags = flags | libc::O_CLOEXEC;
    let mode = libc::S_IRUSR | libc::S_IWUSR | libc::S_IRGRP | libc::S_IWGRP;
    let handle = unsafe {
        let res = libc::open(path.as_ptr(), flags, mode);
        if res < 0 {
            // Returning here is safe and won't leak any file descriptor, open() did not
            // open one if it returned a negative error code
            let err = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EACCES) as i64;
            return (-err, None);
        }
        Handle::new(res.try_into().unwrap()).unwrap()
    };
    return (0, Some(handle));
}
