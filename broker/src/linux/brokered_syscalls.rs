use crate::os::process::OSSandboxedProcess;
use crate::process::CrossPlatformSandboxedProcess;
use iris_policy::{CrossPlatformHandle, Handle};
use std::convert::TryInto;
use std::ffi::CString;
use std::ops::{BitAnd, Not};
use std::sync::Arc;

const MAX_PATH_LEN: usize = 4096;

// Constants from linux/audit.h
const AUDIT_ARCH_X86_64: u32 = 0xC000003E;

pub(crate) fn handle_syscall(
    arch: u32,
    nr: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
    process: &Arc<OSSandboxedProcess>,
    ip: u64,
) -> (i64, Option<Handle>) {
    // Always make decisions based on architecture AND syscall number
    // Always read all arguments once, and then only make decisions based on them
    if arch == AUDIT_ARCH_X86_64 && nr == libc::SYS_open as u64 {
        let (arg1, arg2, arg3) = (
            process.read_cstring_from_ptr(arg1, MAX_PATH_LEN),
            arg2 as libc::c_int,
            arg3 as libc::mode_t,
        );
        let (path, flags, mode) = match (arg1, arg2, arg3) {
            (Ok(path), flags, mode) => (path, flags, mode),
            _ => return (-libc::EINVAL as i64, None),
        };
        handle_open_file(path, flags, mode, &process, ip)
    } else if arch == AUDIT_ARCH_X86_64 && nr == libc::SYS_openat as u64 {
        let (arg1, arg2, arg3, arg4) = (
            arg1 as libc::c_int,
            process.read_cstring_from_ptr(arg2, MAX_PATH_LEN),
            arg3 as libc::c_int,
            arg4 as libc::mode_t,
        );
        let (path, flags, mode) = match (arg1, arg2, arg3, arg4) {
            (dirfd, Ok(path), flags, mode) if dirfd == libc::AT_FDCWD => (path, flags, mode),
            _ => return (-libc::EINVAL as i64, None),
        };
        handle_open_file(path, flags, mode, &process, ip)
    } else {
        println!(" [!] Unsupported syscall number {} (args: 0x{:X} 0x{:X} 0x{:X} 0x{:X} 0x{:X} 0x{:X}) (arch 0x{:X}) at {}",
            nr, arg1, arg2, arg3, arg4, arg5, arg6, arch, try_resolve_addr(ip, &process));
        (-libc::ENOSYS as i64, None)
    }
}

fn consume_flag<T: Copy + PartialEq + Not<Output = T> + BitAnd<Output = T>>(
    needle: T,
    bitfield: &mut T,
) -> bool {
    // Does not check (a & b) != 0 because of multi-bit flags like O_RDWR
    let present = ((*bitfield) & needle) == needle;
    *bitfield = (*bitfield) & !needle;
    present
}

/**
 * Makes a best effort to return a string describing in which module an address
 * is located, in the worker process address space.
 */
fn try_resolve_addr(addr: u64, process: &Arc<OSSandboxedProcess>) -> String {
    let file_path = format!("/proc/{}/maps", process.get_pid());
    let mappings = match std::fs::read_to_string(&file_path) {
        Ok(s) => s,
        Err(e) => return format!("0x{:X} (unable to open {}, {})", addr, file_path, e),
    };
    for mapping in mappings.lines() {
        if let Some((boundaries, rest)) = mapping.split_once(" ") {
            if let Some((start, end)) = boundaries.split_once("-") {
                if let (Ok(start), Ok(end)) =
                    (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
                {
                    if start <= addr && addr <= end {
                        if let Some((fields, module)) = rest.split_once("  ") {
                            let module = module.trim();
                            let fields: Vec<&str> = fields.splitn(3, " ").collect();
                            if module.len() == 0 || fields.len() != 3 {
                                return format!("0x{:X} (anonymous memory)", addr);
                            }
                            if let Ok(offset) = u64::from_str_radix(fields[1], 16) {
                                return format!(
                                    "0x{:X} ({}+0x{:X})",
                                    addr,
                                    module,
                                    offset + (addr - start)
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    format!("0x{:X} (address not found in {})", addr, file_path)
}

fn handle_open_file(
    path: CString,
    flags: libc::c_int,
    _mode: libc::mode_t,
    process: &Arc<OSSandboxedProcess>,
    ip: u64,
) -> (i64, Option<Handle>) {
    // Ensure the path is an absolute path
    let path_utf8 = match path.to_str() {
        Ok(s) => s,
        Err(_) => return (-(libc::ENOSYS as i64), None),
    };
    if path_utf8.is_empty() || path_utf8.chars().next() != Some('/') {
        return (-(libc::EINVAL as i64), None);
    }
    println!(" [.] Requested open({})", path_utf8);
    // FIXME: ensure the path is already resolved (no /..)
    // Clear O_PATH to alias this type of requests to O_RDONLY ones
    // since O_PATH allows fstatat()
    let flags = flags & !libc::O_PATH;
    let mut flags_left = flags;
    let mut requests_read = false;
    let mut requests_write = false;
    let mut requests_append_only = false;
    if consume_flag(libc::O_RDWR, &mut flags_left) {
        requests_read = true;
        requests_write = true;
    } else if consume_flag(libc::O_WRONLY, &mut flags_left) {
        requests_write = true;
    } else {
        requests_read = true; // O_RDONLY == 0 is a pseudo-flag
    }
    if consume_flag(libc::O_PATH, &mut flags_left) {
        requests_read = true; // O_PATH file descriptors can be used in fstat, fstatfs, fchdir
    }
    if consume_flag(libc::O_CREAT, &mut flags_left) {
        requests_write = true;
    }
    if consume_flag(libc::O_APPEND, &mut flags_left) {
        requests_write = true;
        requests_append_only = true;
    }
    if consume_flag(libc::O_TRUNC, &mut flags_left) {
        // note: checked after O_APPEND
        requests_write = true;
        requests_append_only = false; // so that O_APPEND|O_TRUNC is NOT append-only
    }
    consume_flag(libc::O_EXCL, &mut flags_left);
    consume_flag(libc::O_NONBLOCK, &mut flags_left);
    consume_flag(libc::O_DIRECTORY, &mut flags_left);
    consume_flag(libc::O_CLOEXEC, &mut flags_left);
    // Also ensure we understand each flag that was asked.
    if flags_left != 0 {
        println!(
            " [!] Worker denied access to {} (unsupported flag 0x{:X} in 0x{:X}) at {}",
            path_utf8,
            flags_left,
            flags,
            try_resolve_addr(ip, process),
        );
        return (-(libc::ENOSYS as i64), None);
    }
    // Ensure the access requested matches the worker's policy
    let (can_read, can_write, can_only_append) = process.policy.get_file_allowed_access(&path_utf8);
    if (requests_read && !can_read)
        || (requests_write && (!can_write || (!requests_append_only && can_only_append)))
    {
        println!(
            " [!] Worker denied{}{}{} access to {} ({}) at {}",
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
            },
            try_resolve_addr(ip, process)
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
