use crate::error::set_debug_fd;
use core::ffi::{c_void, CStr};
use libc::c_int;

// Hostname set in the sandbox when UTS namespaces can be used.
const UTS_HOSTNAME: &[u8; 7] = b"sandbox";

pub struct EntrypointParameters {
    pub debug_fd: Option<c_int>,
    pub uid_map: *const i8,
    pub uid_map_len: usize,
    pub gid_map: *const i8,
    pub gid_map_len: usize,
    pub exe: *const i8,
    pub argv: *const *const i8,
    pub envp: *const *const i8,
    pub allowed_file_descriptors: *const c_int,
    pub allowed_file_descriptors_count: usize,
    pub execve_errno_pipe: c_int,
    pub stdin: Option<c_int>,
    pub stdout: Option<c_int>,
    pub stderr: Option<c_int>,
}

// You should be extra-careful when editing this function: it is executed as
// the entry point of clone(), which means it cannot use any of libc's functions
// which may use locks (e.g. memory allocators)
pub extern "C" fn clone_entrypoint(args: *mut c_void) -> c_int {
    let args = unsafe { &*(args as *const EntrypointParameters) };
    if let Some(fd) = args.debug_fd {
        set_debug_fd(fd);
    }

    unsafe {
        libc::umask(0o600);
    }

    let res = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if res != 0 {
        log_fatal!("prctl(PR_SET_NO_NEW_PRIVS) failed with errno {}\n", errno());
    }

    // Prevent ourselves from calling setgroups(), which could allow us to remove a supplementary
    // group that restricts us from accessing certain files. This is also required to write the
    // gid_map, when using user namespaces.
    let setgroups_path = CStr::from_bytes_with_nul(b"/proc/self/setgroups\0").unwrap();
    let setgroups_fd = unsafe { libc::open(setgroups_path.as_ptr(), libc::O_WRONLY) };
    if setgroups_fd < 0 {
        log_nonfatal!("open(/proc/self/setgroups) failed with errno {}\n", errno());
    } else {
        let res = unsafe { libc::write(setgroups_fd, b"deny".as_ptr() as *const _, 4) };
        if res != 4 {
            log_nonfatal!(
                "write(/proc/self/setgroups, deny) failed with errno {}\n",
                errno()
            );
        }
        unsafe {
            libc::close(setgroups_fd);
        }
    }

    // Write our UID and GID mapping: map the current user to themselves. This just has the
    // benefit of removing UID 0 in our namespace.
    if args.uid_map_len > 0 {
        let mapping_path = CStr::from_bytes_with_nul(b"/proc/self/uid_map\0").unwrap();
        let mapping_fd = unsafe { libc::open(mapping_path.as_ptr(), libc::O_WRONLY) };
        if mapping_fd < 0 {
            log_nonfatal!("open(/proc/self/uid_map) failed with errno {}\n", errno());
        } else {
            let res =
                unsafe { libc::write(mapping_fd, args.uid_map as *const c_void, args.uid_map_len) };
            if res < 0 || (res as usize) != args.uid_map_len {
                log_nonfatal!("write(/proc/self/uid_map) failed with errno {}\n", errno());
            }
            unsafe {
                libc::close(mapping_fd);
            }
        }
    }
    if args.gid_map_len > 0 {
        let mapping_path = CStr::from_bytes_with_nul(b"/proc/self/gid_map\0").unwrap();
        let mapping_fd = unsafe { libc::open(mapping_path.as_ptr(), libc::O_WRONLY) };
        if mapping_fd < 0 {
            log_nonfatal!("open(/proc/self/gid_map) failed with errno {}\n", errno());
        } else {
            let res =
                unsafe { libc::write(mapping_fd, args.gid_map as *const c_void, args.gid_map_len) };
            if res < 0 || (res as usize) != args.gid_map_len {
                log_nonfatal!("write(/proc/self/gid_map) failed with errno {}\n", errno());
            }
            unsafe {
                libc::close(mapping_fd);
            }
        }
    }

    // Isolate ourselves from the broker's IPC namespace
    let ipc_namespace_err = unsafe { libc::unshare(libc::CLONE_NEWIPC) };
    if ipc_namespace_err != 0 {
        log_nonfatal!("unshare(CLONE_NEWIPC) failed with errno {}\n", errno());
    }

    // Isolate ourselves from the broker's network namespace
    let net_namespace_err = unsafe { libc::unshare(libc::CLONE_NEWNET) };
    if net_namespace_err != 0 {
        log_nonfatal!("unshare(CLONE_NEWNET) failed with errno {}\n", errno());
    }

    // Isolate ourselves from the broker's UTS namespace
    let uts_namespace_err = unsafe { libc::unshare(libc::CLONE_NEWUTS) };
    if uts_namespace_err != 0 {
        log_nonfatal!("unshare(CLONE_NEWUTS) failed with errno {}\n", errno());
    } else {
        // Set our hostname to something arbitrary so that it
        // does not leak information about the host we're running on.
        let res =
            unsafe { libc::sethostname(UTS_HOSTNAME.as_ptr() as *const _, UTS_HOSTNAME.len()) };
        if res != 0 {
            log_nonfatal!(
                "sethostname({:?}) failed with errno {}\n",
                UTS_HOSTNAME,
                errno()
            );
        }
    }

    // Isolate ourselves from the broker's cgroup namespace
    let cgroup_namespace_err = unsafe { libc::unshare(libc::CLONE_NEWCGROUP) };
    if cgroup_namespace_err != 0 {
        log_nonfatal!("unshare(CLONE_NEWCGROUP) failed with errno {}\n", errno());
    }

    // Create a mount namespace based on the broker's one, but in which
    // we can make modifications
    let mnt_namespace_err = unsafe { libc::unshare(libc::CLONE_NEWNS) };
    if mnt_namespace_err != 0 {
        log_nonfatal!("unshare(CLONE_NEWNS) failed with errno {}\n", errno());
    } else {
        let res = unsafe {
            libc::mount(
                b"none\0".as_ptr() as *const i8,
                b"/proc/\0".as_ptr() as *const i8,
                b"proc\0".as_ptr() as *const i8,
                0,
                b"\0".as_ptr() as *const c_void,
            )
        };
        if res != 0 {
            log_nonfatal!("mount(/proc) failed with errno {}\n", errno());
        }
    }

    // Cleanup leftover file descriptors from our parent or from code injected into our process
    let fds_path = unsafe { CStr::from_ptr(b"/proc/self/fd/\0".as_ptr() as *const _) };
    let fds_fd = unsafe {
        libc::open(
            fds_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fds_fd < 0 {
        log_fatal!("open(/proc/self/fd/) failed with errno {}\n", errno());
    }
    let fds_dir = unsafe { libc::fdopendir(fds_fd) };
    if fds_dir.is_null() {
        log_fatal!("fdopendir(/proc/self/fd/) failed with errno {}\n", errno());
    }
    loop {
        reset_errno();
        let entry = unsafe { libc::readdir(fds_dir) };
        if entry.is_null() {
            if errno() != 0 {
                log_fatal!("readdir(/proc/self/fd/) failed with errno {}\n", errno());
            }
            break;
        }
        if unsafe { (*entry).d_type } != libc::DT_LNK {
            continue;
        }
        let num_str = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let num_str = match num_str.to_str() {
            Ok(s) => s,
            Err(_) => log_fatal!("unable to parse /proc/self/fd entry as string\n"),
        };
        let fd: libc::c_int = match num_str.parse::<i32>() {
            Ok(n) => n,
            Err(_) => log_fatal!(
                "unable to parse /proc/self/fd/{} entry as integer\n",
                num_str
            ),
        };
        // Exclude the file descriptor from the read_dir itself (if we close it, we might
        // break the /proc/self/fd/ enumeration)
        let mut allow = false;
        for i in 0..args.allowed_file_descriptors_count {
            let allowed_fd = unsafe { *(args.allowed_file_descriptors.add(i)) };
            // Also don't close the CLOEXEC pipe used to check if execve() worked
            // (which would defeat its purpose), and the file descriptor used to
            // enumerate file descriptors (otherwise the next iteration would fail)
            if fd <= libc::STDERR_FILENO
                || fd == allowed_fd
                || fd == fds_fd
                || fd == args.execve_errno_pipe
            {
                allow = true;
                break;
            }
        }
        if !allow {
            let res = unsafe { libc::close(fd) };
            if res != 0 {
                log_fatal!(
                    "closing inherited file descriptor {} failed with errno {}\n",
                    fd,
                    errno()
                );
            }
        }
    }
    unsafe {
        libc::close(fds_fd);
    }

    // Close stdin and replace it with the user-provided file descriptor, or /dev/null
    // (so that any read(stdin) deterministically returns EOF)
    setup_std_file_descriptor(libc::STDIN_FILENO, args.stdin);

    // Close stdout and replace it with the user-provided file descriptor, or /dev/null
    // (so that any write(stdout) deterministically is ignored)
    setup_std_file_descriptor(libc::STDOUT_FILENO, args.stdout);

    // Close stderr just like stdout, do it last so that we can log errors for as long as possible
    setup_std_file_descriptor(libc::STDERR_FILENO, args.stderr);

    unsafe {
        libc::execve(args.exe, args.argv, args.envp);

        let errno = errno();
        let errno_bytes = (errno as u32).to_be_bytes();
        libc::write(
            args.execve_errno_pipe,
            errno_bytes.as_ptr() as *const _,
            core::mem::size_of_val(&errno_bytes),
        );
        libc::exit(errno);
    }
}

fn errno() -> c_int {
    unsafe { *(libc::__errno_location()) }
}

fn reset_errno() {
    unsafe {
        *(libc::__errno_location()) = 0;
    }
}

fn setup_std_file_descriptor(num: c_int, replace_with: Option<c_int>) {
    unsafe {
        libc::close(num);
    }
    if let Some(fd) = replace_with {
        let res = unsafe { libc::dup(fd) };
        if res < 0 {
            log_fatal!("dup() failed with errno {}\n", errno());
        } else if res != num {
            log_fatal!(
                "dup() returned file descriptor number {}, expected {}\n",
                res,
                num
            );
        }
    } else {
        // Use libc::open instead of stdlib because it would set CLOEXEC to avoid leaking
        // (which defeats the purpose)
        let dev_null_path = unsafe { CStr::from_ptr(b"/dev/null\0".as_ptr() as *const _) };
        let res = unsafe { libc::open(dev_null_path.as_ptr(), libc::O_RDONLY) };
        if res < 0 {
            log_fatal!("open(/dev/null) failed with errno {}\n", errno());
        } else if res != num {
            log_fatal!(
                "open(/dev/null) returned file descriptor number {}, expected {}\n",
                res,
                num
            );
        }
    }
}
