use core::ffi::{CStr, c_void};
use core::fmt::Write;
use libc::c_int;

pub struct EntrypointParameters {
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
// the entry point of clone(), which means it cannot use any of libc/stdlib
// which may use locks (e.g. memory allocators)
pub extern "C" fn clone_entrypoint(args: *mut c_void) -> c_int {
    unsafe {
        let args = &*(args as *const EntrypointParameters);

        libc::umask(0600);

        // Cleanup leftover file descriptors from our parent or from code injected into our process
        let fds_path = CStr::from_ptr(b"/proc/self/fd/\0".as_ptr() as *const _);
        let fds_fd = libc::open(fds_path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC);
        if fds_fd < 0 {
            log_fatal!("open(/proc/self/fd/) failed with errno {}\n", errno());
        }
        let fds_dir = libc::fdopendir(fds_fd);
        if fds_dir.is_null() {
            log_fatal!("fdopendir(/proc/self/fd/) failed with errno {}\n", errno());
        }
        loop {
            reset_errno();
            let entry = libc::readdir(fds_dir);
            if entry.is_null() {
                if errno() != 0 {
                    log_fatal!("readdir(/proc/self/fd/) failed with errno {}\n", errno());
                }
                break;
            }
            if (*entry).d_type != libc::DT_LNK {
                continue;
            }
            let num_str = CStr::from_ptr((*entry).d_name.as_ptr());
            let num_str = match num_str.to_str() {
                Ok(s) => s,
                Err(_) => log_fatal!("unable to parse /proc/self/fd entry as string\n"),
            };
            let fd: libc::c_int = match num_str.parse::<i32>() {
                Ok(n) => n,
                Err(_) => log_fatal!("unable to parse /proc/self/fd/{} entry as integer\n", num_str),
            };
            // Exclude the file descriptor from the read_dir itself (if we close it, we might
            // break the /proc/self/fd/ enumeration)
            let mut allow = false;
            for i in 0..args.allowed_file_descriptors_count {
                let allowed_fd = *(args.allowed_file_descriptors.add(i));
                // Also don't close the CLOEXEC pipe used to check if execve() worked
                // (which would defeat its purpose), and the file descriptor used to
                // enumerate file descriptors (otherwise the next iteration would fail)
                if fd <= libc::STDERR_FILENO ||
                        fd == allowed_fd ||
                        fd == fds_fd ||
                        fd == args.execve_errno_pipe {
                    allow = true;
                    break;
                }
            }
            if !allow {
                let res = libc::close(fd);
                if res != 0 {
                    log_fatal!("closing inherited file descriptor {} failed with errno {}\n", fd, errno());
                }
            }
        }
        libc::close(fds_fd);
        
        // Close stdin and replace it with the user-provided file descriptor, or /dev/null
        // (so that any read(stdin) deterministically returns EOF)
        setup_std_file_descriptor(libc::STDIN_FILENO, args.stdin);

        // Close stdout and replace it with the user-provided file descriptor, or /dev/null
        // (so that any write(stdout) deterministically is ignored)
        setup_std_file_descriptor(libc::STDOUT_FILENO, args.stdout);

        // Close stderr just like stdout, do it last so that we can log errors for as long as possible
        setup_std_file_descriptor(libc::STDERR_FILENO, args.stderr);

        libc::execve(args.exe, args.argv, args.envp);

        let errno = errno();
        let errno_bytes = (errno as u32).to_be_bytes();
        libc::write(args.execve_errno_pipe, errno_bytes.as_ptr() as *const _, core::mem::size_of_val(&errno_bytes));
        libc::exit(errno);
    }
}

unsafe fn errno() -> c_int {
    *(libc::__errno_location())
}

unsafe fn reset_errno() {
    *(libc::__errno_location()) = 0;
}

unsafe fn setup_std_file_descriptor(num: c_int, replace_with: Option<c_int>) {
    libc::close(num);
    if let Some(fd) = replace_with {
        let res = libc::dup(fd);
        if res < 0 {
            log_fatal!("dup() failed with errno {}\n", errno());
        }
        else if res != num {
            log_fatal!("dup() returned file descriptor number {}, expected {}\n", res, num);
        }
    } else {
        // Use libc::open instead of stdlib because it would set CLOEXEC to avoid leaking
        // (which defeats the purpose)
        let dev_null_path = CStr::from_ptr(b"/dev/null\0".as_ptr() as *const _);
        let res = libc::open(dev_null_path.as_ptr(), libc::O_RDONLY);
        if res < 0 {
            log_fatal!("open(/dev/null) failed with errno {}\n", errno());
        }
        else if res != num {
            log_fatal!("open(/dev/null) returned file descriptor number {}, expected {}\n", res, num);
        }
    }
}
