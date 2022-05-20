#![no_std]

use core::panic::PanicInfo;
use libc::c_int;
use iris_ipc::{IPC_MESSAGE_MAX_SIZE, MessagePipe, CrossPlatformMessagePipe};
use iris_policy::handle::CrossPlatformHandle;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libc::exit(-1);
    // Even with a malfunctioning IPC channel, we should still be able to
    // exit the worker (this is an unprivileged operation). If it fails,
    // the last resort is to crash the program.
    let null: *const u32 = null_mut();
    loop {
        *null = 0xDEAD;
    }
}

pub struct CloneStubParameters {
    // Pointer to absolute path of the executable to start,
    // as a NULL-terminated string
    exe: *const i8,
    argv: *const *const i8,
    envp: *const *const i8,
    // Communication channel to our caller/parent, so that we can
    // report what worked and what did not
    //sock: MessagePipe,
    // File descriptor (read/write) for /dev/null (we could open one
    // in the clone stub, but the less we do here the better)
    devnull_fd: c_int,
    // File descriptor to use as stdin, if any
    stdin: Option<c_int>,
    // File descriptor to use as stdout, if any
    stdout: Option<c_int>,
    // File descriptor to use as stderr, if any
    stderr: Option<c_int>,
    // File descriptor to a pipe to communicate any execve() error
    // to our broker
    sock_execve: MessagePipe,
    // File descriptor to a pipe to communicate about seccomp with
    // our broker
    sock_seccomp: MessagePipe,
    // Pre-allocated buffer we can use as temporary space to serialize
    // and de-serialize IPC data without making any memory allocation
    buffer: [u8; IPC_MESSAGE_MAX_SIZE],
}

fn errno() -> c_int {
    unsafe { *(libc::__errno_location()) }
}

// Entrypoint executed by clone(). This needs to be async-signal-safe,
// and so is kept in a separate no_std crate. Care must be taken when
// modifying this function, so as to not:
// - execute any libc function that is not async-signal-safe
// - perform any memory allocation or libstd operation which might
//   hang if a lock is kept in a dead thread
pub extern "C" fn clone_stub(args: *mut CloneStubParameters) -> c_int {
    let args = unsafe { &mut *args };
    // Prevent ourselves from acquiring more capabilities using binaries with SUID
    // bit or capabilities set, which blocks exploitation of vulnerabilities in them.
    // This is also required to use seccomp().
    let res = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if res != 0 {
        panic!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed with error {}",
            errno()
        );
    }

    // TODO: set the umask
    
    // Close stdin/stdout/stderr and replace them with user-provided file descriptors,
    // or /dev/null so that any read (resp. write) deterministically returns EOF (resp.
    // does nothing), and so that no sensitive FD can be opened and leaked under the radar
    // passing as stdin stdout or stderr.
    replace_fd_with_or_dev_null(libc::STDIN_FILENO, args.stdin, args.devnull_fd);
    replace_fd_with_or_dev_null(libc::STDOUT_FILENO, args.stdout, args.devnull_fd);
    replace_fd_with_or_dev_null(libc::STDERR_FILENO, args.stderr, args.devnull_fd);

    // Wait for our broker to tell us whether it can read our memory (if it
    // cannot, we cannot use any seccomp filter)
    let broker_can_read_our_memory = match args.sock_seccomp.recv(&mut args.buffer) {
        Ok(v) if v.len() == 1 => v[0] != 0,
        other => {
            println!(" [!] Unable to receive seccomp status from broker ({:?}), falling back to seccomp trap", other);
            false
        }
    };

    if broker_can_read_our_memory {
        // Try to load a seccomp user notification filter
        let mut code = 0_i32.to_be_bytes();
        let mut notify_fd = None;
        #[cfg(seccomp_notify)]
        match generate_seccomp_filter(true) {
            Err(e) => {
                eprintln!(" [!] Unable to generate seccomp user notification filter: {}", e);
            }
            Ok(filter) => {
                if let Err(n) = filter.load() {
                    code = n.to_be_bytes();
                } else {
                    // Note: at this point, we're fully committed to seccomp-unotify.
                    // If something fails, our process is doomed to hang as soon as we
                    // issue an unauthorized syscall. Better to crash than to hang.
                    notify_fd = match filter.get_notify_fd() {
                        Ok(fd) => Some(fd),
                        Err(err) => {
                            eprintln!("Fatal error: seccomp_notify_fd() failed ({})", err);
                            std::process::abort(); // do *not* panic!() which unwinds
                        },
                    };
                }
            },
        }
        // Send the file descriptor to our parent so that it can receive notifications
        if let Err(e) = args.sock_seccomp.send(&code, notify_fd.as_ref()) {
            eprintln!(
                "Fatal error: unable to send seccomp notify handle to broker: {}",
                e
            );
            std::process::abort(); // do *not* panic!() which unwinds
        }
    }
    // Get the number of currently opened file descriptors, by setting a soft limit on
    // their number and trying to open one more. If it fails, restart with a higher limit, until it succeeds.
    let mut original_limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let res = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut original_limit as *mut _) };
    if res != 0 {
        println!(
            " [!] Unable to cleanup inherited file descriptors: getrlimit(RLIMIT_NOFILE) errno {}",
            errno()
        );
    } else {
        let mut fd_count = 0;
        loop {
            let mut tmp_limit = original_limit;
            tmp_limit.rlim_cur = fd_count + 1;
            let res = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &tmp_limit as *const _) };
            if res != 0 {
                println!(" [!] Unable to cleanup inherited file descriptors: setrlimit(RLIMIT_NOFILE) errno {}", errno());
                break;
            }
            let res = unsafe { libc::dup(args.devnull_fd) };
            if res >= 0 {
                unsafe {
                    libc::close(res);
                }
                break;
            }
            fd_count += 1;
        }
        let res = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &original_limit as *const _) };
        if res != 0 {
            println!(" [!] Unable to cleanup inherited file descriptors: setrlimit(RLIMIT_NOFILE) errno {}", errno());
        }
        println!(
            " [.] Cleaning up file descriptors: {} to find, allowed: {:?}",
            fd_count, args.allowed_file_descriptors
        );
        let mut fd_found = 3; // don't clean up stdin/stdout/stderr
        for fd in 3i32.. {
            if fd_found == fd_count {
                break;
            }
            if fd == args.sock_execve.as_handle().as_raw() || args.allowed_file_descriptors.contains(&fd) {
                fd_found += 1;
                continue;
            }
            let res = unsafe { libc::close(fd) };
            if res == 0 {
                fd_found += 1;
                println!(" [+] Cleaned up file descriptor {}", fd);
            } else {
                if errno() != libc::EBADF {
                    // no such file descriptor
                    println!(
                        " [!] Unable to cleanup inherited file descriptors: close({}) errno {}",
                        fd, errno()
                    );
                    break;
                }
            }
        }
    }

    unsafe {
        libc::execve(args.exe, args.argv, args.envp);
    }
    // execve() failed, either because the executable was not found, was not
    // executable, or some system-related error (insufficient resources or whatnot).
    // Tell our broker so it can report the error back to the Worker::new() caller.
    let errno_val = errno();
    let errno_bytes = (errno_val as u32).to_be_bytes();
    if let Err(e) = args.sock_execve.send(&errno_bytes, None) {
        eprintln!(
            "Fatal error: failed to report execve() error to broker: {}",
            e
        );
    }
    errno_val
}

fn replace_fd_with_or_dev_null(fd: c_int, new: Option<c_int>, devnull_fd: c_int) {
    unsafe {
        libc::close(fd);
    }
    let replacement = new.unwrap_or(devnull_fd);
    let res = unsafe { libc::dup(replacement) };
    if res != fd {
        panic!("Failed to setup file descriptor {} : dup() returned {} (errno {})", res, errno())
    }
}
