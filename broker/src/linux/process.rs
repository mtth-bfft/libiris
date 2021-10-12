use crate::process::CrossPlatformSandboxedProcess;
use core::ffi::c_void;
use core::ptr::null;
use iris_policy::{CrossPlatformHandle, Handle, Policy};
use iris_ipc::{SECCOMP_HANDLE_ENV_NAME, MessagePipe, CrossPlatformMessagePipe};
use libc::c_int;
use std::convert::{TryFrom, TryInto};
use std::ffi::{CStr, CString};
use std::io::Error;
use seccomp_sys::{
    scmp_arg_cmp, scmp_compare, scmp_filter_attr, seccomp_api_get, seccomp_attr_set, seccomp_init, seccomp_load, seccomp_export_bpf,
    seccomp_release, seccomp_rule_add, seccomp_syscall_resolve_name, SCMP_ACT_ALLOW, SCMP_ACT_TRAP, SCMP_ACT_NOTIFY,
    __NR_SCMP_ERROR,
};

const DEFAULT_CLONE_STACK_SIZE: usize = 1 * 1024 * 1024;
const MAGIC_VALUE_TO_READ_FROM_BROKER: u64 = 0xC0FF33C0FF33;
const SYSCALLS_ALLOWED_BY_DEFAULT: [&str; 54] = [
    "read",
    "write",
    "readv",
    "writev",
    "recvmsg",
    "sendmsg",
    "tee",
    "fstat",
    "lseek",
    "_llseek",
    "select",
    "_newselect",
    "accept",
    "accept4",
    //"ftruncate", disallowed to prevent truncation of O_APPEND files
    "close",
    "memfd_create",
    "sigaltstack",
    "munmap",
    "nanosleep",
    "fchdir",
    "exit_group",
    "restart_syscall",
    "rt_sigreturn",
    "rt_sigaction", // FIXME: should really be handled separately, to hook rt_sigaction(SIGSYS,..)
    "getpid",
    "gettid",
    "alarm",
    "arch_prctl",
    "brk",
    "cacheflush",
    "close_range",
    "getresuid",
    "getresgid",
    "getresuid32",
    "getresgid32",
    "getrandom",
    "getuid",
    "getuid32",
    "readdir",
    "timer_create",
    "timer_delete",
    "timer_getoverrun",
    "timer_gettime",
    "timer_settime",
    "timerfd_create",
    "timerfd_gettime",
    "timerfd_settime",
    "times",
    "sched_yield",
    "time",
    "uname",
    "shutdown",
    "nice",
    "pause",
];

pub struct OSSandboxedProcess {
    pid: u32,
    // Thread stack for clone(2), flagged as "never read" because rust does not
    // know about the thread created unsafely
    #[allow(dead_code)]
    initial_thread_stack: Vec<u8>,
}

struct EntrypointParameters {
    exe: CString,
    argv: Vec<CString>,
    envp: Vec<CString>,
    allowed_file_descriptors: Vec<c_int>,
    sock_execve_errno: MessagePipe,
    sock_seccomp: MessagePipe,
    stdin: Option<c_int>,
    stdout: Option<c_int>,
    stderr: Option<c_int>,
}

fn get_syscall_number(name: &str) -> Result<i32, String> {
    let name_null_terminated = CString::new(name).unwrap();
    let nr = unsafe { seccomp_syscall_resolve_name(name_null_terminated.as_ptr()) };
    if nr == __NR_SCMP_ERROR {
        return Err(format!(
            "Syscall name \"{}\" not resolved by libseccomp",
            name
        ));
    }
    Ok(nr)
}

impl CrossPlatformSandboxedProcess for OSSandboxedProcess {
    fn new(
        policy: &Policy,
        exe: &CStr,
        argv: &[&CStr],
        envp: &[&CStr],
        stdin: Option<&Handle>,
        stdout: Option<&Handle>,
        stderr: Option<&Handle>,
    ) -> Result<Self, String> {
        if argv.len() < 1 {
            return Err("Invalid argument: empty argv".to_owned());
        }
        for handle in vec![stdin, stdout, stderr] {
            if let Some(handle) = handle {
                if !handle.is_inheritable()? {
                    return Err("Stdin, stdout, and stderr handles must not be set to be closed on exec() for them to be usable by a worker".to_owned());
                }
            }
        }
        for env_var in envp {
            if env_var.to_string_lossy().starts_with(SECCOMP_HANDLE_ENV_NAME) {
                return Err(format!(
                    "Workers cannot use the reserved {} environment variable",
                    SECCOMP_HANDLE_ENV_NAME
                ));
            }
        }

        // Allocate a stack for the process' first thread to use
        let mut stack = vec![0; DEFAULT_CLONE_STACK_SIZE];
        let stack_end_ptr = stack.as_mut_ptr().wrapping_add(stack.len()) as *mut c_void;

        // Unshare as many namespaces as possible
        // (this might not be possible due to insufficient privilege level,
        // and/or kernel support for unprivileged or even privileged user namespaces)
        let clone_args = 0; // FIXME: add a retry-loop for libc::CLONE_NEWUSER | libc::CLONE_NEWCGROUP | libc::CLONE_NEWIPC | libc::CLONE_NEWNET | libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWUTS;

        // Set up a pipe that will get CLOEXEC-ed if execve() succeeds, and otherwise be used to send us the errno
        let (mut sock_exec_parent, mut sock_exec_child) = MessagePipe::new()?;
        // Set the child end as CLOEXEC so it gets closed on successful execve(), which we can detect
        sock_exec_child.as_handle().set_inheritable(false)?;

        // Set up a pipe that we will use to transmit a go/no-go for seccomp unotify to the worker
        let (sock_seccomp_child, mut sock_seccomp_parent) = MessagePipe::new()?;

        // Pack together everything that needs to be passed to the new process
        let entrypoint_params = EntrypointParameters {
            exe: exe.to_owned(),
            argv: argv.iter().map(|x| (*x).to_owned()).collect(),
            envp: envp.iter().map(|x| (*x).to_owned()).collect(),
            allowed_file_descriptors: policy
                .get_inherited_handles()
                .iter()
                .map(|n| n.as_raw().try_into().unwrap())
                .collect(),
            sock_execve_errno: sock_exec_child,
            sock_seccomp: sock_seccomp_child,
            stdin: stdin.map(|h| c_int::try_from(h.as_raw()).unwrap()),
            stdout: stdout.map(|h| c_int::try_from(h.as_raw()).unwrap()),
            stderr: stderr.map(|h| c_int::try_from(h.as_raw()).unwrap()),
        };
        let entrypoint_params = Box::leak(Box::new(entrypoint_params));

        let worker_pid = unsafe {
            libc::clone(
                process_entrypoint,
                stack_end_ptr,
                clone_args,
                entrypoint_params as *const _ as *mut c_void,
            )
        };

        // Drop the structure in the parent so it doesn't leak. This is safe since we
        // created the box a few lines above and only we own/know about it (in *this* process)
        drop(unsafe { Box::from_raw(entrypoint_params as *mut EntrypointParameters) });

        if worker_pid <= 0 {
            return Err(format!(
                "clone() failed with code {}",
                Error::last_os_error()
            ));
        }

        // Check out if seccomp user notifications are usable: we need support from the
        // kernel, from libseccomp, and the ability to read from the newly created process memory.
        let use_seccomp_user_notifications = if unsafe { seccomp_api_get() } < 5 {
            println!(" [!] Installed version of Linux or libseccomp is too old to support user notifications");
            false
        } else {
            let mut read_buffer: u64 = 0;
            let local_iov = libc::iovec {
                iov_base: &mut read_buffer as *mut _ as *mut _,
                iov_len: std::mem::size_of::<u64>(),
            };
            let remote_iov = libc::iovec {
                iov_base: &MAGIC_VALUE_TO_READ_FROM_BROKER as *const _ as *mut _,
                iov_len: std::mem::size_of::<u64>(),
            };
            let res = unsafe { libc::process_vm_readv(worker_pid, &local_iov as *const _, 1, &remote_iov as *const _, 1, 0) };
            if res != std::mem::size_of::<u64>().try_into().unwrap() || read_buffer == MAGIC_VALUE_TO_READ_FROM_BROKER {
                println!(" [!] Unable to read worker process memory from broker (code {}), falling back to legacy seccomp-trap", res);
                false
            }
            else {
                println!(" [.] Will use seccomp user notifications for sandboxing");
                true
            }
        };
        // Send that info to the worker, so they can use the right type of seccomp filter
        // before execve() (if user notifications are usable) or after execve()
        // (if only seccomp trap is usable).
        if let Err(e) = sock_seccomp_parent.send(&[use_seccomp_user_notifications as u8], None) {
            // TODO: check need for freeing resource
            return Err(format!("Unable to send seccomp status to worker process: {}", e));
        }

        if let Ok(v) = sock_exec_parent.recv() {
            if v.len() > 0 {
                return Err(format!("execve() failed with code {}", u32::from_be_bytes(v.try_into().unwrap_or([0u8; 4]))));
            }
        }

        println!(" [.] Worker PID={} created", worker_pid);
        Ok(Self {
            pid: worker_pid.try_into().unwrap(),
            initial_thread_stack: stack,
        })
    }

    fn get_pid(&self) -> u64 {
        self.pid.into()
    }

    fn wait_for_exit(&mut self) -> Result<u64, String> {
        let mut wstatus: c_int = 0;
        loop {
            let res =
                unsafe { libc::waitpid(self.pid as i32, &mut wstatus as *mut _, libc::__WALL) };
            if res == -1 {
                return Err(format!(
                    "waitpid({}) failed with code {}",
                    self.pid,
                    Error::last_os_error().raw_os_error().unwrap_or(0)
                ));
            }
            if libc::WIFEXITED(wstatus) {
                return Ok(libc::WEXITSTATUS(wstatus).try_into().unwrap());
            }
            if libc::WIFSIGNALED(wstatus) {
                return Ok((128 + libc::WTERMSIG(wstatus)).try_into().unwrap());
            }
        }
    }
}

fn replace_fd_with_or_dev_null(fd: libc::c_int, replacement: Option<libc::c_int>) {
    unsafe {
        libc::close(fd);
    }
    if let Some(replacement) = replacement {
        let res = unsafe { libc::dup(replacement) };
        if res != fd {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(0);
            panic!("Failed to setup file descriptor for std[in,out,err] : dup() returned {} (errno {})", res, errno);
        }
    } else {
        // Use libc::open because Rust's stdlib sets CLOEXEC to avoid leaking file descriptors
        let dev_null_path = CString::new("/dev/null").unwrap();
        unsafe {
            libc::open(dev_null_path.as_ptr(), libc::O_RDWR);
        }
    }
}

extern "C" fn process_entrypoint(args: *mut c_void) -> c_int {
    let mut args = unsafe { Box::from_raw(args as *mut EntrypointParameters) };
    println!(
        " [.] Worker {} started with PID={}",
        args.exe.to_string_lossy(),
        unsafe { libc::getpid() }
    );

    // Prevent ourselves from acquiring more capabilities using binaries with SUID
    // bit or capabilities set, which blocks exploitation of vulnerabilities in them.
    // This is also required to use seccomp().
    let res = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if res != 0 {
        panic!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed with error {}",
            std::io::Error::last_os_error()
        );
    }

    // TODO: set the umask

    // Close stdin/stdout/stderr and replace them with user-provided file descriptors,
    // or /dev/null so that any read (resp. write) deterministically returns EOF (resp.
    // does nothing), and so that no sensitive FD can be opened and leaked under the radar
    // passing as stdin stdout or stderr.
    replace_fd_with_or_dev_null(libc::STDIN_FILENO, args.stdin);
    replace_fd_with_or_dev_null(libc::STDOUT_FILENO, args.stdout);
    replace_fd_with_or_dev_null(libc::STDERR_FILENO, args.stderr);

    // Wait for our broker to tell us which type of seccomp filter to use
    let use_seccomp_user_notifications = {
        let mut byte = 0u8;
        let res = unsafe { libc::recv(args.sock_seccomp.as_raw().try_into().unwrap(), &mut byte as *mut _ as *mut _, 1, libc::MSG_WAITALL) };
        if res != 1 {
            println!(" [!] Unable to recv seccomp status from broker ({}), falling back to seccomp trap", Error::last_os_error());
            byte = 0;
        }
        byte != 0
    };

    // Compile a seccomp filter for this worker
    let filter = unsafe { seccomp_init(if use_seccomp_user_notifications { SCMP_ACT_NOTIFY } else { SCMP_ACT_TRAP }) };
    if filter.is_null() {
        panic!("seccomp_init() failed, no error information available");
    }

    let res = unsafe { seccomp_attr_set(filter, scmp_filter_attr::SCMP_FLTATR_CTL_TSYNC, 1) };
    if res != 0 {
        panic!(
            "seccomp_attr_set(SCMP_FLTATR_CTL_TSYNC) failed with error {}",
            -res
        );
    }

    for syscall_name in &SYSCALLS_ALLOWED_BY_DEFAULT {
        let syscall_nr = match get_syscall_number(&syscall_name) {
            Ok(n) => n,
            Err(e) => {
                eprintln!(" [.] Unable to find syscall {} : {}", syscall_name, e);
                continue;
            }
        };
        println!(" [.] Allowing syscall {} / {}", syscall_name, syscall_nr);
        let res = unsafe { seccomp_rule_add(filter, SCMP_ACT_ALLOW, syscall_nr, 0) };
        if res != 0 {
            panic!(
                "seccomp_rule_add(SCMP_ACT_ALLOW, {}) failed with code {}",
                syscall_name, -res
            );
        }
    }

    // Add special case handling for fcntl() with F_GETFL only
    // - F_SETFL would allow a worker to clear the O_APPEND flag on an opened file
    let syscall_nr = get_syscall_number("fcntl").unwrap();
    println!(
        " [.] Allowing syscall fcntl / {} for F_GETFL only",
        syscall_nr
    );
    let a0_pid_comparator = scmp_arg_cmp {
        arg: 0, // first syscall argument
        op: scmp_compare::SCMP_CMP_EQ,
        datum_a: libc::F_GETFL.try_into().unwrap(),
        datum_b: 0, // unused with SCMP_CMP_EQ
    };
    let res = unsafe { seccomp_rule_add(filter, SCMP_ACT_ALLOW, syscall_nr, 1, a0_pid_comparator) };
    if res != 0 {
        println!(" [!] seccomp_rule_add(SCMP_ACT_ALLOW, fcntl, SCMP_A0(SCMP_CMP_EQ, F_GETFL)) failed with code {}", -res);
    }

    // Add special case handling for kill() on ourselves only (useful for e.g. raise())
    let syscall_nr = get_syscall_number("kill").unwrap();
    println!(
        " [.] Allowing syscall kill / {} on ourselves only",
        syscall_nr
    );
    let mypid = std::process::id();
    let a0_pid_comparator = scmp_arg_cmp {
        arg: 0, // first syscall argument
        op: scmp_compare::SCMP_CMP_EQ,
        datum_a: mypid.try_into().unwrap(),
        datum_b: 0, // unused with SCMP_CMP_EQ
    };
    let res = unsafe { seccomp_rule_add(filter, SCMP_ACT_ALLOW, syscall_nr, 1, a0_pid_comparator) };
    if res != 0 {
        println!(" [!] seccomp_rule_add(SCMP_ACT_ALLOW, kill, SCMP_A0(SCMP_CMP_EQ, getpid())) failed with code {}", -res);
    }

    let syscall_nr = get_syscall_number("tgkill").unwrap();
    println!(
        " [.] Allowing syscall tgkill / {} on ourselves only",
        syscall_nr
    );
    let a0_pid_comparator = scmp_arg_cmp {
        arg: 0, // first syscall argument
        op: scmp_compare::SCMP_CMP_EQ,
        datum_a: mypid.try_into().unwrap(),
        datum_b: 0, // unused with SCMP_CMP_EQ
    };
    let res = unsafe { seccomp_rule_add(filter, SCMP_ACT_ALLOW, syscall_nr, 1, a0_pid_comparator) };
    if res != 0 {
        println!(" [!] seccomp_rule_add(SCMP_ACT_ALLOW, tgkill, SCMP_A0(SCMP_CMP_EQ, getpid())) failed with code {}", -res);
    }

    let syscall_nr = get_syscall_number("tkill").unwrap();
    println!(
        " [.] Allowing syscall tkill / {} on ourselves only",
        syscall_nr
    );
    let mytid = unsafe { libc::syscall(libc::SYS_gettid) };
    let a0_tid_comparator = scmp_arg_cmp {
        arg: 0, // first syscall argument
        op: scmp_compare::SCMP_CMP_EQ,
        datum_a: mytid.try_into().unwrap(),
        datum_b: 0, // unused with SCMP_CMP_EQ
    };
    let res = unsafe { seccomp_rule_add(filter, SCMP_ACT_ALLOW, syscall_nr, 1, a0_tid_comparator) };
    if res != 0 {
        panic!("seccomp_rule_add(SCMP_ACT_ALLOW, tkill, SCMP_A0(SCMP_CMP_EQ, gettid())) failed with code {}", -res);
    }

    let mut seccomp_fd_to_allow = None;
    if use_seccomp_user_notifications {
        // FIXME: load filter
        let res = unsafe { seccomp_load(filter) };
        if res != 0 {
            panic!("seccomp_load() failed with error {}", -res);
        }

        unsafe { seccomp_release(filter) };
    }
    else {
        // We need to give this filter to the process, post-execve(). Save it
        // to an ephemeral file descriptor they will inherit (the only export
        // function from libseccomp only accepts a file descriptor as of today)
        let mut tmp_fd_path = CString::new("iris_seccomp_XXXXXX").unwrap().into_bytes_with_nul();
        let tmp_fd = unsafe { libc::mkstemp(tmp_fd_path.as_mut_ptr() as *mut _) };
        if tmp_fd < 0 {
            println!(" [!] Unable to open ephemeral file to export seccomp filter");
        }
        else {
            println!(" [.] Storing seccomp filter at {}", std::str::from_utf8(&tmp_fd_path[..]).unwrap_or("<?>"));
            let res = unsafe { libc::unlink(tmp_fd_path.as_ptr() as *const _) };
            if res != 0 {
                println!(" [!] Unable to clean up tmp file containing seccomp filter");
            }
            let res = unsafe { seccomp_export_bpf(filter, tmp_fd) };
            if res != 0 {
                println!(" [!] Unable to export seccomp filter (error {})", res);
            }
            else {
                let res = unsafe { libc::lseek(tmp_fd, 0, libc::SEEK_SET) };
                if res != 0 {
                    println!(" [!] Unable to reset seccomp filter file descriptor (error {})", Error::last_os_error());
                }
                else {
                    args.envp.push(CString::new(format!("{}={}", SECCOMP_HANDLE_ENV_NAME, tmp_fd)).unwrap());
                    seccomp_fd_to_allow = Some(tmp_fd);
                }
            }
        }
    }

    // Cleanup leftover file descriptors from our parent or from code injected into our process
    for entry in std::fs::read_dir("/proc/self/fd/").expect("unable to read /proc/self/fd/") {
        let entry = entry.expect("unable to read entry from /proc/self/fd/");
        if !entry
            .file_type()
            .expect("unable to read file type from /proc/self/fd")
            .is_symlink()
        {
            continue;
        }
        let mut path = entry.path();
        loop {
            match std::fs::read_link(&path) {
                Ok(target) => path = target,
                Err(_) => break,
            }
        }
        // Exclude the file descriptor from the read_dir itself (if we close it, we might
        // break the /proc/self/fd/ enumeration)
        if path.to_string_lossy() == format!("/proc/{}/fd", std::process::id()) {
            continue;
        }
        if let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() {
            // Don't close our stdin/stdout/stderr handles
            // Don't close the CLOEXEC pipe used to check if execve() worked, otherwise it loses its purpose
            if fd > libc::STDERR_FILENO
                    && fd != args.sock_execve_errno.as_handle().as_raw().try_into().unwrap()
                    && seccomp_fd_to_allow != Some(fd)
                    && !args.allowed_file_descriptors.contains(&fd) {
                println!(" [.] Cleaning up file descriptor {} ({})", fd, path.to_string_lossy());
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }

    let argv: Vec<*const i8> = args
        .argv
        .iter()
        .map(|x| x.as_ptr())
        .chain(std::iter::once(null()))
        .collect();
    let envp: Vec<*const i8> = args
        .envp
        .iter()
        .map(|x| x.as_ptr())
        .chain(std::iter::once(null()))
        .collect();
    unsafe { libc::execve(args.exe.as_ptr(), argv.as_ptr(), envp.as_ptr()) };

    // execve() failed, either because the executable was not found, was not
    // executable, or some system-related error (insufficient resources or whatnot).
    // Tell our broker so it can report the error back to the Worker::new() caller.
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let errno_bytes = (errno as u32).to_be_bytes();
    unsafe {
        libc::send(args.sock_execve_errno.as_handle().as_raw().try_into().unwrap(), errno_bytes.as_ptr() as *const _, 4, 0);
        libc::exit(errno);
    }
}
