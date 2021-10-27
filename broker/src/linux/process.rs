use crate::process::CrossPlatformSandboxedProcess;
use core::ffi::c_void;
use std::sync::Arc;
use core::ptr::{null, null_mut};
use iris_policy::{CrossPlatformHandle, Handle, Policy};
use iris_ipc::{MessagePipe, CrossPlatformMessagePipe, IPCMessagePipe, IPCRequestV1, IPCResponseV1};
use libc::c_int;
use std::convert::{TryFrom, TryInto};
use std::ffi::{CStr, CString};
use std::io::{Error, Read, Seek, SeekFrom};
use std::thread::JoinHandle;
use std::fs::File;
use seccomp_sys::{
    scmp_arg_cmp, scmp_compare, seccomp_load, seccomp_export_bpf, seccomp_notify_fd, seccomp_notif_resp, seccomp_notify_alloc, seccomp_notif, seccomp_notify_receive, seccomp_notify_respond, seccomp_notify_id_valid, seccomp_rule_add, seccomp_syscall_resolve_name, SCMP_ACT_ALLOW, SCMP_ACT_TRAP, SCMP_ACT_NOTIFY, __NR_SCMP_ERROR,
};
use std::os::unix::io::FromRawFd;
use std::os::unix::io::AsRawFd;
use crate::os::brokered_syscalls::handle_syscall;
use crate::os::seccomp::SeccompFilter;

const DEFAULT_CLONE_STACK_SIZE: usize = 1 * 1024 * 1024;
const MAGIC_VALUE_TO_READ_FROM_BROKER: [u8; 29] = *b"I AM A LIBIRIS WORKER PROCESS";
const SYSCALLS_ALLOWED_BY_DEFAULT: [&str; 56] = [
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
    //"clone",  // Note: should only allow thread creation within the same namespaces,
                // but argument order depends on Linux build configuration.
    "get_robust_list",
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
    "set_robust_list",
    "pause",
];

pub struct OSSandboxedProcess {
    pid: u32,
    // Thread stack for clone(2), flagged as "never read" because rust does not
    // know about the thread created unsafely
    #[allow(dead_code)]
    initial_thread_stack: Vec<u8>,
    // Thread which will handle seccomp user notifications
    seccomp_unotify_thread: Option<JoinHandle<()>>,
    // Thread which will continuously read IPC requests
    ipc_thread: Option<JoinHandle<()>>,
    // BPF bytecode waiting to be enforced as soon as process initialization is over
    pending_seccomp_bpf: Option<Vec<u8>>,
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
        stdin: Option<Arc<Handle>>,
        stdout: Option<Arc<Handle>>,
        stderr: Option<Arc<Handle>>,
    ) -> Result<Self, String> {
        if argv.len() < 1 {
            return Err("Invalid argument: empty argv".to_owned());
        }
        for handle in &[&stdin, &stdout, &stderr] {
            if let Some(handle) = handle {
                if !handle.is_inheritable()? {
                    return Err("Stdin, stdout, and stderr handles must not be set to be closed on exec() for them to be usable by a worker".to_owned());
                }
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

        // Check whether we can read from the worker's memory or not
        let proc_mem = match File::open(format!("/proc/{}/mem", worker_pid)) {
            Ok(mut f) => {
                let mut buffer = vec![0u8; std::mem::size_of_val(&MAGIC_VALUE_TO_READ_FROM_BROKER)];
                if let Err(e) = f.seek(SeekFrom::Start((&MAGIC_VALUE_TO_READ_FROM_BROKER as *const _) as u64)) {
                    println!(" [!] Unable to seek into worker process memory: {}", e);
                    None
                }
                else if let Err(e) = f.read_exact(&mut buffer) {
                    println!(" [!] Unable to read from worker process memory: {}", e);
                    None
                }
                else if &buffer[..] != MAGIC_VALUE_TO_READ_FROM_BROKER {
                    println!(" [!] Unexpected value read from worker process memory {:?} , expected {:?}", buffer, &MAGIC_VALUE_TO_READ_FROM_BROKER);
                    None
                }
                else {
                    println!(" [.] Will use seccomp user notifications for sandboxing");
                    Some(f)
                }
            },
            Err(e) => {
                println!(" [!] Unable to open worker process memory: {}", e);
                None
            },
        };
        // Send that info to the worker, so it knows whether it can apply a seccomp filter
        // Note: it's okay not to use a well-defined and versionned IPC here, since this is
        // sent and received by the same executable.
        if let Err(e) = sock_seccomp_parent.send(&[proc_mem.is_some() as u8], None) {
            return Err(format!("Unable to send seccomp status to worker process: {}", e));
        }
        let mut pending_seccomp_bpf = None;
        let mut seccomp_unotify_thread = None;
        if let Some(proc_mem) = proc_mem {
            // Wait for the worker to tell us if it succeeded in applying a seccomp filter
            match sock_seccomp_parent.recv_with_handle() {
                Ok((bpf, None)) if !bpf.is_empty() => pending_seccomp_bpf = Some(bpf),
                Ok((v, Some(notify_fd))) if v.is_empty() => {
                    println!(" [.] Received seccomp user notification fd {:?}", notify_fd);
                    let mut policy = policy.clone();
                    policy.release_handles();
                    seccomp_unotify_thread = Some(std::thread::spawn(move || {
                        // TODO: handle panics in this thread, kill the worker on break; and clean up
                        let mut req: *mut seccomp_notif = null_mut();
                        let mut resp: *mut seccomp_notif_resp = null_mut();
                        let res = unsafe { seccomp_notify_alloc(&mut req as *mut *mut seccomp_notif, &mut resp as *mut *mut seccomp_notif_resp) };
                        if res != 0 {
                            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                            panic!("seccomp_notify_alloc() failed with error {} (errno {})", res, errno);
                        }
                        loop {
                            // seccomp_notify_receive() requires the notification struct to be zeroed
                            unsafe { core::ptr::write_bytes(req as *mut u8, 0u8, std::mem::size_of::<seccomp_notif>()); }
                            let res = unsafe { seccomp_notify_receive(notify_fd.as_raw().try_into().unwrap(), req) };
                            if res != 0 {
                                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                                panic!("seccomp_notify_receive() failed with error {} (errno {})", res, errno);
                            }
                            let ip = unsafe { (*req).data.instruction_pointer };
                            let arch = unsafe { (*req).data.arch };
                            let nr = unsafe { (*req).data.nr as u64 };
                            let arg1 = unsafe { (*req).data.args[0] };
                            let arg2 = unsafe { (*req).data.args[1] };
                            let arg3 = unsafe { (*req).data.args[2] };
                            let arg4 = unsafe { (*req).data.args[3] };
                            let arg5 = unsafe { (*req).data.args[4] };
                            let arg6 = unsafe { (*req).data.args[5] };
                            let (code, handle) = handle_syscall(arch, nr, arg1, arg2, arg3, arg4, arg5, arg6, &policy, &proc_mem);
                            unsafe { core::ptr::write_bytes(resp as *mut u8, 0u8, std::mem::size_of::<seccomp_notif_resp>()); }
                            unsafe { (*resp).id = (*req).id; } // to allow the kernel to match the response to the request
                            unsafe { (*resp).val = code; } // response the process will see
                            let res = unsafe { seccomp_notify_respond(notify_fd.as_raw().try_into().unwrap(), resp) };
                            if res != 0 {
                                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                                let exists = unsafe { seccomp_notify_id_valid(notify_fd.as_raw().try_into().unwrap(), (*req).id) };
                                if exists != -(libc::ENOENT) {
                                    println!(" [!] Spurious syscall response failure: seccomp_notify_respond() failed with code {} (errno {})", res, errno);
                                }
                            }
                        }
                    }));
                },
                _ => {
                    println!(" [!] No seccomp filter worked");
                },
            }
        }

        if let Ok(v) = sock_exec_parent.recv() {
            if v.len() > 0 {
                return Err(format!("execve() failed with code {}", u32::from_be_bytes(v.try_into().unwrap_or([0u8; 4]))));
            }
        }
        println!(" [+] execve() successful");

        println!(" [.] Worker PID={} created", worker_pid);
        Ok(Self {
            pid: worker_pid.try_into().unwrap(),
            initial_thread_stack: stack,
            seccomp_unotify_thread,
            pending_seccomp_bpf,
            ipc_thread: None,
        })
    }

    fn get_pid(&self) -> u64 {
        self.pid.into()
    }

    fn get_late_mitigations(&self) -> Result<IPCResponseV1, String> {
        Ok(IPCResponseV1::LateMitigations {
            seccomp_trap_bpf: self.pending_seccomp_bpf.clone(),
        })
    }

    fn start_serving_ipc_requests(&mut self, mut channel: IPCMessagePipe, policy: Arc<Policy>) -> Result<(), String> {
        let proc_mem = match File::open(format!("/proc/{}/mem", self.pid)) {
            Ok(f) => f,
            Err(e) => { return Err(format!("Unable to open worker process memory: {}", e)) },
        };
        self.ipc_thread = Some(std::thread::spawn(move || {
            loop {
                let req = match channel.recv() {
                    Ok(Some(req)) => req,
                    Ok(None) => break,
                    Err(e) => panic!("Unable to read IPC message from worker: {}", e),
                };
                let (resp, handle) = match req {
                    IPCRequestV1::Syscall { arch, nr, arg1, arg2, arg3, arg4, arg5, arg6 } => handle_syscall(arch, nr, arg1, arg2, arg3, arg4, arg5, arg6, &policy, &proc_mem),
                    other => {
                        println!(" [!] Unexpected IPC message from worker: {:?}", other);
                        break;
                    },
                };
                if let Err(e) = channel.send(&resp, handle.as_ref()) {
                    panic!("Unable to write IPC message to worker: {}", e);
                }
            }
            println!(" [+] Worker closed its IPC socket, closing IPC thread");
        }));
        Ok(())
    }

    fn wait_for_exit(&self) -> Result<u64, String> {
        let mut wstatus: c_int = 0;
        println!(" [.] Waiting for worker exit...");
        let res = unsafe { libc::waitpid(self.pid as i32, &mut wstatus as *mut _, libc::__WALL) };
        if res == -1 {
            Err(format!(
                "waitpid({}) failed with code {}",
                self.pid,
                Error::last_os_error().raw_os_error().unwrap_or(0)
            ))
        }
        else if libc::WIFEXITED(wstatus) {
            Ok(libc::WEXITSTATUS(wstatus).try_into().unwrap())
        }
        else if libc::WIFSIGNALED(wstatus) {
            Ok((128 + libc::WTERMSIG(wstatus)).try_into().unwrap())
        }
        else {
            Err(format!("Unexpected waitpid() success with wstatus {}", wstatus))
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

fn generate_seccomp_filter(default_action: u32) -> Result<SeccompFilter, String> {
    let mut filter = SeccompFilter::new(default_action)?;
    for syscall_name in &SYSCALLS_ALLOWED_BY_DEFAULT {
        let syscall_nr = match get_syscall_number(&syscall_name) {
            Ok(n) => n,
            Err(e) => {
                eprintln!(" [.] Unable to find syscall {} : {}", syscall_name, e);
                continue;
            }
        };
        println!(" [.] Allowing syscall {} / {}", syscall_name, syscall_nr);
        let res = unsafe { seccomp_rule_add(filter.context, SCMP_ACT_ALLOW, syscall_nr, 0) };
        if res != 0 {
            return Err(format!(
                "seccomp_rule_add(SCMP_ACT_ALLOW, {}) failed with code {}",
                syscall_name, -res
            ));
        }
    }

    // Add special case handling for mmap() with prot & PROT_EXEC = 0
    // (allow any combination of PROT_NONE, PROT_READ, PROT_WRITE)
    let syscall_nr = get_syscall_number("mmap").unwrap();
    println!(
        " [.] Allowing syscall mmap / {} for non-executable mappings only",
        syscall_nr
    );
    let a2_prot_exec_comparator = scmp_arg_cmp {
        arg: 2, // third syscall argument
        op: scmp_compare::SCMP_CMP_MASKED_EQ,
        datum_a: (!(libc::PROT_READ | libc::PROT_WRITE)) as u64, // mask
        datum_b: 0, // masked value
    };
    let res = unsafe { seccomp_rule_add(filter.context, SCMP_ACT_ALLOW, syscall_nr, 1, a2_prot_exec_comparator) };
    if res != 0 {
        println!(" [!] seccomp_rule_add(SCMP_ACT_ALLOW, mmap, SCMP_A2(SCMP_CMP_MASKED_EQ, !(PROT_READ|PROT_WRITE), 0)) failed with code {}", -res);
    }

    // Add special case handling for mprotect() with prot & PROT_EXEC = 0
    // (allow any combination of PROT_NONE, PROT_READ, PROT_WRITE)
    let syscall_nr = get_syscall_number("mprotect").unwrap();
    println!(
        " [.] Allowing syscall mprotect / {} for non-executable mappings only",
        syscall_nr
    );
    let a2_prot_exec_comparator = scmp_arg_cmp {
        arg: 2, // third syscall argument
        op: scmp_compare::SCMP_CMP_MASKED_EQ,
        datum_a: (!(libc::PROT_READ | libc::PROT_WRITE)) as u64, // mask
        datum_b: 0, // masked value
    };
    let res = unsafe { seccomp_rule_add(filter.context, SCMP_ACT_ALLOW, syscall_nr, 1, a2_prot_exec_comparator) };
    if res != 0 {
        println!(" [!] seccomp_rule_add(SCMP_ACT_ALLOW, mprotect, SCMP_A2(SCMP_CMP_MASKED_EQ, !(PROT_READ|PROT_WRITE), 0)) failed with code {}", -res);
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
    let res = unsafe { seccomp_rule_add(filter.context, SCMP_ACT_ALLOW, syscall_nr, 1, a0_pid_comparator) };
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
    let res = unsafe { seccomp_rule_add(filter.context, SCMP_ACT_ALLOW, syscall_nr, 1, a0_pid_comparator) };
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
    let res = unsafe { seccomp_rule_add(filter.context, SCMP_ACT_ALLOW, syscall_nr, 1, a0_pid_comparator) };
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
    let res = unsafe { seccomp_rule_add(filter.context, SCMP_ACT_ALLOW, syscall_nr, 1, a0_tid_comparator) };
    if res != 0 {
        panic!("seccomp_rule_add(SCMP_ACT_ALLOW, tkill, SCMP_A0(SCMP_CMP_EQ, gettid())) failed with code {}", -res);
    }

    // Add special case handling for sched_getaffinity() on ourselves only
    // (used by libc at thread initialization)
    // (pid=mypid and pid=0 mean the same thing and are both acceptable)
    let syscall_nr = get_syscall_number("sched_getaffinity").unwrap();
    println!(
        " [.] Allowing syscall sched_getaffinity / {} on ourselves only",
        syscall_nr
    );
    let a0_tid_comparator = scmp_arg_cmp {
        arg: 0, // first syscall argument
        op: scmp_compare::SCMP_CMP_EQ,
        datum_a: mytid.try_into().unwrap(),
        datum_b: 0, // unused with SCMP_CMP_EQ
    };
    let res = unsafe { seccomp_rule_add(filter.context, SCMP_ACT_ALLOW, syscall_nr, 1, a0_tid_comparator) };
    if res != 0 {
        panic!("seccomp_rule_add(SCMP_ACT_ALLOW, sched_getaffinity, SCMP_A0(SCMP_CMP_EQ, gettid())) failed with code {}", -res);
    }
    let a0_zero_comparator = scmp_arg_cmp {
        arg: 0, // first syscall argument
        op: scmp_compare::SCMP_CMP_EQ,
        datum_a: 0, // 0 == ourselves, our PID
        datum_b: 0, // unused with SCMP_CMP_EQ
    };
    let res = unsafe { seccomp_rule_add(filter.context, SCMP_ACT_ALLOW, syscall_nr, 1, a0_zero_comparator) };
    if res != 0 {
        panic!("seccomp_rule_add(SCMP_ACT_ALLOW, sched_getaffinity, SCMP_A0(SCMP_CMP_EQ, 0)) failed with code {}", -res);
    }
    Ok(filter)
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

    // Wait for our broker to tell us whether it can read our memory (if it
    // cannot, we cannot use any seccomp filter)
    let broker_can_read_our_memory = match args.sock_seccomp.recv() {
        Ok(v) if v.len() == 1 => v[0] != 0,
        other => {
            println!(" [!] Unable to receive seccomp status from broker ({:?}), falling back to seccomp trap", other);
            false
        },
    };

    // Compile a seccomp filter for this worker
    let mut mitigation_seccomp_unotify = false;
    if broker_can_read_our_memory {
        if let Ok(filter) = generate_seccomp_filter(SCMP_ACT_NOTIFY) {
            // First, try the ideal case: install a seccomp filter with user notification
            let res = unsafe { seccomp_load(filter.context) };
            if res != 0 {
                println!(" [!] Unable to load seccomp-unotify filter: error {}", res);
            }
            else {
                // Note: at this point, we're fully committed to seccomp-unotify.
                // If something fails, the process is doomed to hang if something fails and we
                // issue an unauthorized syscall. Better to crash than to hang.
                mitigation_seccomp_unotify = true;
                let notify_fd = unsafe {
                    let res = seccomp_notify_fd(filter.context);
                    if res < 0 {
                        panic!("seccomp_notify_fd() failed with error {}", res);
                    }
                    Handle::new(res.try_into().unwrap()).unwrap()
                };
                // Send the file descriptor to our parent so that it can receive notifications
                if let Err(e) = args.sock_seccomp.send(&[], Some(&notify_fd)) {
                    panic!("Unable to send seccomp notify handle to broker: {}", e);
                }
            }
        }
    }
    let mut mitigation_seccomp_trap = false;
    if broker_can_read_our_memory && !mitigation_seccomp_unotify {
        if let Ok(filter) = generate_seccomp_filter(SCMP_ACT_TRAP) {
            // Secondly, try to fallback on seccomp filter with SIGSYS (trap)
            // We need to give this filter to the process, post-execve().
            // Note: Saving to an ephemeral file is convoluted, but it's
            // the only BPF export function from libseccomp as of today.
            let mut tmp_fd_path = CString::new("/tmp/iris_seccomp_XXXXXX").unwrap().into_bytes_with_nul();
            let tmp_fd = unsafe {
                let res = libc::mkstemp(tmp_fd_path.as_mut_ptr() as *mut _);
                if res < 0 {
                    None
                } else {
                    Some(File::from_raw_fd(res))
                }
            };
            if let Some(mut tmp_fd) = tmp_fd {
                let res = unsafe { libc::unlink(tmp_fd_path.as_ptr() as *const _) };
                if res != 0 {
                    println!(" [!] Unable to clean up tmp file {} containing seccomp filter", std::str::from_utf8(&tmp_fd_path).unwrap_or("<?>"));
                }
                let res = unsafe { seccomp_export_bpf(filter.context, tmp_fd.as_raw_fd()) };
                if res != 0 {
                    println!(" [!] Unable to export seccomp filter (error {})", res);
                }
                else {
                    // Converting to a File here is safe as long as we take full ownership of the file
                    if let Err(e) = tmp_fd.seek(SeekFrom::Start(0)) {
                        println!(" [!] Unable to seek to beginning of seccomp BPF filter: {}", e);
                    }
                    else {
                        let mut bpf = vec![];
                        if let Err(e) = tmp_fd.read_to_end(&mut bpf) {
                            println!(" [!] Unable to seek to beginning of seccomp BPF filter: {}", e);
                        }
                        else {
                            if let Err(e) = args.sock_seccomp.send(&bpf[..], None) {
                                println!(" [!] Unable to send seccomp BPF code to broker: {}", e);
                            }
                            else {
                                mitigation_seccomp_trap = true;
                            }
                        }
                    }
                }
            }
        }
    }
    if !mitigation_seccomp_unotify && !mitigation_seccomp_trap {
        if let Err(e) = args.sock_seccomp.send(&[], None) {
            println!(" [!] Unable to send seccomp status (no filter) to broker: {}", e);
        }
    }

    // Cleanup leftover file descriptors from our parent or from code injected into our process
    /*for entry in std::fs::read_dir("/proc/self/fd/").expect("unable to read /proc/self/fd/") {
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
                    && !args.allowed_file_descriptors.contains(&fd) {
                println!(" [.] Cleaning up file descriptor {} ({})", fd, path.to_string_lossy());
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }*/

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
    if let Err(e) = args.sock_execve_errno.send(&errno_bytes, None) {
        println!(" [!] Failed to report execve() error to broker: {}", e);
    }
    std::process::exit(errno);
}
