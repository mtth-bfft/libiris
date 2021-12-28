use crate::os::brokered_syscalls::handle_syscall;
use crate::process::CrossPlatformSandboxedProcess;
use core::ffi::c_void;
use core::ptr::null;
use iris_ipc::{
    CrossPlatformMessagePipe, IPCMessagePipe, IPCRequestV1, IPCResponseV1, IPCVersion, MessagePipe,
};
use iris_policy::{CrossPlatformHandle, Handle, Policy};
use libc::c_int;
use std::convert::{TryFrom, TryInto};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::Error;
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;

use crate::os::seccomp::generate_seccomp_filter;
#[cfg(seccomp_notify)]
use crate::os::seccomp::seccomp_handle_user_notifications;

const DEFAULT_CLONE_STACK_SIZE: usize = 1 * 1024 * 1024;
const MAGIC_VALUE_TO_READ_FROM_BROKER: [u8; 29] = *b"I AM A LIBIRIS WORKER PROCESS";

pub(crate) struct OSSandboxedProcess {
    pid: u32,
    pub(crate) policy: Policy,
    // Thread stack for clone(2), flagged as "never read" because rust does not
    // know about the thread created unsafely
    #[allow(dead_code)]
    initial_thread_stack: Vec<u8>,
    // File descriptor to /proc/x/mem to read syscall arguments from memory
    proc_mem: RwLock<Option<File>>,
    // Thread which will handle seccomp user notifications
    pub(crate) seccomp_unotify_thread: RwLock<Option<JoinHandle<()>>>,
    // Thread which will continuously read IPC requests
    ipc_thread: RwLock<Option<JoinHandle<()>>>,
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

impl CrossPlatformSandboxedProcess for OSSandboxedProcess {
    fn new(
        mut policy: Policy,
        exe: &CStr,
        argv: &[&CStr],
        envp: &[&CStr],
        mut broker_pipe: MessagePipe,
        stdin: Option<Arc<Handle>>,
        stdout: Option<Arc<Handle>>,
        stderr: Option<Arc<Handle>>,
    ) -> Result<Arc<Self>, String> {
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

        // Also drop resources held in the policy: we do not want to keep a handle
        // opened for the whole duration of the worker process just because the worker
        // was allowed to inherit it (and maybe closed it right away)
        policy.release_handles();

        if worker_pid <= 0 {
            return Err(format!(
                "clone() failed with code {}",
                Error::last_os_error()
            ));
        }

        // Check whether we can read from the worker's memory or not
        let proc_mem = match File::open(format!("/proc/{}/mem", worker_pid)) {
            Ok(f) => {
                let mut buffer = vec![0u8; std::mem::size_of_val(&MAGIC_VALUE_TO_READ_FROM_BROKER)];
                let ptr = (&MAGIC_VALUE_TO_READ_FROM_BROKER as *const _) as u64;
                if let Err(e) = f.read_exact_at(&mut buffer, ptr) {
                    println!(" [!] Unable to read from worker process memory: {}", e);
                    None
                } else if &buffer[..] != MAGIC_VALUE_TO_READ_FROM_BROKER {
                    println!(" [!] Unexpected value read from worker process memory {:?} , expected {:?}", buffer, &MAGIC_VALUE_TO_READ_FROM_BROKER);
                    None
                } else {
                    println!(" [.] Worker process memory is readable");
                    Some(f)
                }
            },
            Err(e) => {
                println!(
                    " [!] Cannot use seccomp mitigations: unable to open worker process memory, {}",
                    e
                );
                None
            },
        };
        let can_read_worker_mem = proc_mem.is_some();
        // Send that info to the worker, so it knows whether it can try to apply a seccomp filter
        // Note: it's okay not to use a well-defined and versionned IPC here, since this is
        // sent and received by the same executable.
        if let Err(e) = sock_seccomp_parent.send(&[can_read_worker_mem as u8], None) {
            return Err(format!(
                "Unable to send seccomp status to worker process: {}",
                e
            ));
        }
        // As soon as we sent this, we *cannot* read/timeout on anything coming from the
        // worker. It might already have loaded its filter, and become blocked on an
        // unauthorized syscall performed by a third-party library (or by ourselves, e.g.
        // readdir(/proc/self/fd) to cleanup file descriptors). We need to start responding
        // to seccomp user notifications.

        // Construct a worker object
        // (as an Arc<> because we need to keep a reference in both the IPC and
        // seccomp-unotify thread, with different lifetimes)
        let process = Arc::new(Self {
            pid: worker_pid.try_into().unwrap(),
            initial_thread_stack: stack,
            policy,
            proc_mem: RwLock::new(proc_mem),
            ipc_thread: RwLock::new(None),
            seccomp_unotify_thread: RwLock::new(None),
        });

        // Wait for the worker to tell us if it succeeded in applying a seccomp user notification
        // filter, so that we can spawn a dedicated thread holding an Arc<> to read its memory
        // Note: it's okay not to use a well-defined and versionned IPC here, since this is
        // sent and received by the same executable.
        match sock_seccomp_parent.recv_with_handle() {
            Ok((_, Some(notify_fd))) => {
                println!(" [+] Received seccomp user notification fd {:?}", notify_fd);
                #[cfg(seccomp_notify)]
                seccomp_handle_user_notifications(&process, notify_fd);
            }
            Ok((v, None)) => {
                if v.is_empty() {
                    println!(
                        " [!] Cannot use seccomp user notification mitigation: not supported"
                    );
                } else {
                    let error = i32::from_be_bytes(v.try_into().unwrap_or([0, 0, 0, 0]));
                    println!(
                        " [!] Cannot use seccomp user notification mitigation: error {}",
                        error
                    );
                }
            }
            Err(e) => return Err(format!("Unable to read seccomp user notification status: {}", e)),
        }

        // Now that we have unblocked the worker from its potentially unauthorized
        // syscalls, wait for it to execve(). We get this information by watching
        // our end of a O_CLOEXEC socket shared with the worker getting an EOF.
        if let Ok(v) = sock_exec_parent.recv() {
            if v.len() > 0 {
                return Err(format!(
                    "execve() failed with code {}",
                    u32::from_be_bytes(v.try_into().unwrap_or([0u8; 4]))
                ));
            }
        }
        // Now that we know execve() ran, re-open a final file descriptor to
        // /proc/worker_pid/mem if it worked the first time
        // (the file descriptor opened just above was just to check if /proc/
        // is mounted and the ptrace() access check allows us to read its memory.
        // The file descriptor obtained has become invalid as soon as the
        // worker ran execve()).
        *(process.proc_mem.write().unwrap()) = if can_read_worker_mem {
            match File::open(format!("/proc/{}/mem", worker_pid)) {
                Ok(f) => Some(f),
                Err(e) => {
                    // Processs might have died at early launch. Otherwise,
                    // process is doomed to die. It applied a seccomp filter by now, and it
                    // turns out we will not be able to read any syscall arguments.
                    // We need to kill it right now to avoid it remaining blocked forever.
                    // FIXME: kill worker
                    // TODO: retry from the beginning, without using /proc/x/mem?
                    return Err(format!(
                        "Unable to open process memory after execve(): {}",
                        e
                    ));
                }
            }
        } else {
            None
        };

        // If the worker was supposed to try seccomp user notification and failed,
        // fallback on seccomp-trap: compile a filter and schedule it to be loaded
        // as a late mitigation
        let seccomp_trap_bpf = match (
            process.proc_mem.read(),
            process.seccomp_unotify_thread.read(),
            generate_seccomp_filter(false),
        ) {
            (Ok(proc_mem), _, _) if proc_mem.is_none() => None,
            (Err(_), _, _) => None,
            (_, Ok(unotify_thread), _) if unotify_thread.is_some() => {
                None // no need, seccomp user notification filter already installed
            }
            (_, _, Err(e)) => {
                println!(
                    " [!] Cannot use seccomp trap mitigation: unable to compile filter ({})",
                    e
                );
                None
            }
            (Ok(_), _, Ok(filter)) => {
                // We need to give the generated filter to the worker, post-execve().
                match filter.as_bytes() {
                    Ok(v) => Some(v),
                    Err(e) => {
                        println!(
                            " [!] Cannot use seccomp trap mitigation: unable to export filter ({})",
                            e
                        );
                        None
                    },
                }
            }
        };

        // Now that we know which late mitigations need to be applied, start serving
        // IPCs (and not before)
        // Note: this is an OS-specific code to allow processes with seccomp-notify to close their
        // IPC socket after late mitigations are applied.
        broker_pipe.set_remote_process(process.get_pid())?; // set to pass handles later
        let mut broker_pipe = IPCMessagePipe::new_server(broker_pipe, IPCVersion::V1)?;
        let late_mitigations = IPCResponseV1::LateMitigations { seccomp_trap_bpf };
        if let Err(e) = broker_pipe.send(&late_mitigations, None) {
            return Err(format!("Unable to send initial message to worker: {:?}", e));
        }
        let initial_msg = match broker_pipe.recv() {
            Ok(Some(msg)) => msg,
            other => {
                return Err(format!(
                    "Unable to read initial message from worker: {:?}",
                    other
                ))
            }
        };
        match initial_msg {
            IPCRequestV1::ReportLateMitigations { seccomp_trap_bpf } => {
                if let Some(seccomp_trap_bpf) = seccomp_trap_bpf {
                    println!(
                        " [!] Unable to apply seccomp-bpf late mitigation: {:?}",
                        seccomp_trap_bpf
                    );
                }
            }
            other => {
                return Err(format!(
                    "Unexpected initial message from worker: {:?}",
                    other
                ))
            }
        };
        let processref = Arc::clone(&process);
        *(process.ipc_thread.write().unwrap()) = Some(std::thread::spawn(move || {
            loop {
                let req = match broker_pipe.recv() {
                    Ok(Some(req)) => req,
                    Ok(None) => break,
                    Err(e) => panic!("Unable to read IPC message from worker: {}", e),
                };
                let (resp, handle) = match req {
                    IPCRequestV1::Syscall {
                        arch,
                        nr,
                        arg1,
                        arg2,
                        arg3,
                        arg4,
                        arg5,
                        arg6,
                        ip,
                    } => handle_syscall(
                        arch,
                        nr,
                        arg1,
                        arg2,
                        arg3,
                        arg4,
                        arg5,
                        arg6,
                        &processref,
                        ip,
                    ),
                    other => {
                        println!(" [!] Unexpected IPC message from worker: {:?}", other);
                        break;
                    }
                };
                if let Err(e) = broker_pipe.send(&IPCResponseV1::SyscallResult(resp), handle.as_ref()) {
                    panic!("Unable to write IPC message to worker: {}", e);
                }
            }
            println!(" [+] Worker closed its IPC socket, closing IPC thread");
        }));

        println!(
            " [+] Process PID={} execve() successful, running",
            process.get_pid()
        );
        Ok(process)
    }

    fn get_pid(&self) -> u64 {
        self.pid.into()
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
        } else if libc::WIFEXITED(wstatus) {
            Ok(libc::WEXITSTATUS(wstatus).try_into().unwrap())
        } else if libc::WIFSIGNALED(wstatus) {
            Ok((128 + libc::WTERMSIG(wstatus)).try_into().unwrap())
        } else {
            Err(format!(
                "Unexpected waitpid() success with wstatus {}",
                wstatus
            ))
        }
    }
}

impl OSSandboxedProcess {
    pub(crate) fn read_cstring_from_ptr(
        &self,
        ptr: u64,
        max_len: usize,
    ) -> Result<CString, String> {
        let proc_mem = match self.proc_mem.read() {
            Ok(guard) if guard.is_some() => guard,
            _ => return Err("Cannot read from worker memory".to_owned()),
        };
        let proc_mem = proc_mem.as_ref().unwrap();
        // Read at most max_len bytes
        let mut bytes = vec![0u8; max_len];
        match proc_mem.read_at(&mut bytes, ptr) {
            Ok(n) => bytes.truncate(n),
            Err(e) => {
                return Err(format!(
                    "Unable to read from worker memory at address {} : {}",
                    ptr, e
                ))
            }
        };
        // Find the NULL byte in it, if any
        match bytes.iter().position(|b| *b == 0) {
            None => {
                return Err(format!(
                    "No null byte found in the first {} bytes at 0x{:X}",
                    max_len, ptr
                ))
            }
            Some(pos) => bytes.truncate(pos),
        };
        let res = match CString::new(bytes) {
            Ok(s) => s,
            Err(e) => {
                return Err(format!(
                    "Invalid C string read from worker memory at address 0x{:X}: {}",
                    ptr, e
                ))
            }
        };
        Ok(res)
    }
}

fn replace_fd_with_or_dev_null(fd: libc::c_int, replacement: Option<libc::c_int>) {
    unsafe {
        libc::close(fd);
    }
    if let Some(replacement) = replacement {
        let res = unsafe { libc::dup(replacement) };
        if res != fd {
            let errno = Error::last_os_error().raw_os_error().unwrap_or(0);
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

    // Wait for our broker to tell us whether it can read our memory (if it
    // cannot, we cannot use any seccomp filter)
    let broker_can_read_our_memory = match args.sock_seccomp.recv() {
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

    // Cleanup leftover file descriptors from our parent or from code injected into our process
    let dev_null_fd = File::open("/dev/null").expect("unable to open /dev/null");
    let sock_execve_fd = args
        .sock_execve_errno
        .as_handle()
        .as_raw()
        .try_into()
        .unwrap();
    // Get the number of currently opened file descriptors, by setting a soft limit on
    // their number and trying to open one more. If it fails, restart with a higher limit, until it succeeds.
    let mut original_limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let res = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut original_limit as *mut _) };
    if res != 0 {
        let errno = Error::last_os_error().raw_os_error().unwrap_or(0);
        println!(
            " [!] Unable to cleanup inherited file descriptors: getrlimit(RLIMIT_NOFILE) errno {}",
            errno
        );
    } else {
        let mut fd_count = 0;
        loop {
            let mut tmp_limit = original_limit;
            tmp_limit.rlim_cur = fd_count + 1;
            let res = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &tmp_limit as *const _) };
            if res != 0 {
                let errno = Error::last_os_error().raw_os_error().unwrap_or(0);
                println!(" [!] Unable to cleanup inherited file descriptors: setrlimit(RLIMIT_NOFILE) errno {}", errno);
                break;
            }
            let res = unsafe { libc::dup(dev_null_fd.as_raw_fd()) };
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
            let errno = Error::last_os_error().raw_os_error().unwrap_or(0);
            println!(" [!] Unable to cleanup inherited file descriptors: setrlimit(RLIMIT_NOFILE) errno {}", errno);
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
            if fd == sock_execve_fd || args.allowed_file_descriptors.contains(&fd) {
                fd_found += 1;
                continue;
            }
            let res = unsafe { libc::close(fd) };
            if res == 0 {
                fd_found += 1;
                println!(" [+] Cleaned up file descriptor {}", fd);
            } else {
                let errno = Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno != libc::EBADF {
                    // no such file descriptor
                    println!(
                        " [!] Unable to cleanup inherited file descriptors: close({}) errno {}",
                        fd, errno
                    );
                    break;
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
    if let Err(e) = args.sock_execve_errno.send(&errno_bytes, None) {
        eprintln!(
            "Fatal error: failed to report execve() error to broker: {}",
            e
        );
        std::process::exit(errno);
    }
    errno
}
