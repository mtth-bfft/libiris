use crate::os::brokered_syscalls::handle_syscall;
use crate::os::seccomp::SeccompFilter;
use crate::process::CrossPlatformSandboxedProcess;
use core::ffi::c_void;
use core::ptr::{null, null_mut};
use iris_ipc::{
    CrossPlatformMessagePipe, IPCMessagePipe, IPCRequestV1, IPCResponseV1, IPCVersion, MessagePipe,
};
use iris_policy::{CrossPlatformHandle, Handle, Policy};
use libc::c_int;
use seccomp_sys::{
    scmp_arg_cmp, scmp_compare, seccomp_export_bpf, seccomp_load, seccomp_notif,
    seccomp_notif_resp, seccomp_notify_alloc, seccomp_notify_fd, seccomp_notify_id_valid,
    seccomp_notify_receive, seccomp_notify_respond, seccomp_rule_add, seccomp_syscall_resolve_name,
    SCMP_ACT_ALLOW, SCMP_ACT_NOTIFY, SCMP_ACT_TRAP, __NR_SCMP_ERROR,
};
use std::convert::{TryFrom, TryInto};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Error, Read, Seek, SeekFrom};
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;

// Missing from libseccomp (for now)
#[repr(C)]
struct seccomp_notif_addfd {
    id: u64,          // Cookie value
    flags: u32,       // Flags
    srcfd: u32,       // Local file descriptor number
    newfd: u32,       // 0 or desired file descriptor number in target
    newfd_flags: u32, // Flags to set on target file descriptor
}
const SECCOMP_IOCTL_NOTIF_ADDFD: u64 = 0x40182103;

const DEFAULT_CLONE_STACK_SIZE: usize = 1 * 1024 * 1024;
const MAGIC_VALUE_TO_READ_FROM_BROKER: [u8; 29] = *b"I AM A LIBIRIS WORKER PROCESS";
const SYSCALLS_ALLOWED_BY_DEFAULT: [&str; 62] = [
    "read",
    "write",
    "readv",
    "writev",
    "recvmsg",
    "sendmsg",
    "futex",
    "clock_nanosleep",
    "nanosleep",
    "poll",
    "select",
    "_newselect",
    "fstat",
    "tee",
    "lseek",
    "_llseek",
    "accept",
    "accept4",
    //"ftruncate", disallowed to prevent truncation of O_APPEND files
    "close",
    "sched_yield",
    "getpid",
    "gettid",
    "get_robust_list",
    "getresuid",
    "getresgid",
    "getresuid32",
    "getresgid32",
    "getrandom",
    "getuid",
    "getuid32",
    "memfd_create",
    "mmap", // Note: blocking dynamic executable memory allocation is done via a late mitigation
    // because there is no way to mmap into another process, so there is no way to
    // make mmap a broker-handled syscall
    "mprotect",
    "munmap",
    "fchdir",
    "exit_group",
    "restart_syscall",
    "rt_sigreturn",
    "rt_sigaction", // FIXME: should really be handled separately, to hook rt_sigaction(SIGSYS,..)
    "sigaltstack",
    "alarm",
    "arch_prctl",
    "brk",
    "cacheflush",
    "close_range",
    //"clone",  // Note: should only allow thread creation within the same namespaces,
    // but argument order depends on Linux build configuration.
    "readdir",
    "shutdown",
    "timer_create",
    "timer_delete",
    "timer_getoverrun",
    "timer_gettime",
    "timer_settime",
    "timerfd_create",
    "timerfd_gettime",
    "timerfd_settime",
    "times",
    "time",
    "uname",
    "nice",
    "set_robust_list",
    "set_tid_address",
    "pause",
];

pub(crate) struct OSSandboxedProcess {
    pid: u32,
    pub(crate) policy: Policy,
    // Thread stack for clone(2), flagged as "never read" because rust does not
    // know about the thread created unsafely
    #[allow(dead_code)]
    initial_thread_stack: Vec<u8>,
    // File descriptor to /proc/x/mem to read syscall arguments from memory
    proc_mem: Option<File>,
    // Thread which will handle seccomp user notifications
    seccomp_unotify_thread: RwLock<Option<JoinHandle<()>>>,
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
        let can_read_worker_mem = match File::open(format!("/proc/{}/mem", worker_pid)) {
            Ok(f) => {
                let mut buffer = vec![0u8; std::mem::size_of_val(&MAGIC_VALUE_TO_READ_FROM_BROKER)];
                let ptr = (&MAGIC_VALUE_TO_READ_FROM_BROKER as *const _) as u64;
                if let Err(e) = f.read_exact_at(&mut buffer, ptr) {
                    println!(" [!] Unable to read from worker process memory: {}", e);
                    false
                } else if &buffer[..] != MAGIC_VALUE_TO_READ_FROM_BROKER {
                    println!(" [!] Unexpected value read from worker process memory {:?} , expected {:?}", buffer, &MAGIC_VALUE_TO_READ_FROM_BROKER);
                    false
                } else {
                    println!(" [.] Will use seccomp user notifications for sandboxing");
                    true
                }
            }
            Err(e) => {
                println!(
                    " [!] Cannot use seccomp mitigations: unable to open worker process memory, {}",
                    e
                );
                false
            }
        };
        // Send that info to the worker, so it knows whether it can apply a seccomp filter
        // Note: it's okay not to use a well-defined and versionned IPC here, since this is
        // sent and received by the same executable.
        if let Err(e) = sock_seccomp_parent.send(&[can_read_worker_mem as u8], None) {
            return Err(format!(
                "Unable to send seccomp status to worker process: {}",
                e
            ));
        }

        // Wait for the worker to execve(), and re-open the file descriptor to
        // /proc/worker_pid/mem (the file descriptor opened just above was just to check
        // if /proc/ is mounted and the ptrace() check on /proc/worker_pid/mem allows us
        // to read its memory. The file descriptor obtained will become invalid as soon as
        // the worker runs execve()).
        if let Ok(v) = sock_exec_parent.recv() {
            if v.len() > 0 {
                return Err(format!(
                    "execve() failed with code {}",
                    u32::from_be_bytes(v.try_into().unwrap_or([0u8; 4]))
                ));
            }
        }
        // Acquire a definitive file descriptor to /proc/worker_pid/mem (if it worked the
        // first time)
        let proc_mem = if can_read_worker_mem {
            match File::open(format!("/proc/{}/mem", worker_pid)) {
                Ok(f) => Some(f),
                Err(e) => {
                    // Process is doomed to die. It applied a seccomp filter by now, and it
                    // turns out we will not be able to read any syscall arguments.
                    // We need to kill it right now to avoid it remaining blocked forever.
                    // FIXME: kill worker
                    // FIXME: retry from the beginning, without using /proc/x/mem?
                    return Err(format!(
                        "Unable to open process memory after execve(): {}",
                        e
                    ));
                }
            }
        } else {
            None
        };

        // Construct the resulting new worker object
        // (as an Arc<> because we might need to keep a reference in the IPC and seccomp-unotify thread)
        let process = Arc::new(Self {
            pid: worker_pid.try_into().unwrap(),
            policy,
            initial_thread_stack: stack,
            proc_mem,
            ipc_thread: RwLock::new(None),
            seccomp_unotify_thread: RwLock::new(None),
        });
        let processref = Arc::clone(&process);

        // Now that we can pass Arc<> references to our Process struct, wait for the worker
        // to tell us if it succeeded in applying a seccomp user notification filter, so that
        // we can spawn a dedicated thread holding an Arc<> to read its memory
        match sock_seccomp_parent.recv_with_handle() {
            Ok((_, Some(notify_fd))) => {
                println!(" [+] Received seccomp user notification fd {:?}", notify_fd);
                let processref = Arc::clone(&process);
                *(process.seccomp_unotify_thread.write().unwrap()) = Some(std::thread::spawn(
                    move || {
                        // TODO: handle panics in this thread, kill the worker on break; and clean up
                        let mut req: *mut seccomp_notif = null_mut();
                        let mut resp: *mut seccomp_notif_resp = null_mut();
                        let res = unsafe {
                            seccomp_notify_alloc(
                                &mut req as *mut *mut seccomp_notif,
                                &mut resp as *mut *mut seccomp_notif_resp,
                            )
                        };
                        if res != 0 {
                            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                            panic!(
                                "seccomp_notify_alloc() failed with error {} (errno {})",
                                res, errno
                            );
                        }
                        loop {
                            // seccomp_notify_receive() requires the notification struct to be zeroed
                            unsafe {
                                core::ptr::write_bytes(
                                    req as *mut u8,
                                    0u8,
                                    std::mem::size_of::<seccomp_notif>(),
                                );
                            }
                            let res = unsafe {
                                seccomp_notify_receive(notify_fd.as_raw().try_into().unwrap(), req)
                            };
                            if res != 0 {
                                let errno =
                                    std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                                panic!(
                                    "seccomp_notify_receive() failed with error {} (errno {})",
                                    res, errno
                                );
                            }
                            let cookie = unsafe { (*req).id }; // to allow the kernel to match the response to the request
                            let ip = unsafe { (*req).data.instruction_pointer };
                            let arch = unsafe { (*req).data.arch };
                            let nr = unsafe { (*req).data.nr as u64 };
                            let arg1 = unsafe { (*req).data.args[0] };
                            let arg2 = unsafe { (*req).data.args[1] };
                            let arg3 = unsafe { (*req).data.args[2] };
                            let arg4 = unsafe { (*req).data.args[3] };
                            let arg5 = unsafe { (*req).data.args[4] };
                            let arg6 = unsafe { (*req).data.args[5] };
                            // FIXME: need to dereference memory here, then check that the notif cookie is
                            // still valid. Otherwise, the syscall may actually have been cancelled by a
                            // signal, and the arguments we read from memory were garbage e.g. from the signal
                            // handler stack.
                            let code = match handle_syscall(
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
                            ) {
                                (code, None) => code,
                                (_, Some(handle)) => {
                                    let addfd = seccomp_notif_addfd {
                                        id: cookie,
                                        flags: 0,
                                        srcfd: handle.as_raw().try_into().unwrap(),
                                        newfd: 0,
                                        newfd_flags: (libc::O_CLOEXEC as u32),
                                    };
                                    let res = unsafe {
                                        libc::ioctl(
                                            notify_fd.as_raw().try_into().unwrap(),
                                            SECCOMP_IOCTL_NOTIF_ADDFD,
                                            &addfd as *const seccomp_notif_addfd,
                                        )
                                    };
                                    if res < 0 {
                                        let errno = std::io::Error::last_os_error()
                                            .raw_os_error()
                                            .unwrap_or(0);
                                        panic!("Spurious syscall response failure: SECCOMP_IOCTL_NOTIF_ADDFD failed (errno {})", errno);
                                    }
                                    res.into() // file descriptor number in the remote process
                                }
                            };
                            unsafe {
                                core::ptr::write_bytes(
                                    resp as *mut u8,
                                    0u8,
                                    std::mem::size_of::<seccomp_notif_resp>(),
                                );
                            }
                            unsafe {
                                (*resp).id = cookie;
                            }
                            if code >= 0 {
                                // success value
                                unsafe {
                                    (*resp).val = code;
                                }
                            } else {
                                // failure code
                                unsafe {
                                    (*resp).error = code as i32;
                                }
                            }
                            let res = unsafe {
                                seccomp_notify_respond(notify_fd.as_raw().try_into().unwrap(), resp)
                            };
                            if res != 0 {
                                let errno =
                                    std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                                let exists = unsafe {
                                    seccomp_notify_id_valid(
                                        notify_fd.as_raw().try_into().unwrap(),
                                        (*req).id,
                                    )
                                };
                                if exists != -(libc::ENOENT) {
                                    println!(" [!] Spurious syscall response failure: seccomp_notify_respond() failed with code {} (errno {})", res, errno);
                                }
                            }
                        }
                    },
                ));
            }
            Ok((v, None)) => {
                let error = i32::from_be_bytes(v.try_into().unwrap_or([0, 0, 0, 0]));
                println!(
                    " [!] Cannot use seccomp user notification mitigation: error {}",
                    error
                );
            }
            Err(e) => {
                println!(
                    " [!] Cannot use seccomp user notification mitigation: {}",
                    e
                );
            }
        };

        // If the worker was supposed to try seccomp user notification and failed,
        // fallback on seccomp-trap: compile a filter and schedule it to be loaded
        // as a late mitigation
        let seccomp_trap_bpf = match (
            &process.proc_mem,
            process.seccomp_unotify_thread.read(),
            generate_seccomp_filter(SCMP_ACT_TRAP),
        ) {
            (None, _, _) => None,
            (_, Ok(guard), _) if guard.is_some() => {
                None // no need, seccomp user notification filter already installed
            }
            (_, _, Err(e)) => {
                println!(
                    " [!] Cannot use seccomp trap mitigation: unable to compile filter ({})",
                    e
                );
                None
            }
            (Some(_), _, Ok(filter)) => {
                // We need to give the generated filter to the worker, post-execve().
                // Note: Saving to an ephemeral file is convoluted, but it's
                // the only BPF export function from libseccomp as of today.
                let mut tmp_fd_path = CString::new("/tmp/iris_seccomp_XXXXXX")
                    .unwrap()
                    .into_bytes_with_nul();
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
                        println!(
                            " [!] Unable to clean up tmp file {}",
                            std::str::from_utf8(&tmp_fd_path).unwrap_or("<?>")
                        );
                    }
                    let res = unsafe { seccomp_export_bpf(filter.context, tmp_fd.as_raw_fd()) };
                    if res != 0 {
                        println!(" [!] Cannot use seccomp-trap mitigation: seccomp_export_bpf() failed (error {})", res);
                        None
                    } else {
                        // Converting to a File here is safe as long as we take full ownership of the file
                        if let Err(e) = tmp_fd.seek(SeekFrom::Start(0)) {
                            println!(
                                " [!] Cannot use seccomp-trap mitigation: lseek() failed ({})",
                                e
                            );
                            None
                        } else {
                            let mut bpf = vec![];
                            if let Err(e) = tmp_fd.read_to_end(&mut bpf) {
                                println!(
                                    " [!] Cannot use seccomp-trap mitigation: read() failed ({})",
                                    e
                                );
                                None
                            } else {
                                Some(bpf)
                            }
                        }
                    }
                } else {
                    println!(
                        " [!] Cannot use seccomp-trap mitigation: mkstemp() failed (errno {})",
                        Error::last_os_error().raw_os_error().unwrap_or(0)
                    );
                    None
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
                if let Err(e) = broker_pipe.send(&resp, handle.as_ref()) {
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
        let proc_mem = match &self.proc_mem {
            Some(f) => f,
            None => return Err("Cannot read from worker memory".to_owned()),
        };
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
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
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
    let filter = SeccompFilter::new(default_action)?;
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

    // When filtering through user notifications, we do not rely on signals
    // and can let the process do whatever it wants with them
    if default_action == SCMP_ACT_NOTIFY {
        let syscall_name = "rt_sigprocmask";
        match get_syscall_number(&syscall_name) {
            Ok(syscall_nr) => {
                println!(" [.] Allowing syscall {} / {}", syscall_name, syscall_nr);
                let res =
                    unsafe { seccomp_rule_add(filter.context, SCMP_ACT_ALLOW, syscall_nr, 0) };
                if res != 0 {
                    return Err(format!(
                        "seccomp_rule_add(SCMP_ACT_ALLOW, {}) failed with code {}",
                        syscall_name, -res
                    ));
                }
            }
            Err(e) => {
                eprintln!(" [.] Unable to find syscall {} : {}", syscall_name, e);
            }
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
    let res = unsafe {
        seccomp_rule_add(
            filter.context,
            SCMP_ACT_ALLOW,
            syscall_nr,
            1,
            a0_pid_comparator,
        )
    };
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
    let res = unsafe {
        seccomp_rule_add(
            filter.context,
            SCMP_ACT_ALLOW,
            syscall_nr,
            1,
            a0_pid_comparator,
        )
    };
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
    let res = unsafe {
        seccomp_rule_add(
            filter.context,
            SCMP_ACT_ALLOW,
            syscall_nr,
            1,
            a0_pid_comparator,
        )
    };
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
    let res = unsafe {
        seccomp_rule_add(
            filter.context,
            SCMP_ACT_ALLOW,
            syscall_nr,
            1,
            a0_tid_comparator,
        )
    };
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
    let res = unsafe {
        seccomp_rule_add(
            filter.context,
            SCMP_ACT_ALLOW,
            syscall_nr,
            1,
            a0_tid_comparator,
        )
    };
    if res != 0 {
        panic!("seccomp_rule_add(SCMP_ACT_ALLOW, sched_getaffinity, SCMP_A0(SCMP_CMP_EQ, gettid())) failed with code {}", -res);
    }
    let a0_zero_comparator = scmp_arg_cmp {
        arg: 0, // first syscall argument
        op: scmp_compare::SCMP_CMP_EQ,
        datum_a: 0, // 0 == ourselves, our PID
        datum_b: 0, // unused with SCMP_CMP_EQ
    };
    let res = unsafe {
        seccomp_rule_add(
            filter.context,
            SCMP_ACT_ALLOW,
            syscall_nr,
            1,
            a0_zero_comparator,
        )
    };
    if res != 0 {
        panic!("seccomp_rule_add(SCMP_ACT_ALLOW, sched_getaffinity, SCMP_A0(SCMP_CMP_EQ, 0)) failed with code {}", -res);
    }

    // Add special case handling for execve(), only if we're using user notifications.
    // Since we apply the filter before execve(), we need to allow it to run, and then forbid it
    // from within the worker process (post-execve) with a second filter
    if default_action == SCMP_ACT_NOTIFY {
        for syscall_name in &["execve", "execveat"] {
            let syscall_nr = get_syscall_number(syscall_name).unwrap();
            println!(
                " [.] Allowing syscall {} / {} temporarily for process startup",
                syscall_name, syscall_nr
            );
            let res = unsafe { seccomp_rule_add(filter.context, SCMP_ACT_ALLOW, syscall_nr, 0) };
            if res != 0 {
                return Err(format!(
                    "seccomp_rule_add(SCMP_ACT_ALLOW, {}) failed with code {}",
                    syscall_name, -res
                ));
            }
        }
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
        }
    };

    if broker_can_read_our_memory {
        // Compile a seccomp user notification filter for this worker
        if let Ok(filter) = generate_seccomp_filter(SCMP_ACT_NOTIFY) {
            let res: i32 = unsafe { seccomp_load(filter.context) };
            if res != 0 {
                if let Err(e) = args.sock_seccomp.send(&res.to_be_bytes(), None) {
                    panic!("Unable to send seccomp error code to broker: {}", e);
                }
            } else {
                // Note: at this point, we're fully committed to seccomp-unotify.
                // If something fails, the process is doomed to hang as soon as we
                // issue an unauthorized syscall. Better to crash than to hang.
                let notify_fd = unsafe {
                    let res = seccomp_notify_fd(filter.context);
                    if res < 0 {
                        eprintln!("Fatal error: seccomp_notify_fd() failed with error {}", res);
                        std::process::abort(); // don't panic!() which unwinds
                    }
                    Handle::new(res.try_into().unwrap()).unwrap()
                };
                // Send the file descriptor to our parent so that it can receive notifications
                if let Err(e) = args.sock_seccomp.send(&[], Some(&notify_fd)) {
                    eprintln!(
                        "Fatal error: unable to send seccomp notify handle to broker: {}",
                        e
                    );
                    std::process::abort(); // don't panic!() which unwinds
                }
            }
        }
    }

    // Cleanup leftover file descriptors from our parent or from code injected into our process
    let tolerate_sock_execve_errno = args
        .sock_execve_errno
        .as_handle()
        .as_raw()
        .try_into()
        .unwrap();
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
                && fd != tolerate_sock_execve_errno
                && !args.allowed_file_descriptors.contains(&fd)
            {
                println!(
                    " [.] Cleaning up file descriptor {} ({})",
                    fd,
                    path.to_string_lossy()
                );
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
    if let Err(e) = args.sock_execve_errno.send(&errno_bytes, None) {
        eprintln!(
            "Fatal error: failed to report execve() error to broker: {}",
            e
        );
        std::process::exit(errno);
    }
    errno
}
