use core::ffi::c_void;
use core::ptr::null;
use iris_ipc::{IPCMessagePipe, IPCRequest, IPCResponse};
use iris_policy::{CrossPlatformHandle, Handle, Policy};
use libc::c_int;
use seccomp_sys::{
    scmp_arg_cmp, scmp_compare, scmp_filter_attr, seccomp_attr_set, seccomp_init, seccomp_load,
    seccomp_release, seccomp_rule_add, seccomp_syscall_resolve_name, SCMP_ACT_ALLOW, SCMP_ACT_TRAP,
    __NR_SCMP_ERROR,
};
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard};

const SYS_SECCOMP: i32 = 1;

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

// Current working directory is permanently set to an empty directory,
// and workers cannot set it (to avoid side effects, such as coredump creation in cwd)
static mut PROCESS_EMULATED_CWD: Option<Arc<RwLock<String>>> = None;
fn set_cwd(path: &str) {
    *(unsafe { PROCESS_EMULATED_CWD.as_deref().unwrap() }
        .write()
        .unwrap()) = path.to_owned();
}
fn get_cwd() -> RwLockReadGuard<'static, String> {
    unsafe { PROCESS_EMULATED_CWD.as_deref().unwrap() }
        .read()
        .unwrap()
}

// TODO: use a thread_local!{} pipe, and a global mutex-protected pipe to request new thread-specific ones
// OR: create a global pool of threads which wait on a global lock-free queue
// AND/OR: make the ipc pipe multiplexed by adding random transaction IDs
static mut IPC_PIPE_SINGLETON: *const Mutex<IPCMessagePipe> = null();
fn get_ipc_pipe() -> MutexGuard<'static, IPCMessagePipe> {
    unsafe { (*IPC_PIPE_SINGLETON).lock().unwrap() }
}

fn get_fd_for_path_with_perms(
    path: &str,
    read: bool,
    write: bool,
    append_only: bool,
) -> Result<Handle, i64> {
    let request = IPCRequest::OpenFile {
        path: path.to_owned(),
        read,
        write,
        append_only,
    };
    match send_recv(&request, None) {
        (IPCResponse::GenericCode(_), Some(fd)) => Ok(fd),
        (IPCResponse::GenericCode(code), None) if code < 0 => Err(code),
        err => panic!("Unexpected response from broker to file request: {:?}", err),
    }
}

fn get_fd_for_path(path: &str) -> Result<Handle, i64> {
    let err = match get_fd_for_path_with_perms(path, true, false, false) {
        Ok(fd) => return Ok(fd),
        Err(e) => e,
    };
    if let Ok(fd) = get_fd_for_path_with_perms(path, false, false, true) {
        return Ok(fd);
    }
    Err(err)
}

pub(crate) fn lower_final_sandbox_privileges(_policy: &Policy, ipc: IPCMessagePipe) {
    // Initialization of globals. This is safe as long as we are only called once
    unsafe {
        // Store the emulated current working directory
        PROCESS_EMULATED_CWD = Some(Arc::new(RwLock::new("/".to_owned())));
        // Store the IPC pipe to handle all future syscall requests
        IPC_PIPE_SINGLETON = Box::leak(Box::new(Mutex::new(ipc))) as *const _;
    }
    // Set our own SIGSYS handler
    let mut empty_signal_set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut empty_signal_set as *mut _) };
    let new_sigaction = libc::sigaction {
        sa_sigaction: sigsys_handler as usize,
        sa_mask: empty_signal_set,
        sa_flags: libc::SA_SIGINFO,
        sa_restorer: None,
    };
    let mut old_sigaction = libc::sigaction {
        sa_sigaction: 0,
        sa_mask: empty_signal_set,
        sa_flags: 0,
        sa_restorer: None,
    };
    let res = unsafe {
        libc::sigaction(
            libc::SIGSYS,
            &new_sigaction as *const _,
            &mut old_sigaction as *mut _,
        )
    };
    if res != 0 {
        panic!(
            "sigaction(SIGSYS) failed with error {}",
            std::io::Error::last_os_error()
        );
    }
    if old_sigaction.sa_sigaction != libc::SIG_DFL && old_sigaction.sa_sigaction != libc::SIG_IGN {
        println!(" [!] SIGSYS handler overwritten, the worker process might fail unexpectedly");
    }

    let res = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if res != 0 {
        panic!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed with error {}",
            std::io::Error::last_os_error()
        );
    }

    let filter = unsafe { seccomp_init(SCMP_ACT_TRAP) };
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

    let res = unsafe { seccomp_load(filter) };
    if res != 0 {
        panic!("seccomp_load() failed with error {}", -res);
    }

    unsafe { seccomp_release(filter) };
    println!("OK");
}

pub(crate) fn get_syscall_number(name: &str) -> Result<i32, String> {
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

// FIXME: replace this static lifetime with the lifetime of an additional "syscall context" parameter
/*
fn read_cstring_from_ptr(ptr: i64) -> &'static CStr {
    unsafe {
        CStr::from_ptr(ptr as *const _)
    }
}
*/

fn read_string_from_ptr(ptr: i64) -> Option<&'static str> {
    let cstr = unsafe { CStr::from_ptr(ptr as *const _) };
    let utf8 = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => return None,
    };
    Some(utf8)
}

fn read_i64_from_ptr(ucontext: *mut libc::ucontext_t, registry: libc::c_int) -> i64 {
    unsafe { (*ucontext).uc_mcontext.gregs[registry as usize] }
}

pub(crate) extern "C" fn sigsys_handler(
    signal_no: c_int,
    siginfo: *const libc::siginfo_t,
    ucontext: *const c_void,
) {
    // Be very careful when modifying this function: it *cannot* use
    // any syscall except those directly explicitly allowed by our
    // seccomp filter
    if signal_no != libc::SIGSYS {
        return;
    }
    let siginfo = unsafe { *siginfo };
    // Ignore signals other than thread-directed seccomp signals sent by the kernel
    if siginfo.si_code != SYS_SECCOMP {
        return;
    }

    let ucontext = ucontext as *mut libc::ucontext_t;
    let syscall_nr = read_i64_from_ptr(ucontext, libc::REG_RAX);
    let a0 = read_i64_from_ptr(ucontext, libc::REG_RDI);
    let a1 = read_i64_from_ptr(ucontext, libc::REG_RSI);
    let a2 = read_i64_from_ptr(ucontext, libc::REG_RDX);
    let a3 = read_i64_from_ptr(ucontext, libc::REG_R10);
    let a4 = read_i64_from_ptr(ucontext, libc::REG_R8);
    let a5 = read_i64_from_ptr(ucontext, libc::REG_R9);
    let msg = format!(
        " [.] Syscall nr={} ({}, {}, {}, {}, {}, {}) intercepted by seccomp-trap\n",
        syscall_nr, a0, a1, a2, a3, a4, a5
    );
    unsafe { libc::write(2, msg.as_ptr() as *const _, msg.len()) };

    let response_code = match syscall_nr {
        libc::SYS_access => {
            let (path, mode) = (read_string_from_ptr(a0), a1 as i32);
            if let Some(path) = path {
                handle_access(path, mode)
            } else {
                -(libc::ENOENT as i64)
            }
        }
        //libc::SYS_bind => {
        //},
        libc::SYS_chdir => {
            let path = read_string_from_ptr(a0);
            if let Some(path) = path {
                handle_chdir(path)
            } else {
                -(libc::ENOENT as i64)
            }
        }
        /*
                libc::SYS_connect => {
                },
                libc::SYS_creat => {
                },
                libc::SYS_faccessat => {
                },
                libc::SYS_faccessat2 => {
                },
                libc::SYS_stat => {
                },
                // TODO: emulate SYS_capset to be a no-op?
                libc::SYS_capget => {
                    // TODO: limit on broker side hdrp->pid == worker->pid (otherwise, allows leaking info about non-sandboxed processes
                }
        */
        // TODO: SYS_add_key KEY_SPEC_THREAD_KEYRING, KEY_SPEC_PROCESS_KEYRING
        // TODO: kill(): redirect 0 and -1 to getpid() and restart syscall, brokerize others with dedicated IPCRequest::SendSignal(pid, sig)
        // TODO: openat2()
        // TODO: mkdir()
        // TODO: truncate(), truncate64()
        // TODO: socket(), bind(), listen(), accept()
        libc::SYS_open => {
            let (path, flags, mode) = (read_string_from_ptr(a0), a1 as i32, a2 as i32);
            if let Some(path) = path {
                handle_openat(libc::AT_FDCWD, path, flags, mode)
            } else {
                -(libc::ENOENT as i64)
            }
        }
        libc::SYS_openat => {
            // TODO: resolve the file descriptor or CWD if given as argument and path isn't absolute.
            // /!\ readlink(/proc/self/fd/%d) might not be up to date: may have been moved after being opened. Use fstat(fd)?
            let (dirfd, path, flags, mode) =
                (a0 as i32, read_string_from_ptr(a1), a2 as i32, a3 as i32);
            if let Some(path) = path {
                handle_openat(dirfd, path, flags, mode)
            } else {
                -(libc::ENOENT as i64)
            }
        }
        _ => {
            println!(" [!] Syscall not supported yet, denied by default");
            -(libc::EPERM as i64)
        }
    };
    println!(" [.] Syscall result: {}", response_code);
    unsafe {
        (*ucontext).uc_mcontext.gregs[libc::REG_RAX as usize] = response_code;
    }
}

fn send_recv(request: &IPCRequest, handle: Option<&Handle>) -> (IPCResponse, Option<Handle>) {
    let mut pipe = get_ipc_pipe();
    pipe.send(&request, handle)
        .expect("unable to send IPC request to broker");
    let (resp, handle) = pipe
        .recv_with_handle()
        .expect("unable to receive IPC response from broker");
    let resp = resp.expect("broker closed our IPC pipe while expecting its response");
    (resp, handle)
}

fn handle_openat(dirfd: libc::c_int, path: &str, flags: libc::c_int, _mode: libc::c_int) -> i64 {
    if dirfd != libc::AT_FDCWD {
        return -(libc::EINVAL as i64);
    }
    if path.is_empty() {
        return -(libc::ENOENT as i64);
    }
    println!(
        " [.] Requesting access to file path {:?} (flags={})",
        path, flags
    );
    // If path is relative, prepend the process CWD.
    let mut path = path.to_owned();
    if path.chars().next() != Some('/') {
        path = get_cwd().clone() + "/" + &path;
    }
    let request = IPCRequest::OpenFile {
        path,
        read: (flags & (libc::O_WRONLY)) == 0 && (flags & (libc::O_PATH)) == 0,
        write: (flags & (libc::O_WRONLY | libc::O_RDWR)) != 0 && (flags & (libc::O_PATH)) == 0,
        append_only: (flags & libc::O_APPEND) != 0 && (flags & (libc::O_PATH)) == 0,
    };
    // TODO: if O_CREAT, creat it (careful with O_EXCL). Enforce NX for everyone and NR+NW for
    // others when using the `mode` provided by workers.
    // TODO: if O_TRUNC, ftruncate() it. But ftruncate() allows bypassing O_APPEND, so add truncate: bool to OpenFile requests
    match send_recv(&request, None) {
        (IPCResponse::GenericCode(_), Some(handle)) => {
            unsafe { handle.into_raw() }.try_into().unwrap()
        }
        (IPCResponse::GenericCode(code), None) => code,
        other => panic!(
            "Unexpected response from broker to file request: {:?}",
            other
        ),
    }
}

fn handle_access(path: &str, mode: libc::c_int) -> i64 {
    println!(" [.] access({:?}, {}) called", path, mode);
    // Workers cannot execute anything anyway
    if (mode & libc::X_OK) != 0 {
        -(libc::EACCES as i64)
    }
    // To check for file existence, check for read-only first
    else if mode == libc::F_OK {
        match get_fd_for_path(path) {
            Ok(_) => 0,
            Err(e) => e,
        }
    }
    // Checking for read or write access, specifically
    else {
        let read = (mode & (libc::R_OK)) != 0;
        let write = (mode & libc::W_OK) != 0;
        match get_fd_for_path_with_perms(path, read, write, false) {
            Ok(_) => 0,
            Err(e) => e,
        }
    }
}

fn handle_chdir(path: &str) -> i64 {
    println!(
        " [.] chdir({:?}) called, emulating it without syscall...",
        path
    );
    set_cwd(path);
    0
}