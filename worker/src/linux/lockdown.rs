use core::ffi::c_void;
use core::ptr::null;
use iris_ipc::{IPCMessagePipe, IPCRequest, IPCResponse, IPC_SECCOMP_CALL_SITE_PLACEHOLDER};
use iris_policy::{CrossPlatformHandle, Handle};
use libc::{c_char, c_int, O_PATH};
use log::{debug, info};
use std::borrow::BorrowMut;
use std::convert::TryInto;
use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

const SYS_SECCOMP: i32 = 1;

static AUDIT_ONLY_MODE: AtomicBool = AtomicBool::new(false);

thread_local! {
    static IN_SIGSYS_HANDLER: bool = false;
}

// TODO: use a thread_local!{} pipe, and a global mutex-protected pipe to request new thread-specific ones
// OR: create a global pool of threads which wait on a global lock-free queue
// AND/OR: make the ipc pipe multiplexed by adding random transaction IDs
static mut IPC_PIPE_SINGLETON: *const Mutex<IPCMessagePipe> = null();
fn get_ipc_pipe() -> MutexGuard<'static, IPCMessagePipe> {
    unsafe { (*IPC_PIPE_SINGLETON).lock().unwrap() }
}

fn get_fd_for_path_with_perms(path: &str, flags: c_int) -> Result<Handle, i64> {
    let request = IPCRequest::OpenFile {
        path: path.to_owned(),
        flags,
    };
    match send_recv(&request, None) {
        (IPCResponse::SyscallResult(_), Some(fd)) => Ok(fd),
        (IPCResponse::SyscallResult(code), None) if code < 0 => Err(code),
        err => panic!("Unexpected response from broker to file request: {err:?}"),
    }
}

pub(crate) fn lower_final_sandbox_privileges(ipc: IPCMessagePipe) {
    // Initialization of globals. This is safe as long as we are only called once
    unsafe {
        // Store the IPC pipe to handle all future syscall requests
        IPC_PIPE_SINGLETON = Box::leak(Box::new(Mutex::new(ipc))) as *const _;
    }

    get_ipc_pipe()
        .send(&IPCRequest::InitializationRequest, None)
        .expect("unable to send IPC message to broker");
    let resp = get_ipc_pipe()
        .recv()
        .expect("unable to read worker policy from broker");
    let (policy, mut seccomp_filter) = match resp {
        Some(IPCResponse::InitializationResponse {
            policy_applied,
            seccomp_filter_to_apply,
        }) => (policy_applied, seccomp_filter_to_apply),
        other => panic!("unexpected initial response received from broker: {other:?}"),
    };

    if policy.is_audit_only() {
        AUDIT_ONLY_MODE.store(true, Ordering::Relaxed);
    }

    if seccomp_filter.is_empty() {
        info!("No seccomp filter to load");
    } else {
        // TODO: use seccomp user notifications instead, when supported by the kernel + libseccomp
        // Set our own SIGSYS handler
        let mut empty_signal_set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigemptyset(&mut empty_signal_set as *mut _) };
        let new_sigaction = libc::sigaction {
            sa_sigaction: sigsys_handler as usize,
            sa_mask: empty_signal_set,
            // Do not mask SIGSYS when in the handler, thanks to SA_NODEFER.
            // We could leave it masked, and recurse infinitely if our handler triggers
            // a syscall again, but crashing with a stack overflow is harder to debug than
            // a panic!() with a clear error message and stack trace.
            sa_flags: libc::SA_SIGINFO | libc::SA_NODEFER,
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
        if old_sigaction.sa_sigaction != libc::SIG_DFL
            && old_sigaction.sa_sigaction != libc::SIG_IGN
        {
            panic!("SIGSYS handler is already used by something else, cannot use seccomp-bpf");
        }
        if AUDIT_ONLY_MODE.load(Ordering::Relaxed) {
            let actual_call_site: usize =
                (rerun_syscall as *const u8 as usize) + SYSCALL_ASM_OFFSET;
            debug!("Audit mode: allowing all system calls from call site {actual_call_site:#X}");
            // Replace the placeholder inserted by our broker, in a platform
            // endianness independent way
            let bytes = u64::to_ne_bytes(actual_call_site as u64);
            let actual_first = [bytes[0], bytes[1], bytes[2], bytes[3]];
            let actual_second = [bytes[4], bytes[5], bytes[6], bytes[7]];
            let bytes = u64::to_ne_bytes(IPC_SECCOMP_CALL_SITE_PLACEHOLDER);
            let placeholder_first = [bytes[0], bytes[1], bytes[2], bytes[3]];
            let placeholder_second = [bytes[4], bytes[5], bytes[6], bytes[7]];
            let mut start = 0;
            while start + 4 < seccomp_filter.len() {
                if seccomp_filter[start..start + 4] == placeholder_first {
                    seccomp_filter[start..start + 4].clone_from_slice(&actual_first);
                }
                if seccomp_filter[start..start + 4] == placeholder_second {
                    seccomp_filter[start..start + 4].clone_from_slice(&actual_second);
                }
                start += 1;
            }
        }

        let filter_insn_count = seccomp_filter.len() / std::mem::size_of::<libc::sock_filter>();
        let seccomp_filter = libc::sock_fprog {
            len: filter_insn_count as u16,
            filter: seccomp_filter.as_ptr() as *const _ as *mut _, // doesn't really need *mut
        };
        let res = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &seccomp_filter as *const _,
            )
        };
        if res != 0 {
            panic!(
                "prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) failed with error {}",
                std::io::Error::last_os_error()
            );
        }
        info!(
            "Seccomp filter with {} instructions applied successfully",
            filter_insn_count
        );
    }
}

fn read_string_from_ptr(ptr: *const c_char) -> String {
    unsafe {
        CStr::from_ptr(ptr as *const _)
            .to_string_lossy()
            .to_string()
    }
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
    let ip = read_i64_from_ptr(ucontext, libc::REG_RIP);
    IN_SIGSYS_HANDLER.with(|mut b| {
        if *b {
            panic!(
                "Seccomp signal handler triggered unauthorized syscall {syscall_nr}, this is fatal",
            );
        }
        *b.borrow_mut() = &true;
    });
    // FIXME: make everything below architecture-dependent (read siginfo->arch)
    debug!(
        "Intercepted syscall nr={} ({}, {}, {}, {}, {}, {}) at ip={ip:#X} with seccomp-trap",
        syscall_nr, a0, a1, a2, a3, a4, a5
    );

    let response_code = match syscall_nr {
        // TODO: handle legacy syscall tkill(), needs proxying to parent to check it belongs to the worker
        libc::SYS_access => {
            let (path, mode) = (read_string_from_ptr(a0 as *const c_char), a1 as i32);
            handle_access(&path, mode)
        }
        libc::SYS_stat => {
            let (path, out_ptr) = (
                read_string_from_ptr(a0 as *const c_char),
                a1 as *mut libc::stat,
            );
            handle_stat(&path, out_ptr)
        }
        libc::SYS_open => {
            let (path, flags, mode) = (
                read_string_from_ptr(a0 as *const c_char),
                a1 as i32,
                a2 as i32,
            );
            handle_openat(&path, flags, mode)
        }
        libc::SYS_openat
            if a0 as i32 == libc::AT_FDCWD || unsafe { *(a1 as *const u8) } == b'/' =>
        {
            // Note: the dirfd passed cannot be accurately resolved to a valid path (you can
            // readlink(/proc/self/fd/%d) but it might not be up to date if e.g. the folder has been moved)
            let (path, flags, mode) = (
                read_string_from_ptr(a1 as *const c_char),
                a2 as i32,
                a3 as i32,
            );
            handle_openat(&path, flags, mode)
        }
        libc::SYS_chdir => {
            let path = read_string_from_ptr(a0 as *const c_char);
            handle_chdir(&path)
        }
        other_nb => {
            let ip = read_i64_from_ptr(ucontext, libc::REG_RIP);
            handle_syscall(other_nb, [a0, a1, a2, a3, a4, a5], ip)
        }
    };
    debug!("Syscall result: {}", response_code);
    unsafe {
        (*ucontext).uc_mcontext.gregs[libc::REG_RAX as usize] = response_code;
    }
    IN_SIGSYS_HANDLER.with(|mut b| {
        *b.borrow_mut() = &false;
    });
}

fn send_recv(request: &IPCRequest, handle: Option<&Handle>) -> (IPCResponse, Option<Handle>) {
    let mut pipe = get_ipc_pipe();
    debug!("Sending IPC request {:?}", &request);
    pipe.send(&request, handle)
        .expect("unable to send IPC request to broker");
    let (resp, handle) = pipe
        .recv_with_handle()
        .expect("unable to receive IPC response from broker");
    let resp = resp.expect("broker closed our IPC pipe while expecting its response");
    debug!("Received IPC response {:?}", &resp);
    (resp, handle)
}

fn handle_openat(path: &str, flags: libc::c_int, _mode: libc::c_int) -> i64 {
    // Resolve the path ourselves, brokers only accept nonambiguous absolute paths
    let path = if !path.starts_with('/') {
        let mut abspath = std::env::current_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| String::new());
        if !abspath.ends_with('/') {
            abspath.push('/');
        }
        abspath.push_str(path);
        abspath
    } else {
        path.to_owned()
    };
    debug!(
        "Requesting access to file path {:?} (flags={:#X})",
        &path, flags
    );
    let request = IPCRequest::OpenFile { path, flags };
    match send_recv(&request, None) {
        (IPCResponse::SyscallResult(_), Some(handle)) => {
            unsafe { handle.into_raw() }.try_into().unwrap()
        }
        (IPCResponse::SyscallResult(code), None) => code,
        other => panic!("Unexpected response from broker to file request: {other:?}",),
    }
}

fn handle_access(path: &str, mode: libc::c_int) -> i64 {
    debug!("Requesting access({}, {})", path, mode);
    match get_fd_for_path_with_perms(path, mode) {
        Ok(_) => 0,
        Err(e) => e,
    }
}

fn handle_stat(path: &str, out_ptr: *mut libc::stat) -> i64 {
    let fd = match get_fd_for_path_with_perms(path, O_PATH) {
        Ok(fd) => fd,
        Err(code) => return code,
    };
    unsafe {
        *(libc::__errno_location()) = 0;
    }
    let res = unsafe { libc::fstat(fd.as_raw() as i32, out_ptr) };
    if res != 0 {
        let err = unsafe { *(libc::__errno_location()) };
        return (-err).into();
    }
    0
}

fn handle_chdir(path: &str) -> i64 {
    let fd = match get_fd_for_path_with_perms(path, O_PATH) {
        Ok(fd) => fd,
        Err(code) => return code,
    };
    unsafe {
        *(libc::__errno_location()) = 0;
    }
    let res = unsafe { libc::fchdir(fd.as_raw() as i32) };
    if res != 0 {
        let err = unsafe { *(libc::__errno_location()) };
        return (-err).into();
    }
    0
}

fn handle_syscall(nb: i64, args: [i64; 6], ip: i64) -> i64 {
    let request = IPCRequest::Syscall { nb, args, ip };
    let response = match send_recv(&request, None) {
        (IPCResponse::SyscallResult(_), Some(handle)) => {
            unsafe { handle.into_raw() }.try_into().unwrap()
        }
        (IPCResponse::SyscallResult(code), None) => code,
        other => panic!("Unexpected response from broker to syscall request: {other:?}",),
    };

    // In audit mode, do a best effort to replay the syscall from an allow-listed
    // location, so that we logged into the broker that the syscall was denied,
    // but the program will (probably) still continue running as intended. Some system
    // calls change semantics depending on where they're called from (e.g. sigreturn,
    // fork, etc.) but hopefully they are already handled separately.
    if AUDIT_ONLY_MODE.load(Ordering::Relaxed) && response == -(libc::ENOSYS as i64) {
        // Note: we can't use libc::syscall here, otherwise code in the audited application
        // could use it, be allow-listed, and the audit mode would completely miss these syscalls.
        unsafe { rerun_syscall(nb, args[0], args[1], args[2], args[3], args[4], args[5]) }
    } else {
        response
    }
}

// Offset in bytes from the beginning of rerun_syscall() to the actual syscall site
#[cfg(target_arch = "x86_64")]
const SYSCALL_ASM_OFFSET: usize = 91;

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
.globl rerun_syscall
rerun_syscall:
    sub    rsp,0x58
    mov    QWORD PTR [rsp],r9
    mov    r10,r8
    mov    r8,QWORD PTR [rsp]
    mov    QWORD PTR [rsp+0x8],rcx
    mov    rax,rdx
    mov    rdx,QWORD PTR [rsp+0x8]
    mov    QWORD PTR [rsp+0x10],rax
    mov    rax,rsi
    mov    rsi,QWORD PTR [rsp+0x10]
    mov    QWORD PTR [rsp+0x18],rax
    mov    rax,rdi
    mov    rdi,QWORD PTR [rsp+0x18]
    mov    r9,QWORD PTR [rsp+0x60]
    mov    QWORD PTR [rsp+0x28],rax
    mov    QWORD PTR [rsp+0x30],rdi
    mov    QWORD PTR [rsp+0x38],rsi
    mov    QWORD PTR [rsp+0x40],rdx
    mov    QWORD PTR [rsp+0x48],r10
    mov    QWORD PTR [rsp+0x50],r8
    syscall
    mov    QWORD PTR [rsp+0x20],rax
    mov    rax,QWORD PTR [rsp+0x20]
    add    rsp,0x58
    ret
"#
);

extern "C" {
    fn rerun_syscall(
        nb: i64,
        arg0: i64,
        arg1: i64,
        arg2: i64,
        arg3: i64,
        arg4: i64,
        arg5: i64,
    ) -> i64;
}
