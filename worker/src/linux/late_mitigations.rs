use crate::api::get_ipc_pipe;
use core::ffi::c_void;
use iris_ipc::{IPC_MESSAGE_MAX_SIZE, IPCRequestV1, IPCResponseV1, SeccompTrapErrorV1};
use iris_policy::{CrossPlatformHandle, Handle};
use libc::{c_int, c_uint};
use std::convert::TryInto;
use std::io::Error;

const SYS_SECCOMP: i32 = 1;
const SECCOMP_SET_MODE_FILTER: u32 = 1;

#[repr(C)]
struct siginfo_seccomp_t {
    si_signo: c_int,           // Signal number
    si_errno: c_int,           // An errno value
    si_code: c_int,            // Signal code
    si_unused: c_int,          // Unused
    si_call_addr: *mut c_void, // Address of system call instruction
    si_syscall: c_int,         // Number of attempted system call
    si_arch: c_uint,           // Architecture of attempted system call
}

pub(crate) fn apply_late_mitigations(mitigations: &IPCResponseV1) -> IPCRequestV1 {
    let seccomp_bpf = match mitigations {
        IPCResponseV1::LateMitigations { seccomp_trap_bpf } => seccomp_trap_bpf,
        _ => panic!("Not reachable"),
    };
    let seccomp_trap_bpf = if let Some(seccomp_bpf) = seccomp_bpf {
        apply_bpf_filter_mitigation(seccomp_bpf)
    } else {
        None
    };
    IPCRequestV1::ReportLateMitigations { seccomp_trap_bpf }
}

fn apply_bpf_filter_mitigation(seccomp_bpf: &[u8]) -> Option<SeccompTrapErrorV1> {
    println!(" [.] Applying seccomp trap BPF filter...");
    let instr_len = std::mem::size_of::<libc::sock_filter>();
    let instr_count = seccomp_bpf.len() / instr_len;
    if instr_count > u16::MAX.into() || (seccomp_bpf.len() % instr_len) != 0 {
        return Some(SeccompTrapErrorV1::InvalidFilterLen(seccomp_bpf.len()));
    }
    let seccomp_filter = libc::sock_fprog {
        filter: seccomp_bpf.as_ptr() as *const _ as *mut _,
        len: instr_count as u16,
    };

    // Set our own SIGSYS handler, before loading any filter
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
        return Some(SeccompTrapErrorV1::SigactionFailure(
            Error::last_os_error().raw_os_error().unwrap_or(0),
        ));
    }

    // Load the filter, by hand (libseccomp does not have a filter import function)
    let res = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &seccomp_filter as *const _,
            0,
            0,
        )
    };
    if res != 0 {
        return Some(SeccompTrapErrorV1::SeccompLoadFailure(
            Error::last_os_error().raw_os_error().unwrap_or(0),
        ));
    }
    println!(" [+] Seccomp trap BPF filter applied");

    if old_sigaction.sa_sigaction != libc::SIG_DFL && old_sigaction.sa_sigaction != libc::SIG_IGN {
        Some(SeccompTrapErrorV1::NonFatalHandlerOverwrite)
    } else {
        None
    }
}

fn read_u64_from_ctx(ucontext: *mut libc::ucontext_t, registry: libc::c_int) -> u64 {
    unsafe { (*ucontext).uc_mcontext.gregs[registry as usize] as u64 }
}

pub(crate) extern "C" fn sigsys_handler(
    signal_no: c_int,
    siginfo: *const libc::siginfo_t,
    ucontext: *const c_void,
) {
    // Be very careful when modifying this function: it *cannot* use
    // any syscall except those directly explicitly allowed by our
    // seccomp filter. It also must be async-signal-safe, meaning it
    // cannot allocate memory.
    if signal_no != libc::SIGSYS {
        return;
    }
    // Ignore signals other than thread-directed seccomp signals sent by the kernel
    if unsafe { (*siginfo).si_code } != SYS_SECCOMP {
        return;
    }

    let full_siginfo = siginfo as *const siginfo_seccomp_t;
    let arch = unsafe { (*full_siginfo).si_arch };
    let ip = unsafe { (*full_siginfo).si_call_addr } as u64;
    let nr = unsafe { (*full_siginfo).si_syscall } as u64;

    let ucontext = ucontext as *mut libc::ucontext_t;
    let rax = read_u64_from_ctx(ucontext, libc::REG_RAX);
    if nr != rax {
        panic!(
            "Unexpected registry value during syscall {}: RAX={}",
            nr, rax
        );
    }
    let arg1 = read_u64_from_ctx(ucontext, libc::REG_RDI);
    let arg2 = read_u64_from_ctx(ucontext, libc::REG_RSI);
    let arg3 = read_u64_from_ctx(ucontext, libc::REG_RDX);
    let arg4 = read_u64_from_ctx(ucontext, libc::REG_R10);
    let arg5 = read_u64_from_ctx(ucontext, libc::REG_R8);
    let arg6 = read_u64_from_ctx(ucontext, libc::REG_R9);
    let msg = format!(
        " [.] Syscall ip={} arch={} nr={} ({}, {}, {}, {}, {}, {}) intercepted by seccomp-trap\n",
        ip, arch, nr, arg1, arg2, arg3, arg4, arg5, arg6
    );
    unsafe { libc::write(2, msg.as_ptr() as *const _, msg.len()) };

    let req = IPCRequestV1::Syscall {
        arch,
        nr,
        arg1,
        arg2,
        arg3,
        arg4,
        arg5,
        arg6,
        ip,
    };
    let mut buf = [0u8; IPC_MESSAGE_MAX_SIZE];
    let response_code = match send_recv(&req, None, &mut buf) {
        (IPCResponseV1::SyscallResult(code), None) => code,
        (IPCResponseV1::SyscallResult(0), Some(handle)) => {
            // Handle becomes the result code for successful syscalls
            let res = unsafe { handle.into_raw() };
            res.try_into().unwrap()
        }
        other => panic!("Unexpected broker answer to {:?} : {:?}", req, other),
    };
    println!(" [.] Syscall result: {}", response_code);
    unsafe {
        (*ucontext).uc_mcontext.gregs[libc::REG_RAX as usize] = response_code as i64;
    }
}

fn send_recv<'a>(request: &IPCRequestV1, handle: Option<&Handle>, buffer: &'a mut [u8]) -> (IPCResponseV1<'a>, Option<Handle>) {
    let mut pipe = get_ipc_pipe();
    pipe.send(&request, handle, buffer)
        .expect("unable to send IPC request to broker");
    let (resp, handle) = pipe
        .recv_with_handle(buffer)
        .expect("unable to receive IPC response from broker");
    let resp = resp.expect("broker closed our IPC pipe while expecting its response");
    (resp, handle)
}
