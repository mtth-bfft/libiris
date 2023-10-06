use iris_worker::IPC_SECCOMP_CALL_SITE_PLACEHOLDER;
use libseccomp::{
    error::SeccompError, scmp_cmp, ScmpAction, ScmpArch, ScmpFilterContext, ScmpSyscall,
};
use log::info;
use std::io::{Read, Seek};

const SYSCALLS_ALLOWED_BY_DEFAULT: [&str; 84] = [
    "read",
    "write",
    "readv",
    "writev",
    "recvmsg",
    "sendmsg",
    "tee",
    "fstat",
    "fstat64",
    "newfstatat",
    "lseek",
    "_llseek",
    "select",
    "_newselect",
    "accept",
    "accept4",
    "ftruncate",
    "close",
    "memfd_create",
    "sigaltstack",
    "munmap",
    "nanosleep",
    "exit_group",
    "restart_syscall",
    "rt_sigreturn",
    "rt_sigprocmask", // FIXME: should be trapped to avoid masking SIGSYS
    "rt_sigaction",   // FIXME: should be trapped to avoid masking SIGSYS
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
    "fsync",
    "fdatasync",
    "shutdown",
    "nice",
    "pause",
    "clock_nanosleep",
    "clock_gettime",
    "clock_gettime64",
    "clock_getres",
    "poll",
    "pipe",
    "mremap",
    "msync",
    "mincore",
    "madvise",
    "dup",
    "dup2",
    "dup3",
    "fcntl",
    "getitimer",
    "setitimer",
    "sendfile",
    "listen",
    "getsockname",
    "getpeername",
    "socketpair",
    "getsockopt",
    "futex",
    "exit",
    "exit_group",
];

macro_rules! get_offset {
    ($type:ty, $field:tt) => {{
        type T = $type;
        // Make sure the field actually exists. This line ensures that an error
        // is generated if $field is accessed through an implicit deref.
        #[allow(clippy::unneeded_field_pattern)]
        let T { $field: _, .. };
        let dummy = ::core::mem::MaybeUninit::<$type>::uninit();
        let dummy_ptr = dummy.as_ptr();
        let member_ptr = unsafe { ::core::ptr::addr_of!((*dummy_ptr).$field) };
        member_ptr as usize - dummy_ptr as usize
    }};
}

pub(crate) fn compute_seccomp_filter(pid: u64, audit_mode: bool) -> Result<Vec<u8>, SeccompError> {
    let mut filter = ScmpFilterContext::new_filter(ScmpAction::Trap)?;
    if let Err(e) = filter.set_ctl_tsync(true) {
        info!("Unable to set flag SCMP_FLTATR_CTL_TSYNC ({}), no defense in depth against threads missing their seccomp filter", e);
    }

    // Architectures must be registered before system calls, so that each system call is derived for
    // each architecture.
    filter.add_arch(ScmpArch::X86)?;
    filter.add_arch(ScmpArch::X8664)?;
    filter.add_arch(ScmpArch::X32)?;

    // Add always-unconditionally-allowed system calls
    for syscall_name in &SYSCALLS_ALLOWED_BY_DEFAULT {
        let syscall = match ScmpSyscall::from_name(syscall_name) {
            Ok(s) => s,
            Err(_) => {
                info!(
                    "Unable to allow system call {} (probably not supported by the kernel)",
                    syscall_name
                );
                continue;
            }
        };
        filter.add_rule(ScmpAction::Allow, syscall)?;
    }

    // Add special cas for mmap() and mprotect() but only non-executable memory
    let denied_page_protection_flags = !(0x1u64 | 0x2 | 0x8 | 0x10 | 0x01000000 | 0x02000000);
    match ScmpSyscall::from_name("mmap") {
        Ok(s) => filter.add_rule_conditional(
            ScmpAction::Allow,
            s,
            &[scmp_cmp!($arg2 & denied_page_protection_flags == 0)],
        )?,
        Err(_) => {
            info!("Unable to allow non-executable mmap (probably not supported by the kernel)")
        }
    };
    match ScmpSyscall::from_name("mmap2") {
        Ok(s) => filter.add_rule_conditional(
            ScmpAction::Allow,
            s,
            &[scmp_cmp!($arg2 & denied_page_protection_flags == 0)],
        )?,
        Err(_) => {
            info!("Unable to allow non-executable mmap2 (probably not supported by the kernel)")
        }
    };
    match ScmpSyscall::from_name("mprotect") {
        Ok(s) => filter.add_rule_conditional(
            ScmpAction::Allow,
            s,
            &[scmp_cmp!($arg2 & denied_page_protection_flags == 0)],
        )?,
        Err(_) => {
            info!("Unable to allow non-executable mprotect (probably not supported by the kernel)")
        }
    };

    // Add special case for kill() on ourselves only (useful for e.g. raise())
    match ScmpSyscall::from_name("kill") {
        Ok(s) => filter.add_rule_conditional(ScmpAction::Allow, s, &[scmp_cmp!($arg0 == pid)])?,
        Err(_) => info!("Unable to allow kill on ourselves (probably not supported by the kernel)"),
    };

    // Add special case for tgkill() on ourselves only
    match ScmpSyscall::from_name("tgkill") {
        Ok(s) => filter.add_rule_conditional(ScmpAction::Allow, s, &[scmp_cmp!($arg0 == pid)])?,
        Err(_) => {
            info!("Unable to allow tgkill on ourselves (probably not supported by the kernel)")
        }
    };

    // Allow ioctl() for TCGETS only
    match ScmpSyscall::from_name("ioctl") {
        Ok(s) => filter.add_rule_conditional(ScmpAction::Allow, s, &[scmp_cmp!($arg1 == 21505)])?,
        Err(_) => info!("Unable to allow ioctl(TCGETS) (probably not supported by the kernel)"),
    };

    // Generate BPF bytecode, to be handed to our child process
    // The libseccomp C API only allows exporting to a file descriptor, so we need
    // this awkward tmp file instead of using a buffer in memory (a memfd could avoid
    // this, but support for memfds is relatively recent)
    let mut tmp_bpf = match tempfile::tempfile() {
        Ok(f) => f,
        Err(e) => {
            // FIXME: actual error handling
            panic!("Unable to allocate a temporary file ({e}), cannot export seccomp filter");
        }
    };
    filter.export_bpf(&mut tmp_bpf)?;
    tmp_bpf
        .rewind()
        .expect("unable to seek(0) tmp file for libseccomp");

    let mut bpf = Vec::new();

    // When running in audit-only mode, prepend a few instructions to allow all syscalls
    // coming from the syscall replay call site. The safe libseccomp API doesn't support
    // conditions based on instruction pointer (for a good reason, it's probably a bad
    // idea to do that in production), so we forge instructions manually, and keep this
    // code isolated from the rest and in audit mode only.
    if audit_mode {
        // Just insert the placeholder in a platform-endianness-independent way
        let bytes = u64::to_ne_bytes(IPC_SECCOMP_CALL_SITE_PLACEHOLDER);
        let first = [bytes[0], bytes[1], bytes[2], bytes[3]];
        let second = [bytes[4], bytes[5], bytes[6], bytes[7]];
        append_instruction(
            &mut bpf,
            &libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jf: 0,
                jt: 0,
                k: get_offset!(libc::seccomp_data, instruction_pointer) as u32,
            },
        );
        append_instruction(
            &mut bpf,
            &libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jf: 3,
                jt: 0,
                k: u32::from_ne_bytes(first),
            },
        );
        append_instruction(
            &mut bpf,
            &libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jf: 0,
                jt: 0,
                k: (get_offset!(libc::seccomp_data, instruction_pointer) + 4) as u32,
            },
        );
        append_instruction(
            &mut bpf,
            &libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jf: 1,
                jt: 0,
                k: u32::from_ne_bytes(second),
            },
        );
        append_instruction(
            &mut bpf,
            &libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jf: 0,
                jt: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        );
    }

    tmp_bpf
        .read_to_end(&mut bpf)
        .expect("unable to read from tmp file for libseccomp");
    Ok(bpf)
}

fn append_instruction(bpf: &mut Vec<u8>, insn: &libc::sock_filter) {
    unsafe {
        bpf.extend_from_slice(std::slice::from_raw_parts(
            insn as *const _ as *const u8,
            std::mem::size_of::<libc::sock_filter>(),
        ));
    }
}
