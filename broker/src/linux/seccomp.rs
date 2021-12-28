use core::ffi::c_void;
use std::convert::TryInto;
use std::io::{SeekFrom, Seek, Read};
use std::ffi::CString;
use tempfile::NamedTempFile;
use std::os::unix::io::AsRawFd;
use seccomp_sys::{
    scmp_filter_attr, seccomp_attr_set, seccomp_init, seccomp_release,
    scmp_arg_cmp, scmp_compare,
    seccomp_rule_add, seccomp_syscall_resolve_name, seccomp_export_bpf,
    SCMP_ACT_ALLOW, SCMP_ACT_TRAP, SCMP_ACT_NOTIFY, __NR_SCMP_ERROR,
};

#[cfg(seccomp_notify)]
use {
    std::sync::Arc,
    std::io::Error,
    core::ptr::null_mut,
    iris_policy::{Handle, CrossPlatformHandle},
    seccomp_sys::{seccomp_notif_resp, seccomp_load,
        seccomp_notify_alloc, seccomp_notify_fd, seccomp_notify_id_valid,
        seccomp_notify_receive, seccomp_notify_respond, seccomp_notif,
    },
    crate::os::{brokered_syscalls::handle_syscall, process::OSSandboxedProcess},
};

// Missing from libseccomp (for now)
#[cfg(seccomp_notify)]
#[repr(C)]
struct seccomp_notif_addfd {
    id: u64,          // Cookie value
    flags: u32,       // Flags
    srcfd: u32,       // Local file descriptor number
    newfd: u32,       // 0 or desired file descriptor number in target
    newfd_flags: u32, // Flags to set on target file descriptor
}
#[cfg(seccomp_notify)]
const SECCOMP_IOCTL_NOTIF_ADDFD: u64 = 0x40182103;

// Generic allow-list, no matter the resource policy
const SYSCALLS_ALLOWED_BY_DEFAULT: [&str; 68] = [
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
    "getdents64",
    "tee",
    "lseek",
    "_llseek",
    "accept",
    "accept4",
    //"ftruncate", disallowed to prevent truncation of O_APPEND files
    "dup",
    "dup2",
    "dup3",
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
    "getrlimit",
    "setrlimit",
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

pub(crate) struct SeccompFilter {
    context: *mut c_void,
}

impl SeccompFilter {
    pub fn new(default_action: u32) -> Result<Self, String> {
        let context = unsafe { seccomp_init(default_action) };
        if context.is_null() {
            return Err("seccomp_init() failed, no error information available".to_owned());
        }
        let res = unsafe { seccomp_attr_set(context, scmp_filter_attr::SCMP_FLTATR_CTL_TSYNC, 1) };
        if res != 0 {
            return Err(format!(
                "seccomp_attr_set(SCMP_FLTATR_CTL_TSYNC) failed with error {}",
                -res
            ));
        }
        Ok(Self { context })
    }

    #[cfg(seccomp_notify)]
    pub fn load(&self) -> Result<(), i32> {
        let res: i32 = unsafe { seccomp_load(self.context) };
        if res != 0 {
            Err(res)
        } else {
            Ok(())
        }
    }

    pub fn as_bytes(&self) -> Result<Vec<u8>, String> {
        // Note: Saving to an ephemeral file is convoluted, but it's
        // the only BPF export function from libseccomp as of today.
        let mut tmpfile = NamedTempFile::new().map_err(|e| format!("Unable to open temporary file: {}", e))?;
        let res = unsafe { seccomp_export_bpf(self.context, tmpfile.as_file().as_raw_fd()) };
        if res < 0 {
            return Err(format!("seccomp_export_bpf() failed with code {}", res));
        }
        tmpfile.as_file_mut().seek(SeekFrom::Start(0)).map_err(|e| format!("Unable to seek into temporary file: {}", e))?;
        let mut bpf = vec![];
        tmpfile.read_to_end(&mut bpf).map_err(|e| format!("Unable to read from temporary file: {}", e))?;
        Ok(bpf)
    }

    #[cfg(seccomp_notify)]
    pub fn get_notify_fd(&self) -> Result<Handle, i32> {
        let res = unsafe { seccomp_notify_fd(self.context) };
        if res < 0 {
            Err(res)
        } else {
            Ok(unsafe { Handle::new(res.try_into().unwrap()) }.unwrap())
        }
    }
}

impl Drop for SeccompFilter {
    fn drop(&mut self) {
        unsafe { seccomp_release(self.context) };
    }
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

#[cfg(seccomp_notif)]
fn apply_seccomp_user_notification_filter() -> Result<c_int, String> {
    let filter = match generate_seccomp_filter(true) {
        Ok(f) => f,
        Err(e) => return Err(format!("Unable to generate seccomp filter: {}", e)),
    };
    let res: i32 = unsafe { seccomp_load(filter.context) };
    if res != 0 {
        if let Err(e) = args.sock_seccomp.send(&res.to_be_bytes(), None) {
            panic!("Unable to send seccomp error code to broker: {}", e);
        }
        return Err(format!("Cannot load seccomp user notification filter: code {}", res));
    }
    // Note: at this point, we're fully committed to seccomp-unotify.
    // If something fails, the process is doomed to hang as soon as we
    // issue an unauthorized syscall. Better to crash than to hang.
    let notify_fd = unsafe {
        let res = seccomp_notify_fd(filter.context);
        if res < 0 {
            eprintln!("Fatal error: seccomp_notify_fd() failed with error {}", res);
            std::process::abort(); // do *not* panic!() which unwinds
        }
        Handle::new(res.try_into().unwrap()).unwrap()
    };
    // Send the file descriptor to our parent so that it can receive notifications
    if let Err(e) = args.sock_seccomp.send(&[], Some(&notify_fd)) {
        eprintln!(
            "Fatal error: unable to send seccomp notify handle to broker: {}",
            e
        );
        std::process::abort(); // do *not* panic!() which unwinds
    }
    Ok(notify_fd)
}

#[cfg(seccomp_notify)]
pub(crate) fn seccomp_handle_user_notifications(process: &Arc<OSSandboxedProcess>, notify_fd: Handle) {
    let processref = Arc::clone(&process);
    *(process.seccomp_unotify_thread.write().unwrap()) = Some(std::thread::spawn(move || {
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
            let res = unsafe {
                core::ptr::write_bytes(
                    req as *mut u8,
                    0u8,
                    std::mem::size_of::<seccomp_notif>(),
                );
                seccomp_notify_receive(notify_fd.as_raw().try_into().unwrap(), req)
            };
            if res != 0 {
                let errno = Error::last_os_error().raw_os_error().unwrap_or(0);
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
                        // FIXME: The worker can trigger this error at will, e.g. by asking for a file
                        // after lowering its file descriptor rlimit. We need to handle it gracefully.
                        let errno =
                            Error::last_os_error().raw_os_error().unwrap_or(0);
                        panic!("Spurious syscall response failure: SECCOMP_IOCTL_NOTIF_ADDFD failed (errno {})", errno);
                    }
                    res.into() // file descriptor number in the remote process
                }
            };
            let res = unsafe {
                core::ptr::write_bytes(
                    resp as *mut u8,
                    0u8,
                    std::mem::size_of::<seccomp_notif_resp>(),
                );
                (*resp).id = cookie;
                if code >= 0 {
                    (*resp).val = code;
                } else {
                    (*resp).error = code as i32;
                }
                seccomp_notify_respond(notify_fd.as_raw().try_into().unwrap(), resp)
            };
            if res != 0 {
                let errno = Error::last_os_error().raw_os_error().unwrap_or(0);
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
    }));
}

pub(crate) fn generate_seccomp_filter(user_notif: bool) -> Result<SeccompFilter, String> {
    let default_action: u32 = if user_notif { SCMP_ACT_NOTIFY } else { SCMP_ACT_TRAP };
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
            },
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
    let a1_getfl_comparator = scmp_arg_cmp {
        arg: 1, // second syscall argument, the command number
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
            a1_getfl_comparator,
        )
    };
    if res != 0 {
        println!(" [!] seccomp_rule_add(SCMP_ACT_ALLOW, fcntl, SCMP_A1(SCMP_CMP_EQ, F_GETFL)) failed with code {}", -res);
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

    // Add special case handling for prlimit64() on ourselves only
    let syscall_nr = get_syscall_number("prlimit64").unwrap();
    println!(
        " [.] Allowing syscall prlimit64 / {} on ourselves only",
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
        println!(" [!] seccomp_rule_add(SCMP_ACT_ALLOW, prlimit64, SCMP_A0(SCMP_CMP_EQ, getpid())) failed with code {}", -res);
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
        panic!("seccomp_rule_add(SCMP_ACT_ALLOW, prlimit64, SCMP_A0(SCMP_CMP_EQ, 0)) failed with code {}", -res);
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
