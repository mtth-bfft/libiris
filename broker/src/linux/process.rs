use crate::process::CrossPlatformSandboxedProcess;
use core::ffi::c_void;
use core::ptr::null;
use iris_policy::{CrossPlatformHandle, Handle, Policy};
use libc::c_int;
use std::convert::{TryFrom, TryInto};
use std::ffi::{CStr, CString};
use std::io::Error;

const DEFAULT_CLONE_STACK_SIZE: usize = 1 * 1024 * 1024;

pub struct OSSandboxedProcess {
    pid: u32,
    initial_thread_stack: Vec<u8>,
}

struct EntrypointParameters {
    exe: CString,
    argv: Vec<CString>,
    envp: Vec<CString>,
    allowed_file_descriptors: Vec<c_int>,
    execve_errno_pipe: c_int,
    stdin: Option<c_int>,
    stdout: Option<c_int>,
    stderr: Option<c_int>,
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

        // Allocate a stack for the process' first thread to use
        let mut stack = vec![0; DEFAULT_CLONE_STACK_SIZE];
        let stack_end_ptr = stack.as_mut_ptr().wrapping_add(stack.len()) as *mut c_void;

        // Unshare as many namespaces as possible
        // (this might not be possible due to insufficient privilege level,
        // and/or kernel support for unprivileged or even privileged user namespaces)
        let clone_args = 0; // FIXME: add a retry-loop for libc::CLONE_NEWUSER | libc::CLONE_NEWCGROUP | libc::CLONE_NEWIPC | libc::CLONE_NEWNET | libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWUTS;

        // Set up a pipe that will get CLOEXEC-ed if execve() succeeds, and otherwise be used to send us the errno
        let (parent_pipe, mut child_pipe) = unsafe {
            let mut clone_error_pipes: Vec<c_int> = vec![-1, -1];
            let res = libc::pipe(clone_error_pipes.as_mut_ptr());
            if res < 0 {
                // It's safe to return here, if pipe() returned an error it did not give us file descriptors so there is no leak
                return Err(format!(
                    "pipe() failed with code {}",
                    Error::last_os_error()
                ));
            }
            (
                Handle::new(clone_error_pipes[0].try_into().unwrap()).unwrap(),
                Handle::new(clone_error_pipes[1].try_into().unwrap()).unwrap(),
            )
        };
        child_pipe.set_inheritable(false)?; // set the pipe as CLOEXEC so it gets closed on successful execve(), which we can detect

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
            execve_errno_pipe: child_pipe.as_raw().try_into().unwrap(),
            stdin: stdin.map(|h| c_int::try_from(h.as_raw()).unwrap()),
            stdout: stdout.map(|h| c_int::try_from(h.as_raw()).unwrap()),
            stderr: stderr.map(|h| c_int::try_from(h.as_raw()).unwrap()),
        };
        let entrypoint_params = Box::leak(Box::new(entrypoint_params));

        let pid = unsafe {
            libc::clone(
                process_entrypoint,
                stack_end_ptr,
                clone_args,
                entrypoint_params as *const _ as *mut c_void,
            )
        };

        // Drop the structure in the parent so it doesn't leak. This is safe since we
        // created the box a few lines above and we control it.
        unsafe { Box::from_raw(entrypoint_params as *mut EntrypointParameters) };
        drop(child_pipe);

        if pid <= 0 {
            return Err(format!(
                "clone() failed with code {}",
                Error::last_os_error()
            ));
        }

        let mut execve_errno = vec![0u8; 4];
        let res = unsafe {
            libc::read(
                parent_pipe.as_raw().try_into().unwrap(),
                execve_errno.as_mut_ptr() as *mut _,
                execve_errno.len(),
            )
        };
        if res > 0 {
            return Err(format!(
                "execve() failed with code {}",
                u32::from_be_bytes(execve_errno[..].try_into().unwrap())
            ));
        }

        println!(" [.] Worker PID={} created", pid);

        Ok(Self {
            pid: pid.try_into().unwrap(),
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

extern "C" fn process_entrypoint(args: *mut c_void) -> c_int {
    let args = unsafe { Box::from_raw(args as *mut EntrypointParameters) };
    println!(
        " [.] Worker {} started with PID={}",
        args.exe.to_string_lossy(),
        unsafe { libc::getpid() }
    );
    let dev_null_path = CString::new("/dev/null").unwrap();

    // TODO: set the umask

    // Close stdin and replace it with /dev/null (so that any read(stdin) deterministically returns EOF)
    // We use libc::open in the lines below, because Rust's stdlib sets CLOEXEC to avoid leaking file descriptors.
    unsafe {
        libc::close(libc::STDIN_FILENO);
    }
    if let Some(fd) = args.stdin {
        let res = unsafe { libc::dup(fd) };
        if res < 0 || res != libc::STDIN_FILENO {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(200);
            return errno;
        }
    } else {
        unsafe {
            libc::open(dev_null_path.as_ptr(), libc::O_RDONLY);
        }
    }

    // Close stdout and replace it with the user-provided file descriptor, or /dev/null
    // (so that any write(stdout) deterministically is ignored)
    unsafe {
        libc::close(libc::STDOUT_FILENO);
    }
    if let Some(fd) = args.stdout {
        let res = unsafe { libc::dup(fd) };
        if res < 0 || res != libc::STDOUT_FILENO {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(201);
            return errno;
        }
    } else {
        unsafe {
            libc::open(dev_null_path.as_ptr(), libc::O_WRONLY);
        }
    }

    // Close stderr and replace it with the user-provided file descriptor, or /dev/null
    // (so that any write(stderr) deterministically is ignored)
    unsafe {
        libc::close(libc::STDERR_FILENO);
    }
    if let Some(fd) = args.stderr {
        let res = unsafe { libc::dup(fd) };
        if res < 0 || res != libc::STDERR_FILENO {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(202);
            return errno;
        }
    } else {
        unsafe {
            libc::open(dev_null_path.as_ptr(), libc::O_WRONLY);
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
            if fd <= libc::STDERR_FILENO || fd == args.execve_errno_pipe {
                continue; // don't close the CLOEXEC pipe used to check if execve() worked, otherwise it loses its purpose
            }
            if !args.allowed_file_descriptors.contains(&fd) {
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

    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let errno_bytes = (errno as u32).to_be_bytes();
    unsafe {
        libc::write(args.execve_errno_pipe, errno_bytes.as_ptr() as *const _, 4);
        libc::exit(errno);
    }
}
