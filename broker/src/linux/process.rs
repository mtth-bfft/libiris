use crate::error::BrokerError;
use crate::process::CrossPlatformSandboxedProcess;
use crate::ProcessConfig;
use core::ffi::c_void;
use core::ptr::null;
use iris_policy::{CrossPlatformHandle, Handle, Policy};
use libc::c_int;
use linux_entrypoint::{clone_entrypoint, EntrypointParameters};
use log::debug;
use std::convert::{TryFrom, TryInto};
use std::io::Error;

const DEFAULT_CLONE_STACK_SIZE: usize = 1024 * 1024;

#[derive(Debug)]
pub struct OSSandboxedProcess {
    pid: u32,
    // Thread stack for clone(2), flagged as "never read" because rust does not
    // know about the thread created unsafely
    #[allow(dead_code)]
    initial_thread_stack: Vec<u8>,
}

impl CrossPlatformSandboxedProcess for OSSandboxedProcess {
    fn new(
        policy: &Policy,
        process_config: &ProcessConfig,
    ) -> Result<Self, BrokerError> {
        if process_config.argv.is_empty() {
            return Err(BrokerError::MissingCommandLine);
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
                return Err(BrokerError::InternalOsOperationFailed {
                    description: "pipe() failed".to_owned(),
                    os_code: Error::last_os_error().raw_os_error().unwrap_or(0) as u64,
                });
            }
            (
                Handle::new(clone_error_pipes[0].try_into().unwrap()).unwrap(),
                Handle::new(clone_error_pipes[1].try_into().unwrap()).unwrap(),
            )
        };
        child_pipe.set_inheritable(false)?; // set the pipe as CLOEXEC so it gets closed on successful execve(), which we can detect

        // Pack together everything that needs to be passed to the new process,
        // and ensure their lifetime is long enough to pass clone()
        let argv: Vec<*const i8> = process_config.argv
            .iter()
            .map(|x| x.as_ptr())
            .chain(std::iter::once(null()))
            .collect();
        let envp: Vec<*const i8> = process_config.envp
            .iter()
            .map(|x| x.as_ptr())
            .chain(std::iter::once(null()))
            .collect();
        let allowed_file_descriptors: Vec<c_int> = policy
            .get_inherited_handles()
            .iter()
            .map(|n| n.as_raw().try_into().unwrap())
            .collect();
        let entrypoint_params = EntrypointParameters {
            exe: process_config.executable_path.as_ptr(),
            argv: argv.as_ptr(),
            envp: envp.as_ptr(),
            allowed_file_descriptors: allowed_file_descriptors.as_ptr(),
            allowed_file_descriptors_count: allowed_file_descriptors.len(),
            execve_errno_pipe: child_pipe.as_raw().try_into().unwrap(),
            stdin: process_config.stdin.map(|h| c_int::try_from(h.as_raw()).unwrap()),
            stdout: process_config.stdout.map(|h| c_int::try_from(h.as_raw()).unwrap()),
            stderr: process_config.stderr.map(|h| c_int::try_from(h.as_raw()).unwrap()),
        };
        let entrypoint_params = Box::leak(Box::new(entrypoint_params));

        let pid = unsafe {
            libc::clone(
                clone_entrypoint,
                stack_end_ptr,
                clone_args,
                entrypoint_params as *const _ as *mut c_void,
            )
        };

        // Drop the structure in the parent so it doesn't leak. This is safe since we
        // created the box a few lines above and we control it.
        unsafe { Box::from_raw(entrypoint_params as *mut EntrypointParameters) };
        drop(child_pipe);

        let pid: u32 = match pid.try_into() {
            Ok(n) => n,
            Err(_) => {
                return Err(BrokerError::InternalOsOperationFailed {
                    description: "clone()".to_owned(),
                    os_code: Error::last_os_error().raw_os_error().unwrap_or(0) as u64,
                })
            }
        };

        let mut execve_errno = [0u8; 4];
        let res = unsafe {
            libc::read(
                parent_pipe.as_raw().try_into().unwrap(),
                execve_errno.as_mut_ptr() as *mut _,
                execve_errno.len(),
            )
        };
        if res > 0 {
            return Err(BrokerError::InternalOsOperationFailed {
                description: "execve()".to_owned(),
                os_code: u32::from_be_bytes(execve_errno).into(),
            });
        }

        debug!("Worker PID={} created", pid);

        Ok(Self {
            pid,
            initial_thread_stack: stack,
        })
    }

    fn get_pid(&self) -> u64 {
        self.pid.into()
    }
}
