use crate::os::process::OSSandboxedProcess;
use crate::process::CrossPlatformSandboxedProcess;
use iris_ipc::{CrossPlatformMessagePipe, MessagePipe, IPC_HANDLE_ENV_NAME};
use iris_policy::{CrossPlatformHandle, Handle, Policy};
use std::ffi::{CStr, CString};
use std::sync::Arc;

pub struct Worker {
    process: Arc<OSSandboxedProcess>,
}

impl Worker {
    pub fn new(
        policy: &Policy,
        exe: &CStr,
        argv: &[&CStr],
        envp: &[&CStr],
        stdin: Option<Arc<Handle>>,
        stdout: Option<Arc<Handle>>,
        stderr: Option<Arc<Handle>>,
    ) -> Result<Self, String> {
        let (broker_pipe, worker_pipe) = MessagePipe::new()?;
        let mut worker_pipe_handle = worker_pipe.into_handle();
        worker_pipe_handle.set_inheritable(true)?;
        let worker_pipe_handle = Arc::new(worker_pipe_handle);
        let mut policy = policy.clone();
        policy.allow_inherit_handle(Arc::clone(&worker_pipe_handle))?;
        for handle in policy.get_inherited_handles() {
            // On Linux, exec() will close all CLOEXEC handles.
            // On Windows, CreateProcess() with bInheritHandles = TRUE doesn't automatically set the given
            // handles as inheritable, and instead returns a ERROR_INVALID_PARAMETER if one of them is not.
            // We cannot just set the handles as inheritable behind the caller's back, since they might
            // reset it or depend on it in another thread. They have to get this right by themselves.
            if !handle.is_inheritable()? {
                return Err(format!(
                    "Cannot make worker inherit handle {:?} which is not set as inheritable",
                    handle
                ));
            }
        }
        for env_var in envp {
            if env_var.to_string_lossy().starts_with(IPC_HANDLE_ENV_NAME) {
                return Err(format!(
                    "Workers cannot use the reserved {} environment variable",
                    IPC_HANDLE_ENV_NAME
                ));
            }
        }
        let mut envp = Vec::from(envp);
        let ipc_handle_var = CString::new(format!(
            "{}={}",
            IPC_HANDLE_ENV_NAME,
            worker_pipe_handle.as_raw().to_string()
        ))
        .unwrap();
        // Ensure only the policy holds a reference to the worker's end of the pipe
        // so that when policy.release_handles() is called, we know we're not holding
        // a reference to the worker's end of the pipe (and thus we can start detecting
        // if the worker closed its end)
        drop(worker_pipe_handle);
        envp.push(&ipc_handle_var);
        let process =
            OSSandboxedProcess::new(policy, exe, argv, &envp, broker_pipe, stdin, stdout, stderr)?;
        Ok(Self { process })
    }

    pub fn get_pid(&self) -> u64 {
        self.process.get_pid()
    }

    pub fn wait_for_exit(&self) -> Result<u64, String> {
        self.process.wait_for_exit()
    }
}
