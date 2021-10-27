use crate::os::process::OSSandboxedProcess;
use crate::process::CrossPlatformSandboxedProcess;
use iris_ipc::{
    CrossPlatformMessagePipe, IPCMessagePipe, IPCRequestV1, IPCResponseV1, IPCVersion, MessagePipe,
    IPC_HANDLE_ENV_NAME,
};
use iris_policy::{CrossPlatformHandle, Handle, Policy};
use std::sync::Arc;
use std::ffi::{CStr, CString};

pub struct Worker {
    process: OSSandboxedProcess,
    policy: Arc<Policy>,
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
        let (mut broker_pipe, worker_pipe) = MessagePipe::new()?;
        let mut worker_pipe_handle = worker_pipe.into_handle();
        worker_pipe_handle.set_inheritable(true)?;
        let worker_pipe_handle = Arc::new(worker_pipe_handle);
        let mut policy = policy.clone();
        policy.allow_inherit_handle(worker_pipe_handle.clone())?;
        for handle in [&stdin, &stdout, &stderr] {
            if let Some(handle) = handle {
                policy.allow_inherit_handle(handle.clone())?;
            }
        }
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
        envp.push(&ipc_handle_var);
        let mut process = OSSandboxedProcess::new(&policy, exe, argv, &envp, stdin, stdout, stderr)?;
        let late_mitigations = process.get_late_mitigations()?;
        broker_pipe.set_remote_process(process.get_pid())?; // set to pass handles later
        let mut broker_pipe = IPCMessagePipe::new_server(broker_pipe, IPCVersion::V1)?;
        if let Err(e) = broker_pipe.send(&late_mitigations, None) {
            return Err(format!("Unable to send initial message to worker process: {:?}", e));
        }
        // The IPC might outlive our worker object (e.g. if it is dropped without waiting
        // for the worker to exit), and it needs to keep a hand on our policy to apply it.
        let policy = Arc::new(policy);
        process.start_serving_ipc_requests(broker_pipe, policy.clone())?;
        Ok(Self { process, policy })
    }

    pub fn get_pid(&self) -> u64 {
        self.process.get_pid()
    }

    pub fn wait_for_exit(&self) -> Result<u64, String> {
        self.process.wait_for_exit()
    }
}
