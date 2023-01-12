use crate::error::BrokerError;
use crate::os::brokered_syscalls::handle_os_specific_request;
use crate::os::process::OSSandboxedProcess;
use crate::process::CrossPlatformSandboxedProcess;
use iris_ipc::{
    CrossPlatformMessagePipe, IPCMessagePipe, IPCRequest, IPCResponse, MessagePipe,
    IPC_HANDLE_ENV_NAME,
};
use iris_policy::{CrossPlatformHandle, Handle, Policy};
use log::{debug, warn};
use std::ffi::{CStr, CString};

#[derive(Debug, Clone)]
pub struct ProcessConfig<'a> {
    executable_path: CString,
    argv: Vec<CString>,
    envp: Vec<CString>,
    cwd: Option<CString>,
    stdin: Option<&'a Handle>,
    stdout: Option<&'a Handle>,
    stderr: Option<&'a Handle>,
}

impl<'a> ProcessConfig<'a> {
    pub fn new(executable_path: CString, argv: &[CString]) -> Self {
        Self {
            executable_path,
            argv: argv.to_owned(),
            envp: vec![],
            cwd: None,
            stdin: None,
            stdout: None,
            stderr: None,
        }
    }

    pub fn with_current_working_directory(mut self, cwd: CString) -> Result<Self, BrokerError> {
        self.cwd = Some(cwd);
        Ok(self)
    }

    pub fn with_environment_variable(mut self, env_var: CString) -> Result<Self, BrokerError> {
        if env_var.to_string_lossy().starts_with(IPC_HANDLE_ENV_NAME) {
            return Err(BrokerError::CannotUseReservedEnvironmentVariable {
                name: IPC_HANDLE_ENV_NAME.to_owned(),
            });
        }
        self.envp.push(env_var);
        Ok(self)
    }

    pub fn with_stdin_redirected(mut self, new_stdin: &'a Handle) -> Result<Self, BrokerError> {
        self.stdin = Some(new_stdin);
        Ok(self)
    }

    pub fn with_stdout_redirected(mut self, new_stdout: &'a Handle) -> Result<Self, BrokerError> {
        self.stdout = Some(new_stdout);
        Ok(self)
    }

    pub fn with_stderr_redirected(mut self, new_stderr: &'a Handle) -> Result<Self, BrokerError> {
        self.stderr = Some(new_stderr);
        Ok(self)
    }
}

#[derive(Debug)]
pub struct Worker {
    process: OSSandboxedProcess,
}

impl Worker {
    pub fn new(process_config: &ProcessConfig, policy: &Policy) -> Result<Self, BrokerError> {
        let (mut broker_pipe, worker_pipe) = MessagePipe::new()?;
        let mut worker_pipe_handle = worker_pipe.into_handle();
        worker_pipe_handle.set_inheritable(true)?;
        let mut policy = policy.clone();
        policy.allow_inherit_handle(&worker_pipe_handle)?;
        for handle in [
            process_config.stdin,
            process_config.stdout,
            process_config.stderr,
        ]
        .iter()
        .flatten()
        {
            policy.allow_inherit_handle(handle)?;
        }
        let ipc_handle_var = CString::new(format!(
            "{}={}",
            IPC_HANDLE_ENV_NAME,
            worker_pipe_handle.as_raw()
        ))
        .unwrap();
        let argv: Vec<&CStr> = process_config.argv.iter().map(|s| s.as_ref()).collect();
        let envp: Vec<&CStr> = process_config
            .envp
            .iter()
            .chain(std::iter::once(&ipc_handle_var))
            .map(|s| s.as_ref())
            .collect();
        let process = OSSandboxedProcess::new(
            &policy,
            &process_config.executable_path,
            &argv[..],
            &envp[..],
            process_config.cwd.as_deref(),
            process_config.stdin,
            process_config.stdout,
            process_config.stderr,
        )?;
        broker_pipe.set_remote_process(process.get_pid())?;
        let mut broker_pipe = IPCMessagePipe::new(broker_pipe);
        let runtime_policy = policy.get_runtime_policy(); // free resources kept open before passing it to the 'static manager thread
        std::thread::spawn(move || {
            // TODO: wait for the initial child message before returning
            // TODO: bind manager thread lifetime to the worker lifetime (cleanup in drop?)
            let mut has_lowered_privileges = false;
            loop {
                let request = match broker_pipe.recv() {
                    Ok(Some(m)) => m,
                    Ok(None) => {
                        if !has_lowered_privileges {
                            warn!("Manager thread exiting, child closed its IPC socket before lowering privileges");
                            break;
                        }
                        debug!("Manager thread exiting cleanly, worker closed its IPC socket");
                        break;
                    }
                    Err(e) => {
                        warn!("Manager thread exiting: error when receiving IPC: {:?}", e);
                        break;
                    }
                };
                debug!("Received request: {:?}", &request);
                let (resp, handle) = match request {
                    // Handle OS-agnostic requests
                    IPCRequest::LowerFinalSandboxPrivilegesAsap if !has_lowered_privileges => {
                        has_lowered_privileges = true;
                        (IPCResponse::PolicyApplied(runtime_policy.clone()), None)
                    }
                    other => handle_os_specific_request(other, &runtime_policy),
                };
                debug!("Sending response: {:?} (handle={:?})", &resp, &handle);
                if let Err(e) = broker_pipe.send(&resp, handle.as_ref()) {
                    warn!("Broker thread exiting: error when sending IPC: {:?}", e);
                    break;
                }
            }
        });
        Ok(Self { process })
    }

    pub fn get_pid(&self) -> u64 {
        self.process.get_pid()
    }
}
