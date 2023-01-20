use crate::error::BrokerError;
use crate::os::brokered_syscalls::handle_os_specific_request;
use crate::os::process::OSSandboxedProcess;
use crate::process::CrossPlatformSandboxedProcess;
use crate::ProcessConfig;
use iris_ipc::{
    CrossPlatformMessagePipe, IPCMessagePipe, IPCRequest, IPCResponse, MessagePipe,
    IPC_HANDLE_ENV_NAME,
};
use iris_policy::{CrossPlatformHandle, Policy};
use log::{debug, warn};
use std::ffi::CString;

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
        let process_config = process_config
            .clone()
            .with_environment_variable(ipc_handle_var)?;
        let process = OSSandboxedProcess::new(&policy, &process_config)?;
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
                        (
                            IPCResponse::PolicyApplied(Box::new(runtime_policy.clone())),
                            None,
                        )
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
