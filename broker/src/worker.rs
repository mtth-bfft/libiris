use crate::error::BrokerError;
use crate::os::ipc_loop::start_ipc_loop;
use crate::os::process::OSSandboxedProcess;
use crate::process::CrossPlatformSandboxedProcess;
use crate::ProcessConfig;
use iris_ipc::{
    os::IpcChannel, CrossPlatformHandle, CrossPlatformIpcChannel, IpcError, IPC_HANDLE_ENV_NAME,
};
use iris_policy::Policy;
use std::ffi::CString;

#[derive(Debug)]
pub struct Worker {
    process: OSSandboxedProcess,
}

impl Worker {
    pub fn new(process_config: &ProcessConfig, policy: &Policy) -> Result<Self, BrokerError> {
        let (mut broker_channel, worker_channel) = IpcChannel::new().map_err(|e| match e {
            IpcError::InternalOsOperationFailed {
                description,
                os_code,
            } => BrokerError::InternalOsOperationFailed {
                description: description.to_owned(),
                os_code,
            },
            _ => BrokerError::InternalOsOperationFailed {
                description: "unknown OS operation failed, cannot create an IPC channel".to_owned(),
                os_code: 0,
            },
        })?;
        let mut worker_channel_handle = worker_channel.into_handle();
        worker_channel_handle.set_inheritable(true)?;
        let mut policy = policy.clone();
        policy.allow_inherit_handle(&worker_channel_handle)?;
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
            worker_channel_handle.as_raw()
        ))
        .unwrap();
        let mut process_config = process_config.clone();
        process_config.set_environment_variable(ipc_handle_var)?;
        let process = OSSandboxedProcess::new(&policy, &process_config)?;
        let worker_pid = process.get_pid();
        broker_channel
            .set_remote_process(worker_pid)
            .map_err(|e| match e {
                IpcError::InternalOsOperationFailed {
                    description,
                    os_code,
                } => BrokerError::InternalOsOperationFailed {
                    description: description.to_owned(),
                    os_code,
                },
                _ => BrokerError::InternalOsOperationFailed {
                    description:
                        "unknown OS operation failed, IPC channel does not accept worker PID"
                            .to_owned(),
                    os_code: 0,
                },
            })?;

        // Free resources kept open before passing it to the 'static manager thread
        let runtime_policy = policy.get_runtime_policy();
        // Deterministically close our handle of the worker's side of the IPC channel
        // so that writing to it will deterministically fail right away if the worker died
        drop(policy);
        drop(worker_channel_handle);

        // FIXME: bind thread lifetime to struct lifetime
        start_ipc_loop(broker_channel, runtime_policy, worker_pid)?;

        Ok(Self { process })
    }

    pub fn get_pid(&self) -> u64 {
        self.process.get_pid()
    }
}
