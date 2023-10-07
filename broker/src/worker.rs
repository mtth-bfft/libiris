use crate::error::BrokerError;
use crate::os::brokered_syscalls::handle_os_specific_request;
use crate::os::process::OSSandboxedProcess;
use crate::process::CrossPlatformSandboxedProcess;
use crate::ProcessConfig;
use iris_ipc::{CrossPlatformMessagePipe, IPCMessagePipe, IPC_HANDLE_ENV_NAME, IPC_MESSAGE_MAX_SIZE};
use iris_ipc::os::{OSMessagePipe, IPCRequest, IPCResponse};
use iris_policy::{Policy, CrossPlatformHandle};
use log::{debug, warn};
use std::ffi::CString;

#[derive(Debug)]
pub struct Worker {
    process: OSSandboxedProcess,
}

impl Worker {
    pub fn new(process_config: &ProcessConfig, policy: &Policy) -> Result<Self, BrokerError> {
        let mut buf = [0u8; IPC_MESSAGE_MAX_SIZE];
        let (mut broker_pipe, worker_pipe) =
            OSMessagePipe::new().map_err(|_| BrokerError::WorkerCommunicationError)?;
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
        let mut process_config = process_config.clone();
        process_config.set_environment_variable(ipc_handle_var)?;
        let process = OSSandboxedProcess::new(&policy, &process_config)?;
        let worker_pid = process.get_pid();
        broker_pipe
            .set_remote_process(worker_pid)
            .map_err(|_| BrokerError::WorkerCommunicationError)?;
        let mut broker_pipe = IPCMessagePipe::new(broker_pipe); // upgrade to a serializing/deserializing pipe

        // Free resources kept open before passing it to the 'static manager thread
        let runtime_policy = policy.get_runtime_policy();
        // Be careful not to leak a handle to the worker's side of the pipe, otherwise we would not detect
        // when the worker dies and the counterpart handle to the IPC pipe is closed.
        drop(worker_pipe_handle);

        match broker_pipe.recv(&mut buf) {
            Ok(Some(IPCRequest::InitializationRequest)) => (),
            Ok(Some(_)) => {
                return Err(BrokerError::UnexpectedWorkerMessage);
            }
            Ok(None) => return Err(BrokerError::ProcessExitedDuringInitialization),
            Err(_) => return Err(BrokerError::WorkerCommunicationError),
        };
        debug!("Child process is initializing its sandboxing helper library");
        let resp = Self::compute_initialization_response(&runtime_policy, worker_pid);
        broker_pipe
            .send(&resp, None, &mut buf)
            .map_err(|_| BrokerError::WorkerCommunicationError)?;

        // TODO: bind manager thread lifetime to the worker lifetime (cleanup in drop?)
        std::thread::spawn(move || loop {
            let request: IPCRequest = match broker_pipe.recv(&mut buf) {
                Ok(Some(m)) => m,
                Ok(None) => {
                    debug!("Manager thread exiting cleanly, worker closed its IPC socket");
                    break;
                }
                other => {
                    warn!(
                        "Manager thread exiting because of unexpected message from IPC: {:?}",
                        other
                    );
                    break;
                }
            };
            debug!("Received request: {:?}", &request);
            let (resp, handle) = handle_os_specific_request(request, &runtime_policy);
            debug!("Sending response: {:?} (handle={:?})", &resp, &handle);
            if let Err(e) = broker_pipe.send(&resp, handle.as_ref(), &mut buf) {
                warn!("Broker thread exiting: error when sending IPC: {:?}", e);
                break;
            }
        });
        Ok(Self { process })
    }

    pub fn get_pid(&self) -> u64 {
        self.process.get_pid()
    }

    #[cfg(target_os = "linux")]
    fn compute_initialization_response(policy: &Policy<'static>, worker_pid: u64) -> IPCResponse {
        let seccomp_filter_to_apply = match crate::os::seccomp::compute_seccomp_filter(
            worker_pid,
            policy.is_audit_only(),
        ) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("Unable to create a seccomp filter ({}), worker will run with access to many more system calls than it needs", e);
                vec![]
            }
        };
        debug!("Seccomp filter: {} bytes", seccomp_filter_to_apply.len());

        IPCResponse::InitializationResponse {
            policy_applied: Box::new(policy.clone()),
            seccomp_filter_to_apply,
        }
    }

    #[cfg(target_os = "windows")]
    fn compute_initialization_response(policy: &Policy<'static>, _worker_pid: u64) -> IPCResponse {
        IPCResponse::InitializationResponse {
            policy_applied: Box::new(policy.clone()),
        }
    }
}
