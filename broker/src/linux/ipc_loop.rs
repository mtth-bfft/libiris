use log::{debug, error, warn};
use crate::BrokerError;
use iris_ipc::{CrossPlatformIpcChannel, IPC_MESSAGE_MAX_SIZE, os::IpcChannel};
use iris_ipc_messages::os::{IPCRequest, IPCResponse};
use iris_policy::Policy;
use crate::os::brokered_syscalls::{proxied_open_file, proxied_syscall};

pub(crate) fn start_ipc_loop(mut channel: IpcChannel, policy: Policy<'static>, worker_pid: u64) -> Result<(), BrokerError> {
    let mut buf = [0u8; IPC_MESSAGE_MAX_SIZE];
    match channel.recv(&mut buf) {
        Ok(Some((IPCRequest::InitializationRequest, None))) => (),
        Ok(Some(_)) => {
            return Err(BrokerError::UnexpectedWorkerMessage);
        }
        Ok(None) => return Err(BrokerError::ProcessExitedDuringInitialization),
        Err(_) => return Err(BrokerError::WorkerCommunicationError),
    };
    debug!("Child process is initializing its sandboxing helper library");
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

    let resp = IPCResponse::InitializationResponse {
        policy_applied: policy.clone(),
        seccomp_filter_to_apply: &seccomp_filter_to_apply,
    };
    channel
        .send(&resp, None, &mut buf)
        .map_err(|_| BrokerError::WorkerCommunicationError)?;

    std::thread::Builder::new()
        .name(format!("iris-{}-broker", worker_pid))
        .spawn(move || {
            loop {
                let request: IPCRequest = match channel.recv(&mut buf) {
                    Ok(Some((m, None))) => m,
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
                let (resp, handle) = match request {
                    IPCRequest::OpenFile { path, flags } => proxied_open_file(&policy, path, flags),
                    IPCRequest::Syscall { nb, args, ip } => proxied_syscall(&policy, nb, args, ip),
                    unknown => {
                        error!("Unexpected request from worker: {:?}", unknown);
                        (IPCResponse::SyscallResult(-(libc::EINVAL as i64)), None)
                    }
                };
                debug!("Sending response: {:?} (handle={:?})", &resp, &handle);
                if let Err(e) = channel.send(&resp, handle.as_ref(), &mut buf) {
                    warn!("Broker thread exiting: error when sending IPC: {:?}", e);
                    break;
                }
            }
        })
        .map_err(|e| BrokerError::InternalOsOperationFailed {
            description: format!("cannot create ipc thread: {}", e),
            os_code: 0,
        })?;

    Ok(())
}
