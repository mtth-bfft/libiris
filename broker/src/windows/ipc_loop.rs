use crate::os::brokered_syscalls::{proxied_ntcreatefile, proxied_ntcreatekey};
use crate::BrokerError;
use iris_ipc::os::IpcChannel;
use iris_ipc::{CrossPlatformIpcChannel, IPC_MESSAGE_MAX_SIZE};
use iris_ipc_messages::os::{IPCRequest, IPCResponse};
use iris_policy::Policy;
use log::{debug, error, warn};

pub(crate) fn start_ipc_loop(
    mut channel: IpcChannel,
    policy: Policy<'static>,
    worker_pid: u64,
) -> Result<(), BrokerError> {
    let mut buf = [0u8; IPC_MESSAGE_MAX_SIZE];
    std::thread::Builder::new()
        .name(format!("iris-{}-broker", worker_pid))
        .spawn(move || {
            match channel.recv(&mut buf) {
                Ok(Some((IPCRequest::InitializationRequest, None))) => (),
                Ok(Some(_)) => {
                    return Err(BrokerError::UnexpectedWorkerMessage);
                }
                Ok(None) => return Err(BrokerError::ProcessExitedDuringInitialization),
                Err(_) => return Err(BrokerError::WorkerCommunicationError),
            };
            debug!("Child process is initializing its sandboxing helper library");
            let resp = IPCResponse::InitializationResponse {
                policy_applied: policy.clone(),
            };
            channel
                .send(&resp, None, &mut buf)
                .map_err(|_| BrokerError::WorkerCommunicationError)?;

            loop {
                let request: IPCRequest = match channel.recv(&mut buf) {
                    Ok(Some((m, None))) => m,
                    Ok(None) => {
                        debug!("Manager thread exiting cleanly, worker closed its IPC socket");
                        return Ok(());
                    }
                    other => {
                        warn!(
                            "Manager thread exiting because of unexpected message from IPC: {:?}",
                            other
                        );
                        return Err(BrokerError::WorkerCommunicationError);
                    }
                };
                debug!("Received request: {:?}", &request);
                let (resp, handle) = match request {
                    IPCRequest::NtCreateFile {
                        desired_access,
                        path,
                        allocation_size,
                        file_attributes,
                        share_access,
                        create_disposition,
                        create_options,
                        ea,
                    } => proxied_ntcreatefile(
                        &policy,
                        desired_access,
                        path,
                        allocation_size,
                        file_attributes,
                        share_access,
                        create_disposition,
                        create_options,
                        ea,
                    ),
                    IPCRequest::NtCreateKey {
                        desired_access,
                        path,
                        title_index,
                        class,
                        create_options,
                        do_create,
                    } => proxied_ntcreatekey(
                        &policy,
                        desired_access,
                        path,
                        title_index,
                        class,
                        create_options,
                        do_create,
                    ),
                    unknown => {
                        error!("Unexpected request from worker: {:?}", unknown);
                        return Err(BrokerError::WorkerCommunicationError);
                    }
                };
                if let Err(e) = channel.send(&resp, handle.as_ref(), &mut buf) {
                    error!(
                        "Broker ipc thread exiting due to error when replying to worker: {:?}",
                        e
                    );
                    return Err(BrokerError::WorkerCommunicationError);
                }
            }
        })
        .map_err(|e| BrokerError::InternalOsOperationFailed {
            description: format!("cannot create ipc thread: {}", e),
            os_code: 0,
        })?;

    Ok(())
}
