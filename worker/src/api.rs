use crate::lockdown;
use iris_ipc::{
    CrossPlatformMessagePipe, IPCMessagePipe, IPCRequest, IPCResponse, MessagePipe,
    IPC_HANDLE_ENV_NAME,
};
use iris_policy::{CrossPlatformHandle, Handle};
use log::{debug, info};

pub fn lower_final_sandbox_privileges_asap() {
    info!("Lowering final sandbox privileges");

    let handle = std::env::var(IPC_HANDLE_ENV_NAME)
        .expect("missing environment variable containing the IPC handle");
    std::env::remove_var(IPC_HANDLE_ENV_NAME);
    let handle = handle
        .parse::<u64>()
        .expect("invalid IPC handle environment variable contents");
    // This unsafe block takes possession of the handle, which is safe since we are the only ones aware
    // of this environment variable, and we erase it as soon as it is used.
    let handle = unsafe { Handle::new(handle).expect("invalid IPC handle environment variable") };
    let pipe = MessagePipe::from_handle(handle);
    let mut ipc = IPCMessagePipe::new(pipe);

    ipc.send(&IPCRequest::LowerFinalSandboxPrivilegesAsap, None)
        .expect("unable to send IPC message to broker");
    let resp = ipc
        .recv()
        .expect("unable to read worker policy from broker");
    let pol = match resp {
        Some(IPCResponse::PolicyApplied(pol)) => pol,
        other => panic!("unexpected initial response received from broker: {other:?}"),
    };
    debug!("Policy applied: {:?}", pol);

    lockdown::lower_final_sandbox_privileges(&pol, ipc);

    info!("Now running with final privileges");
}
