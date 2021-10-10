use crate::lockdown;
use iris_ipc::{
    CrossPlatformMessagePipe, IPCMessagePipe, IPCRequestV1, IPCResponseV1, MessagePipe,
    IPC_HANDLE_ENV_NAME,
};
use iris_policy::{CrossPlatformHandle, Handle};

pub fn lower_final_sandbox_privileges_asap() {
    println!(" [.] Lowering final sandbox privileges");

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
    let (mut ipc, _) =
        IPCMessagePipe::new_client(pipe).expect("unable to open IPC channel to broker");

    ipc.send(&IPCRequestV1::LowerFinalSandboxPrivilegesAsap, None)
        .expect("unable to send IPC message to broker");
    let resp = ipc
        .recv()
        .expect("unable to read worker policy from broker");
    let pol = match resp {
        Some(IPCResponseV1::PolicyApplied(pol)) => pol,
        other => panic!(
            "unexpected initial response received from broker: {:?}",
            other
        ),
    };
    println!(" [.] Policy applied: {:?}", pol);

    lockdown::lower_final_sandbox_privileges(&pol, ipc);

    println!(" [.] Now running with final privileges");
}
