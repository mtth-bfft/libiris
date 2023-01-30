use crate::lockdown;
use iris_ipc::{CrossPlatformMessagePipe, IPCMessagePipe, MessagePipe, IPC_HANDLE_ENV_NAME};
use iris_policy::{CrossPlatformHandle, Handle};
use log::info;

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
    let ipc = IPCMessagePipe::new(pipe);

    lockdown::lower_final_sandbox_privileges(ipc);

    info!("Now running with final privileges");
}
