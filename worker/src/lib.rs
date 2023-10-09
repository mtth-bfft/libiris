// OS-specific modules
#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
mod os;

use iris_ipc::{CrossPlatformIpcChannel, CrossPlatformHandle, IPC_HANDLE_ENV_NAME};
use iris_ipc::os::{Handle, IpcChannel};
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
    let handle = unsafe { Handle::from_raw(handle) }.expect("invalid IPC handle environment variable");
    let ipc = IpcChannel::from_handle(handle);
    crate::os::lockdown::lower_final_sandbox_privileges(ipc);

    info!("Now running with final privileges");
}
