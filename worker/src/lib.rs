use iris_ipc::{
    CrossPlatformHandle, CrossPlatformMessagePipe, Handle, IPCMessagePipe, OSMessagePipe,
};
use log::info;

// OS-specific modules
#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
mod os;

pub use os::messages::{IPCRequest, IPCResponse};

// Name of the environment variable used to pass the IPC socket handle/file
// descriptor number to child processes
pub const IPC_HANDLE_ENV_NAME: &str = "SANDBOX_IPC_HANDLE";

// Maximum number of bytes a serialized IPC message can take.
pub const IPC_MESSAGE_MAX_SIZE: usize = 64 * 1024;

// Arbitrary placeholder value used by the broker when generating Seccomp filters
// on Linux, and replaced by actual addresses by the worker. We could inspect the
// worker's memory from the broker to resolve addresses directly, but this constant
// is way simpler. Put here since it is a form of "communication" between both
// parts, and it needs to be kept in sync between both.
#[cfg(target_os = "linux")]
pub const IPC_SECCOMP_CALL_SITE_PLACEHOLDER: u64 = 0xCAFECAFEC0DEC0DE;

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
    let handle =
        unsafe { Handle::from_raw(handle).expect("invalid IPC handle environment variable") };
    let pipe = OSMessagePipe::from_handle(handle);
    let ipc = IPCMessagePipe::new(pipe);

    os::lockdown::lower_final_sandbox_privileges(ipc);

    info!("Now running with final privileges");
}
