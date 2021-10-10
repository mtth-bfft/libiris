// Common modules

mod ipc;
mod messagepipe;

// OS-specific modules

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
mod os;

pub use ipc::{IPCMessagePipe, IPCVersion};
pub use messagepipe::CrossPlatformMessagePipe;
pub use os::message::{IPCRequestV1, IPCResponseV1};
pub use os::messagepipe::OSMessagePipe as MessagePipe;

// Name of the environment variable used to pass the IPC socket handle/file
// descriptor number to child processes
pub const IPC_HANDLE_ENV_NAME: &str = "SANDBOX_IPC_HANDLE";
