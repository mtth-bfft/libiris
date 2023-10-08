// Common modules

mod error;
mod ipc;
mod messagepipe;
mod stackbuffer;

pub use stackbuffer::StackBuffer;
pub use error::IpcError;
pub use ipc::IPCMessagePipe;
pub use messagepipe::CrossPlatformMessagePipe;

// OS-specific modules

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
pub mod os;

// Name of the environment variable used to pass the IPC socket handle/file
// descriptor number to child processes
pub const IPC_HANDLE_ENV_NAME: &str = "SANDBOX_IPC_HANDLE";

// Maximum number of bytes a serialized IPC message can take.
pub const IPC_MESSAGE_MAX_SIZE: usize = 64 * 1024;
