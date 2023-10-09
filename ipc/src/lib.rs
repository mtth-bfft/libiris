#![no_std]

// Common modules

mod channel;
mod error;
mod handle;
mod stackbuffer;

pub use channel::CrossPlatformIpcChannel;
pub use error::{HandleError, IpcError};
pub use handle::CrossPlatformHandle;
pub use stackbuffer::StackBuffer;

// OS-specific modules

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
pub mod os;

// Name of the environment variable used to pass the IPC socket handle/file
// descriptor number to child processes
pub const IPC_HANDLE_ENV_NAME: &str = "SANDBOX_IPC_HANDLE";

// Maximum number of bytes a serialized IPC message can take.
pub const IPC_MESSAGE_MAX_SIZE: usize = 64 * 1024;
