// Common modules

mod error;
mod ipc;
mod messagepipe;

pub use error::IpcError;

// OS-specific modules

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
mod os;

pub use ipc::IPCMessagePipe;
pub use messagepipe::CrossPlatformMessagePipe;
pub use os::message::{IPCRequest, IPCResponse};
pub use os::messagepipe::OSMessagePipe as MessagePipe;

// Name of the environment variable used to pass the IPC socket handle/file
// descriptor number to child processes
pub const IPC_HANDLE_ENV_NAME: &str = "SANDBOX_IPC_HANDLE";

// Arbitrary placeholder value used by the broker when generating Seccomp filters
// on Linux, and replaced by actual addresses by the worker. We could inspect the
// worker's memory from the broker to resolve addresses directly, but this constant
// is way simpler. Put here since it is a form of "communication" between both
// parts, and it needs to be kept in sync between both.
#[cfg(target_os = "linux")]
pub const IPC_SECCOMP_CALL_SITE_PLACEHOLDER: u64 = 0xCAFECAFEC0DEC0DE;
