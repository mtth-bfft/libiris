// Common modules

mod error;
mod handle;
mod ipc;
mod messagepipe;

pub use error::{HandleError, IpcError};
pub use handle::CrossPlatformHandle;
pub use ipc::IPCMessagePipe;
pub use messagepipe::CrossPlatformMessagePipe;

// OS-specific modules

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
mod os;

pub use os::handle::Handle;
pub use os::handle::{downcast_to_handle, set_unmanaged_handle_inheritable};
pub use os::messagepipe::OSMessagePipe;
