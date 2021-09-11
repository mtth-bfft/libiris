// Common modules
mod handle;
mod policy;

// OS-specific modules

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
mod os;

pub use handle::{CrossPlatformHandle, Handle};
pub use os::handle::{downcast_to_handle, set_unmanaged_handle_inheritable};
pub use policy::Policy;
