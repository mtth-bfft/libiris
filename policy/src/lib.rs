// Common modules
mod error;
mod handle;
mod policy;

pub use error::PolicyError;
pub use handle::{CrossPlatformHandle, Handle};
pub use policy::Policy;

// OS-specific modules

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
mod os;

pub use os::handle::{downcast_to_handle, set_unmanaged_handle_inheritable};
pub use os::path::derive_all_file_paths_from_path;

#[cfg(windows)]
pub use os::path::derive_all_reg_key_paths_from_path;
