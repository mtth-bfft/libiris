mod broker;
mod error;
mod policy;
mod process_config;

pub use broker::*;
pub use error::*;
pub use policy::*;
pub use process_config::*;

// OS-specific modules

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

// Maximum number of handles which can be referenced in a policy
// Fixed to the maximum array size for which traits are automatically
// derived as of now.
pub const IRIS_MAX_HANDLES_PER_POLICY: usize = 32;
