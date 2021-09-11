mod api;

// OS-specific lockdown functions
#[cfg_attr(target_os = "linux", path = "linux/lockdown.rs")]
#[cfg_attr(target_os = "windows", path = "windows/lockdown.rs")]
mod lockdown;

pub use api::*;
