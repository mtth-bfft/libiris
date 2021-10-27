mod api;

// OS-specific mitigation functions
#[cfg_attr(target_os = "linux", path = "linux/late_mitigations.rs")]
#[cfg_attr(target_os = "windows", path = "windows/late_mitigations.rs")]
mod late_mitigations;

pub use api::*;
