// Common modules

mod error;
mod process;
mod process_config;
mod worker;

pub use error::BrokerError;
pub use process_config::ProcessConfig;
pub use worker::Worker;

#[cfg(target_os = "windows")]
#[macro_use]
extern crate lazy_static;

// OS-specific modules
#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
mod os;
