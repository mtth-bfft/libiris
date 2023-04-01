#![no_std]
#![cfg(target_os = "linux")]

#[macro_use]
mod error;

mod capabilities;
mod entry;

pub use entry::{clone_entrypoint, EntrypointParameters};
