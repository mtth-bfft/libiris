use crate::error::BrokerError;
use iris_policy::{Handle, Policy};
use std::ffi::CStr;

pub trait CrossPlatformSandboxedProcess {
    // Creates a worker process with the given configuration
    fn new(
        policy: &Policy,
        exe: &CStr,
        argv: &[&CStr],
        envp: &[&CStr],
        stdin: Option<&Handle>,
        stdout: Option<&Handle>,
        stderr: Option<&Handle>,
    ) -> Result<Self, BrokerError>
    where
        Self: std::marker::Sized;

    // Returns the ID of the worker process
    fn get_pid(&self) -> u64;
}
