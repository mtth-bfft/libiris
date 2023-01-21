use crate::error::BrokerError;
use crate::ProcessConfig;
use iris_policy::Policy;

pub trait CrossPlatformSandboxedProcess {
    // Creates a worker process with the given configuration
    fn new(policy: &Policy, process_config: &ProcessConfig) -> Result<Self, BrokerError>
    where
        Self: std::marker::Sized;

    // Returns the ID of the worker process
    fn get_pid(&self) -> u64;
}
