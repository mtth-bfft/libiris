use iris_ipc::MessagePipe;
use iris_policy::{Handle, Policy};
use std::ffi::CStr;
use std::sync::Arc;

pub trait CrossPlatformSandboxedProcess {
    // Creates a worker process with the given configuration
    fn new(
        policy: Policy,
        exe: &CStr,
        argv: &[&CStr],
        envp: &[&CStr],
        broker_pipe: MessagePipe,
        stdin: Option<Arc<Handle>>,
        stdout: Option<Arc<Handle>>,
        stderr: Option<Arc<Handle>>,
    ) -> Result<Arc<Self>, String>
    where
        Self: std::marker::Sized;

    // Returns the ID of the worker process
    fn get_pid(&self) -> u64;

    // Blocks until the process exits, and returns its exit code
    // Returns an error if the process has already exited
    fn wait_for_exit(&self) -> Result<u64, String>;
}
