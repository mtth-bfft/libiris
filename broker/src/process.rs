use iris_policy::{Handle, Policy};
use iris_ipc::{IPCMessagePipe, IPCResponseV1};
use std::ffi::CStr;
use std::sync::Arc;

pub trait CrossPlatformSandboxedProcess {
    // Creates a worker process with the given configuration
    fn new(
        policy: &Policy,
        exe: &CStr,
        argv: &[&CStr],
        envp: &[&CStr],
        stdin: Option<Arc<Handle>>,
        stdout: Option<Arc<Handle>>,
        stderr: Option<Arc<Handle>>,
    ) -> Result<Self, String>
    where
        Self: std::marker::Sized;

    // Returns the ID of the worker process
    fn get_pid(&self) -> u64;

    // Blocks until the process exits, and returns its exit code
    // Returns an error if the process has already exited
    fn wait_for_exit(&self) -> Result<u64, String>;

    // Spawn a background thread to server IPC requests
    fn start_serving_ipc_requests(&mut self, channel: IPCMessagePipe, policy: Arc<Policy>) -> Result<(), String>;

    // Get the IPC message that will be sent to the worker to tell it what
    // to apply as post-process-creation mitigations
    fn get_late_mitigations(&self) -> Result<IPCResponseV1, String>;

    /*
        // Returns true if the worker process has exited
        fn has_exited(&self) -> bool;

        // Returns the OS-specific exit code of the worker process if it has exited
        fn get_exit_code(&self) -> Option<u64>;

        // Blocks until the worker process exits
        fn wait_for_exit(&self) -> ();

        // Terminate
        fn terminate(&self) -> ();
    */
}
