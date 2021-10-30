use iris_policy::{Handle, Policy};
use iris_ipc::{IPCMessagePipe, MessagePipe, IPCResponseV1};
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
