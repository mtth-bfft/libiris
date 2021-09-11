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
    ) -> Result<Self, String>
    where
        Self: std::marker::Sized;

    // Returns the ID of the worker process
    fn get_pid(&self) -> u64;

    // Blocks until the process exits, and returns its exit code
    fn wait_for_exit(&mut self) -> Result<u64, String>;

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
