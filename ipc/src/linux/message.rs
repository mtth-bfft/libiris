use iris_policy::Policy;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum IPCRequest {
    // Initial message sent by workers to signal they are ready to enforce their final
    // sandboxing policy permanently
    LowerFinalSandboxPrivilegesAsap,
    // Worker request to open or create a file (possibly with a directory handle attached, in which case `path` is relative to that directory)
    OpenFile { path: String, flags: libc::c_int },
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum IPCResponse {
    // Acknowledgement of LowerFinalSandboxPrivilegesAsap
    PolicyApplied(Box<Policy<'static>>),
    SyscallResult(i64),
}
