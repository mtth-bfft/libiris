use iris_policy::Policy;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum IPCRequest {
    // Initial message sent by workers if they load a helper library (e.g. on Linux)
    // and they are ready to enforce their final sandboxing policy permanently
    InitializationRequest,
    // Worker request to open or create a file (possibly with a directory handle attached, in which case `path` is relative to that directory)
    OpenFile { path: String, flags: libc::c_int },
    // Raw system call that is not allowed by the seccomp policy
    Syscall { nb: i64, args: [i64; 6], ip: i64 },
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum IPCResponse {
    InitializationResponse {
        policy_applied: Box<Policy<'static>>,
        seccomp_filter_to_apply: Vec<u8>,
    },
    SyscallResult(i64),
}
