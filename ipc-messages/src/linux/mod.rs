#![allow(clippy::large_enum_variant)]
use iris_policy::Policy;
use serde::{Deserialize, Serialize};

// Arbitrary placeholder value used by the broker when generating Seccomp filters
// on Linux, and replaced by actual addresses by the worker. We could inspect the
// worker's memory from the broker to resolve addresses directly, but this constant
// is way simpler. Put here since it is a form of "communication" between both
// parts, and it needs to be kept in sync between both.
pub const IPC_SECCOMP_CALL_SITE_PLACEHOLDER: u64 = 0xCAFECAFEC0DEC0DE;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub enum IPCRequest<'a> {
    // Initial message sent by workers if they load a helper library (e.g. on Linux)
    // and they are ready to enforce their final sandboxing policy permanently
    InitializationRequest,
    // Worker request to open or create a file (possibly with a directory handle attached, in which case `path` is relative to that directory)
    OpenFile { path: &'a str, flags: libc::c_int },
    // Raw system call that is not allowed by the seccomp policy
    Syscall { nb: i64, args: [i64; 6], ip: i64 },
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub enum IPCResponse<'a> {
    InitializationResponse {
        policy_applied: Policy<'static>,
        seccomp_filter_to_apply: &'a [u8],
    },
    SyscallResult(i64),
}
