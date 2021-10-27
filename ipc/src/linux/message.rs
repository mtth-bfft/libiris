use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum IPCRequestV1 {
    // Syscall intercepted by seccomp-bpf
    Syscall {
        arch: u32,
        nr: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        arg6: u64,
    },
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum IPCResponseV1 {
    // Initial message sent by the broker to its worker
    LateMitigations {
        seccomp_trap_bpf: Option<Vec<u8>>,
    },
    // Generic error message, something is wrong in our library itself
    InternalError(u64),
    // Syscall result code (or 0 if the syscall is successful and a handle is attached)
    SyscallResult(i64),
}
