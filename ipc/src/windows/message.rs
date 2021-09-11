use iris_policy::Policy;
use serde::{Deserialize, Serialize};
use winapi::shared::basetsd::ULONG_PTR;
use winapi::shared::ntdef::{LONGLONG, NTSTATUS, ULONG};
use winapi::um::winnt::ACCESS_MASK;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum IPCRequest {
    // Initial message sent by workers to signal they are ready to enforce their final
    // sandboxing policy permanently
    LowerFinalSandboxPrivilegesAsap,
    // Worker request to open or create a file (possibly with a directory handle attached, in which case `path` is relative to that directory)
    NtCreateFile {
        desired_access: ACCESS_MASK,
        path: String,
        allocation_size: LONGLONG,
        file_attributes: ULONG,
        share_access: ULONG,
        create_disposition: ULONG,
        create_options: ULONG,
        ea: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum IPCResponse {
    // Acknowledgement of LowerFinalSandboxPrivilegesAsap
    PolicyApplied(Policy<'static>),
    NtCreateFile {
        io_status: ULONG_PTR,
        code: NTSTATUS,
    },
    GenericError(NTSTATUS),
}
