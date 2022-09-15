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
    // Worker request to open or create a file
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
    // Worker request to open or create a registry key
    NtCreateKey {
        desired_access: ACCESS_MASK,
        path: String,
        title_index: ULONG,
        class: Option<String>,
        create_options: ULONG,
        do_create: bool,
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
    NtCreateKey {
        disposition: ULONG,
        code: NTSTATUS,
    },
    GenericError(NTSTATUS),
}
