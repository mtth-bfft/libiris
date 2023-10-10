#![allow(clippy::large_enum_variant)]
use iris_policy::Policy;
use serde::{Deserialize, Serialize};
use winapi::shared::basetsd::ULONG_PTR;
use winapi::shared::ntdef::{LONGLONG, NTSTATUS, ULONG};
use winapi::um::winnt::ACCESS_MASK;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum IPCRequest<'a> {
    // Initial message sent by workers if they load a helper library (e.g. on Windows)
    // and they are ready to enforce their final sandboxing policy permanently
    InitializationRequest,
    // Worker request to open or create a file
    NtCreateFile {
        desired_access: ACCESS_MASK,
        path: &'a str,
        allocation_size: LONGLONG,
        file_attributes: ULONG,
        share_access: ULONG,
        create_disposition: ULONG,
        create_options: ULONG,
        ea: &'a [u8],
    },
    // Worker request to open or create a registry key
    NtCreateKey {
        desired_access: ACCESS_MASK,
        path: &'a str,
        title_index: ULONG,
        class: Option<&'a str>,
        create_options: ULONG,
        do_create: bool,
    },
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum IPCResponse {
    InitializationResponse {
        policy_applied: Policy<'static>,
    },
    NtCreateFile {
        io_status: ULONG_PTR,
        code: NTSTATUS,
    },
    NtCreateKey {
        disposition: ULONG,
        code: NTSTATUS,
    },
    SyscallResult(NTSTATUS),
}
