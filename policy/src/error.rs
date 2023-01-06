use std::ffi::CString;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PolicyError {
    HandleNotInheritable {
        handle_raw_value: u64,
    },
    UnsupportedFilesystemPath {
        path: CString,
    },
    UnsupportedRegistryPath {
        path: CString,
    },
    InvalidHandle {
        raw_value: u64,
    },
    HandleOsOperationFailed {
        operation: String,
        handle_raw_value: u64,
        os_code: u64,
    },
}
