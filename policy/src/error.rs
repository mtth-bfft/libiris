use iris_ipc::HandleError;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PolicyError {
    InvalidHandleValue { raw_value: u64 },
    HandleNotInheritable { handle_raw_value: u64 },
    UnsupportedFilesystemPath { path: String },
    UnsupportedRegistryPath { path: String },
    InternalOsOperationFailed { description: String, os_code: u64 },
}

impl From<HandleError> for PolicyError {
    fn from(e: HandleError) -> Self {
        match e {
            HandleError::InvalidHandleValue { raw_value } => Self::InvalidHandleValue { raw_value },
            HandleError::InternalOsOperationFailed {
                description,
                os_code,
                ..
            } => Self::InternalOsOperationFailed {
                description: description.to_owned(),
                os_code,
            },
        }
    }
}
