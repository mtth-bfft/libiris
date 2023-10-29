#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleError {
    InvalidHandleValue {
        raw_value: u64,
    },
    InternalOsOperationFailed {
        description: &'static str,
        raw_handle: u64,
        os_code: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcError<'a> {
    UnexpectedHandleWithPayload {
        payload: &'a [u8],
    },
    InvalidProcessID {
        pid: u64,
    },
    UnableToOpenProcessOnTheOtherEnd {
        pid: u64,
        os_code: u64,
    },
    PayloadTooBigToTransmit {
        truncated_payload: &'a [u8],
    },
    PayloadTooBigToSerialize {
        payload: &'a str,
    },
    PayloadTooBigToDeserialize {
        payload: &'a [u8],
    },
    InternalSerializationError {
        description: &'a str,
    },
    InternalDeserializationError {
        description: &'a str,
        payload: &'a [u8],
    },
    InternalOsOperationFailed {
        description: &'a str,
        os_code: u64,
    },
    InvalidHandleValueReceived {
        raw_value: u64,
    },
}

impl From<HandleError> for IpcError<'static> {
    fn from(e: HandleError) -> Self {
        match e {
            HandleError::InvalidHandleValue { raw_value } => {
                Self::InvalidHandleValueReceived { raw_value }
            }
            HandleError::InternalOsOperationFailed {
                description,
                os_code,
                ..
            } => Self::InternalOsOperationFailed {
                description,
                os_code,
            },
        }
    }
}
