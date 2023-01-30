#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcError {
    UnexpectedHandleWithPayload {
        payload: Vec<u8>,
    },
    TooManyHandlesWithPayload {
        payload: Vec<u8>,
    },
    InvalidProcessID {
        pid: u64,
    },
    UnableToOpenProcessOnTheOtherEnd {
        pid: u64,
        os_code: u64,
    },
    PayloadTooBigToTransmit {
        truncated_payload: Vec<u8>,
    },
    PayloadTooBigToSerialize {
        payload: String,
    },
    PayloadTooBigToDeserialize {
        payload: Vec<u8>,
    },
    InternalSerializationError {
        payload: String,
        description: String,
    },
    InternalDeserializationError {
        payload: Vec<u8>,
        description: String,
    },
    InternalOsOperationFailed {
        os_code: u64,
        description: String,
    },
    UnexpectedMessageInThisContext {
        received_type: String,
    },
}
