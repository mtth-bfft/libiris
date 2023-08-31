use iris_policy::PolicyError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcError<'a> {
    UnexpectedHandleWithPayload {
        payload: &'a [u8],
    },
    HandleOperationFailed(PolicyError),
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
        payload: &'a str,
        description: &'a str,
    },
    InternalDeserializationError {
        payload: &'a [u8],
        description: &'a str,
    },
    InternalOsOperationFailed {
        os_code: u64,
        description: &'a str,
    },
}
