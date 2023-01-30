use iris_broker::BrokerError;
use iris_ipc::IpcError;
use iris_policy::PolicyError;

#[repr(u64)]
pub enum IrisStatus {
    // 0x0 : Binding error
    Success = 0,
    InvalidArguments = 1,
    TooManyHandles = 2,
    NonUtf8Path = 3,
    // 0x1000 : PolicyError
    PolicyHandleNotInheritable = 1001,
    PolicyUnsupportedFilesystemPath = 1002,
    PolicyUnsupportedRegistryPath = 1003,
    PolicyInvalidHandle = 1004,
    PolicyHandleOsOperationFailed = 1005,
    // 0x2000 : BrokerError
    BrokerConflictingEnvironmentVariable = 2001,
    BrokerMissingCommandLine = 2002,
    BrokerInternalOsOperationFailed = 2003,
    ProcessExitedDuringInitialization = 2004,
    // 0x3000 : IpcError
    IpcUnexpectedHandleWithPayload = 3001,
    IpcTooManyHandlesWithPayload = 3002,
    IpcInvalidProcessID = 3003,
    IpcUnableToOpenProcessOnTheOtherEnd = 3004,
    IpcPayloadTooBigToTransmit = 3005,
    IpcPayloadTooBigToSerialize = 3006,
    IpcPayloadTooBigToDeserialize = 3007,
    IpcInternalSerializationError = 3008,
    IpcInternalDeserializationError = 3009,
    IpcInternalOsOperationFailed = 3010,
    IpcUnexpectedMessageInThisContext = 3011,
}

impl From<PolicyError> for IrisStatus {
    fn from(err: PolicyError) -> Self {
        match err {
            PolicyError::HandleNotInheritable { .. } => IrisStatus::PolicyHandleNotInheritable,
            PolicyError::UnsupportedFilesystemPath { .. } => {
                IrisStatus::PolicyUnsupportedFilesystemPath
            }
            PolicyError::UnsupportedRegistryPath { .. } => {
                IrisStatus::PolicyUnsupportedRegistryPath
            }
            PolicyError::InvalidHandle { .. } => IrisStatus::PolicyInvalidHandle,
            PolicyError::HandleOsOperationFailed { .. } => {
                IrisStatus::PolicyHandleOsOperationFailed
            }
        }
    }
}

impl From<BrokerError> for IrisStatus {
    fn from(err: BrokerError) -> Self {
        match err {
            BrokerError::ConflictingEnvironmentVariable { .. } => {
                IrisStatus::BrokerConflictingEnvironmentVariable
            }
            BrokerError::MissingCommandLine => IrisStatus::BrokerMissingCommandLine,
            BrokerError::CannotBuildPolicyForWorker(e) => IrisStatus::from(e),
            BrokerError::WorkerCommunicationError(e) => IrisStatus::from(e),
            BrokerError::InternalOsOperationFailed { .. } => {
                IrisStatus::BrokerInternalOsOperationFailed
            }
            BrokerError::ProcessExitedDuringInitialization => {
                IrisStatus::ProcessExitedDuringInitialization
            }
        }
    }
}

impl From<IpcError> for IrisStatus {
    fn from(err: IpcError) -> Self {
        match err {
            IpcError::UnexpectedHandleWithPayload { .. } => {
                IrisStatus::IpcUnexpectedHandleWithPayload
            }
            IpcError::TooManyHandlesWithPayload { .. } => IrisStatus::IpcTooManyHandlesWithPayload,
            IpcError::InvalidProcessID { .. } => IrisStatus::IpcInvalidProcessID,
            IpcError::UnableToOpenProcessOnTheOtherEnd { .. } => {
                IrisStatus::IpcUnableToOpenProcessOnTheOtherEnd
            }
            IpcError::PayloadTooBigToTransmit { .. } => IrisStatus::IpcPayloadTooBigToTransmit,
            IpcError::PayloadTooBigToSerialize { .. } => IrisStatus::IpcPayloadTooBigToSerialize,
            IpcError::PayloadTooBigToDeserialize { .. } => {
                IrisStatus::IpcPayloadTooBigToDeserialize
            }
            IpcError::InternalSerializationError { .. } => {
                IrisStatus::IpcInternalSerializationError
            }
            IpcError::InternalDeserializationError { .. } => {
                IrisStatus::IpcInternalDeserializationError
            }
            IpcError::InternalOsOperationFailed { .. } => IrisStatus::IpcInternalOsOperationFailed,
            IpcError::UnexpectedMessageInThisContext { .. } => {
                IrisStatus::IpcUnexpectedMessageInThisContext
            }
        }
    }
}
