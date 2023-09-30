use iris_ipc::HandleError;
use iris_policy::PolicyError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerError {
    ConflictingEnvironmentVariable { name: String },
    MissingCommandLine,
    CannotBuildPolicyForWorker(PolicyError),
    WorkerCommunicationError,
    UnexpectedWorkerMessage,
    InternalOsOperationFailed { description: String, os_code: u64 },
    ProcessExitedDuringInitialization,
}

impl From<HandleError> for BrokerError {
    fn from(err: HandleError) -> Self {
        match err {
            HandleError::InvalidHandleValue { .. } => Self::InternalOsOperationFailed {
                description: "invalid handle value used".to_owned(),
                os_code: 0,
            },
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

impl From<PolicyError> for BrokerError {
    fn from(err: PolicyError) -> Self {
        Self::CannotBuildPolicyForWorker(err)
    }
}
