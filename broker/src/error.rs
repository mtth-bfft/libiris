use iris_ipc::IpcError;
use iris_policy::PolicyError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerError {
    CannotUseReservedEnvironmentVariable { name: String },
    MissingCommandLine,
    CannotBuildPolicyForWorker(PolicyError),
    WorkerCommunicationError(IpcError),
    InternalOsOperationFailed { description: String, os_code: u64 },
}

impl From<PolicyError> for BrokerError {
    fn from(err: PolicyError) -> Self {
        Self::CannotBuildPolicyForWorker(err)
    }
}

impl From<IpcError> for BrokerError {
    fn from(err: IpcError) -> Self {
        Self::WorkerCommunicationError(err)
    }
}
