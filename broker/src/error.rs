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

impl From<PolicyError> for BrokerError {
    fn from(err: PolicyError) -> Self {
        Self::CannotBuildPolicyForWorker(err)
    }
}
