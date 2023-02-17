use crate::{
    IrisPolicyHandle, IrisProcessConfigHandle, IrisStatus, SelfContainedPolicy,
    SelfContainedProcessConfig,
};
use core::ffi::c_void;
use iris_broker::Worker;

pub type IrisWorkerHandle = *mut c_void;

/// Create a worker object and return a handle to it. The worker will start with the
/// given process configuration, and will only be allowed actions based on the given
/// policy.
/// # Safety
/// Both process configuration and policy handles must be valid, and the worker handle
/// pointer must point to a NULL worker handle.
#[no_mangle]
pub unsafe extern "C" fn iris_worker_new(
    process_config: IrisProcessConfigHandle,
    policy: IrisPolicyHandle,
    worker: *mut IrisWorkerHandle,
) -> IrisStatus {
    if process_config.is_null() || policy.is_null() || worker.is_null() {
        return IrisStatus::InvalidArguments;
    }
    let process_config = Box::from_raw(process_config as *mut SelfContainedProcessConfig);
    let policy = Box::from_raw(policy as *mut SelfContainedPolicy);
    let res = Worker::new(&process_config.inner, &policy.inner);
    Box::leak(process_config);
    Box::leak(policy);
    match res {
        Ok(w) => {
            *worker = Box::into_raw(Box::new(w)) as IrisWorkerHandle;
            IrisStatus::Success
        }
        Err(e) => IrisStatus::from(e),
    }
}

/// Get the PID of a worker's backing process, given a handle to the worker object.
/// # Safety
/// The worker handle must be valid, and the PID output pointer must point to
/// valid writable memory.
#[no_mangle]
pub unsafe extern "C" fn iris_worker_get_pid(
    worker: IrisWorkerHandle,
    pid: *mut u64,
) -> IrisStatus {
    if worker.is_null() || pid.is_null() {
        return IrisStatus::InvalidArguments;
    }
    let worker = Box::from_raw(worker as *mut Worker);
    *pid = worker.get_pid();
    Box::leak(worker);
    IrisStatus::Success
}

/// Frees all memory and resources allocated for a worker, and kills its process
/// if it is still running.
/// # Safety
/// The handle passed must be a valid handle returned by iris_worker_new(),
/// and that handle must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn iris_worker_free(worker: IrisWorkerHandle) {
    drop(Box::from_raw(worker as *mut Worker));
}
