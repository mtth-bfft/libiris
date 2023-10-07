use crate::{IrisStatus, IRIS_MAX_HANDLES_PER_POLICY};
use core::ffi::{c_char, c_void, CStr};
use iris_policy::{CrossPlatformHandle, Policy, os::Handle};
use std::ffi::CString;
pub use iris_policy::{PolicyLogCallback, PolicyVerdict, os::PolicyRequest};

#[cfg(target_os = "linux")]
pub use crate::linux::IrisPolicyRequest;
#[cfg(target_os = "windows")]
pub use crate::windows::IrisPolicyRequest;

pub type IrisPolicyHandle = *mut c_void;

pub(crate) struct SelfContainedPolicy {
    pub(crate) inner: Policy<'static>,
    referenced_handles: Vec<Option<Handle>>,
}

#[no_mangle]
pub extern "C" fn iris_policy_new_nothing_allowed() -> IrisPolicyHandle {
    let policy = SelfContainedPolicy {
        inner: Policy::nothing_allowed(),
        referenced_handles: vec![None; IRIS_MAX_HANDLES_PER_POLICY],
    };
    Box::into_raw(Box::new(policy)) as IrisPolicyHandle
}

#[no_mangle]
pub extern "C" fn iris_policy_new_audit() -> IrisPolicyHandle {
    let policy = SelfContainedPolicy {
        inner: Policy::unsafe_testing_audit_only(),
        referenced_handles: vec![None; IRIS_MAX_HANDLES_PER_POLICY],
    };
    Box::into_raw(Box::new(policy)) as IrisPolicyHandle
}

/// Frees all memory allocated for a policy.
/// # Safety
/// The handle passed must be a valid handle returned by iris_policy_new_nothing_allowed(),
/// and that handle must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn iris_policy_free(policy: IrisPolicyHandle) {
    let policy = Box::from_raw(policy as *mut SelfContainedPolicy);
    // Destructure the fields to drop them in the right order
    let SelfContainedPolicy {
        inner,
        referenced_handles,
    } = *policy;
    drop(inner);
    // leak each one (we don't have ownership, they are just supposed to be references)
    for handle in referenced_handles.into_iter().flatten() {
        handle.into_raw();
    }
}

/// Allows processes created with the given policy to inherit a specific handle or file descriptor.
/// # Safety
/// The policy handle must be valid, and the file descriptor or handle to inherit must be valid too.
/// This function does not take ownership of the handle passed: it must remain valid at least until
/// the policy is freed, and callers remain in charge of closing it after.
#[no_mangle]
pub unsafe extern "C" fn iris_policy_allow_inherit_handle(
    policy: IrisPolicyHandle,
    handle: u64,
) -> IrisStatus {
    if policy.is_null() {
        return IrisStatus::InvalidArguments;
    }
    let handle = match Handle::from_raw(handle) {
        Ok(h) => h,
        Err(e) => return IrisStatus::from(e),
    };
    let mut policy = Box::from_raw(policy as *mut SelfContainedPolicy);
    let handle_ref = match policy.referenced_handles.iter_mut().find(|h| h.is_none()) {
        Some(h) => {
            *h = Some(handle);
            h.as_ref().unwrap()
        }
        None => return IrisStatus::TooManyHandles,
    };
    // Make the reference 'static. This is unsafe, but right now there is no simple
    // way to show the borrow checker that the handle will remain valid for at least
    // as long as the Policy
    let handle_ref = &*(handle_ref as *const Handle);
    let res = policy.inner.allow_inherit_handle(handle_ref);
    Box::leak(policy);
    match res {
        Ok(_) => IrisStatus::Success,
        Err(e) => IrisStatus::from(e),
    }
}

/// Allows processes created with the given policy to read from a specific exact file path
/// # Safety
/// The policy handle must be valid, and the path must be an UTF-8-encoded NULL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn iris_policy_allow_file_read(
    policy: IrisPolicyHandle,
    path: *const c_char,
) -> IrisStatus {
    if policy.is_null() || path.is_null() {
        return IrisStatus::InvalidArguments;
    }
    let path = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return IrisStatus::NonUtf8Path,
    };
    let mut policy = Box::from_raw(policy as *mut SelfContainedPolicy);
    let res = policy.inner.allow_file_read(path);
    Box::leak(policy);
    match res {
        Ok(_) => IrisStatus::Success,
        Err(e) => IrisStatus::from(e),
    }
}

/// Allows processes created with the given policy to write to a specific exact file path, or
/// delete that file.
/// # Safety
/// The policy handle must be valid, and the path must be an UTF-8-encoded NULL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn iris_policy_allow_file_write(
    policy: IrisPolicyHandle,
    path: *const c_char,
) -> IrisStatus {
    if policy.is_null() || path.is_null() {
        return IrisStatus::InvalidArguments;
    }
    let path = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return IrisStatus::NonUtf8Path,
    };
    let mut policy = Box::from_raw(policy as *mut SelfContainedPolicy);
    let res = policy.inner.allow_file_write(path);
    Box::leak(policy);
    match res {
        Ok(_) => IrisStatus::Success,
        Err(e) => IrisStatus::from(e),
    }
}

/// Allows processes created with the given policy to block other processes from reading, writing
/// and/or deleting a specific exact file path
/// # Safety
/// The policy handle must be valid, and the path must be an UTF-8-encoded NULL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn iris_policy_allow_file_lock(
    policy: IrisPolicyHandle,
    path: *const c_char,
    block_other_readers: bool,
    block_other_writers: bool,
    block_other_deleters: bool,
) -> IrisStatus {
    if policy.is_null() || path.is_null() {
        return IrisStatus::InvalidArguments;
    }
    let path = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return IrisStatus::NonUtf8Path,
    };
    let mut policy = Box::from_raw(policy as *mut SelfContainedPolicy);
    let res = policy.inner.allow_file_lock(
        path,
        block_other_readers,
        block_other_writers,
        block_other_deleters,
    );
    Box::leak(policy);
    match res {
        Ok(_) => IrisStatus::Success,
        Err(e) => IrisStatus::from(e),
    }
}

/// Allows processes created with the given policy to list and read files from a directory and all
/// its subdirectories.
/// # Safety
/// The policy handle must be valid, and the path must be an UTF-8-encoded NULL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn iris_policy_allow_dir_read(
    policy: IrisPolicyHandle,
    path: *const c_char,
) -> IrisStatus {
    if policy.is_null() || path.is_null() {
        return IrisStatus::InvalidArguments;
    }
    let path = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return IrisStatus::NonUtf8Path,
    };
    let mut policy = Box::from_raw(policy as *mut SelfContainedPolicy);
    let res = policy.inner.allow_dir_read(path);
    Box::leak(policy);
    match res {
        Ok(_) => IrisStatus::Success,
        Err(e) => IrisStatus::from(e),
    }
}

/// Allows processes created with the given policy to write to files within a directory and all its
/// subdirectories, and to remove those files.
/// # Safety
/// The policy handle must be valid, and the path must be an UTF-8-encoded NULL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn iris_policy_allow_dir_write(
    policy: IrisPolicyHandle,
    path: *const c_char,
) -> IrisStatus {
    if policy.is_null() || path.is_null() {
        return IrisStatus::InvalidArguments;
    }
    let path = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return IrisStatus::NonUtf8Path,
    };
    let mut policy = Box::from_raw(policy as *mut SelfContainedPolicy);
    let res = policy.inner.allow_dir_write(path);
    Box::leak(policy);
    match res {
        Ok(_) => IrisStatus::Success,
        Err(e) => IrisStatus::from(e),
    }
}

/// Allows processes created with the given policy to block other processes from reading, writing
/// and/or deleting files and directories in a directory and all its subdirectories.
/// # Safety
/// The policy handle must be valid, and the path must be an UTF-8-encoded NULL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn iris_policy_allow_dir_lock(
    policy: IrisPolicyHandle,
    path: *const c_char,
    block_other_readers: bool,
    block_other_writers: bool,
    block_other_deleters: bool,
) -> IrisStatus {
    if policy.is_null() || path.is_null() {
        return IrisStatus::InvalidArguments;
    }
    let path = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return IrisStatus::NonUtf8Path,
    };
    let mut policy = Box::from_raw(policy as *mut SelfContainedPolicy);
    let res = policy.inner.allow_dir_lock(
        path,
        block_other_readers,
        block_other_writers,
        block_other_deleters,
    );
    Box::leak(policy);
    match res {
        Ok(_) => IrisStatus::Success,
        Err(e) => IrisStatus::from(e),
    }
}

#[repr(C, u8)]
pub enum IrisPolicyVerdict {
    Granted,
    DeniedByPolicy {
        why: *const c_char,
    },
    DelegationToSandboxNotSupported {
        why: *const c_char,
    },
    InvalidRequestParameters {
        argument_name: *const c_char,
        why: *const c_char,
    },
}

impl From<&PolicyVerdict> for IrisPolicyVerdict {
    fn from(rust_enum: &PolicyVerdict) -> Self {
        match rust_enum {
            PolicyVerdict::Granted => Self::Granted,
            PolicyVerdict::DeniedByPolicy { why } => Self::DeniedByPolicy {
                why: CString::new(why.as_str()).unwrap().into_raw(),
            },
            PolicyVerdict::DelegationToSandboxNotSupported { why } => {
                Self::DelegationToSandboxNotSupported {
                    why: CString::new(why.as_str()).unwrap().into_raw(),
                }
            }
            PolicyVerdict::InvalidRequestParameters { argument_name, why } => {
                Self::InvalidRequestParameters {
                    argument_name: CString::new(argument_name.as_str()).unwrap().into_raw(),
                    why: CString::new(why.as_str()).unwrap().into_raw(),
                }
            }
        }
    }
}

impl Drop for IrisPolicyVerdict {
    fn drop(&mut self) {
        match *self {
            Self::Granted => (),
            Self::DeniedByPolicy { why } => drop(unsafe { CString::from_raw(why as *mut i8) }),
            Self::DelegationToSandboxNotSupported { why } => {
                drop(unsafe { CString::from_raw(why as *mut i8) })
            }
            Self::InvalidRequestParameters { argument_name, why } => {
                drop(unsafe { CString::from_raw(argument_name as *mut i8) });
                drop(unsafe { CString::from_raw(why as *mut i8) });
            }
        }
    }
}

pub type IrisPolicyLogCallback = unsafe extern "C" fn(
    request: &IrisPolicyRequest,
    verdict: &IrisPolicyVerdict,
    context: *const c_void,
);

// Internal type defined around *const c_void, just to mark it self to pass between
// threads. Callers of iris_policy_add_log_callback are in charge of only passing
// multithread-safe context pointers through here.
#[derive(Clone, Copy)]
struct IrisPolicyLogCallbackContext(*const c_void);
unsafe impl Send for IrisPolicyLogCallbackContext {}
unsafe impl Sync for IrisPolicyLogCallbackContext {}

#[no_mangle]
pub extern "C" fn iris_policy_add_log_callback(
    policy: IrisPolicyHandle,
    callback: IrisPolicyLogCallback,
    context: *const c_void,
) -> IrisStatus {
    if policy.is_null() {
        return IrisStatus::InvalidArguments;
    }
    let context = IrisPolicyLogCallbackContext(context);
    let mut policy = unsafe { Box::from_raw(policy as *mut SelfContainedPolicy) };
    policy
        .inner
        .add_log_callback(Box::new(move |request, verdict| {
            let context = &context;
            let ffi_request = IrisPolicyRequest::from(request);
            let ffi_verdict = IrisPolicyVerdict::from(verdict);
            unsafe {
                (callback)(&ffi_request, &ffi_verdict, context.0);
            }
        }));
    Box::leak(policy);
    IrisStatus::Success
}
