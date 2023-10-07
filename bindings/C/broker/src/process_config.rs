use crate::IrisStatus;
use core::ffi::{c_char, c_void, CStr};
use core::ptr::null_mut;
use iris_broker::ProcessConfig;
use iris_policy::{CrossPlatformHandle, os::Handle};
use std::ffi::CString;

pub type IrisProcessConfigHandle = *mut c_void;

pub(crate) struct SelfContainedProcessConfig {
    pub(crate) inner: ProcessConfig<'static>,
    stdin_handle: Option<Handle>,
    stdout_handle: Option<Handle>,
    stderr_handle: Option<Handle>,
}

/// Create an IrisProcessConfigHandle with the given commandline to pass to future
/// processes created with this config.
/// # Safety
/// This call is safe as long as executable_path points to a NULL-terminated string,
/// and argv points to a sized-array of length argc.
#[no_mangle]
pub unsafe extern "C" fn iris_process_config_new(
    executable_path: *const c_char,
    argc: usize,
    argv: *const *const c_char,
    process_config: *mut IrisProcessConfigHandle,
) -> IrisStatus {
    if executable_path.is_null() || argv.is_null() || argc == 0 || process_config.is_null() {
        return IrisStatus::InvalidArguments;
    }
    *process_config = null_mut();
    let executable_path = CStr::from_ptr(executable_path).to_owned();
    let argv: Vec<CString> = std::slice::from_raw_parts(argv, argc)
        .iter()
        .map(|cstr| CStr::from_ptr(*cstr).to_owned())
        .collect();

    let out = SelfContainedProcessConfig {
        inner: ProcessConfig::new(executable_path, &argv),
        stdin_handle: None,
        stdout_handle: None,
        stderr_handle: None,
    };
    *process_config = Box::into_raw(Box::new(out)) as *mut c_void;
    IrisStatus::Success
}

/// Frees all memory associated with a process configuration.
/// # Safety
/// This is safe as long as a valid handle is passed coming from iris_process_config_new(),
/// and the handle passed is not used anymore after this call returns.
#[no_mangle]
pub unsafe extern "C" fn iris_process_config_free(process_config: IrisProcessConfigHandle) {
    drop(Box::from_raw(
        process_config as *mut SelfContainedProcessConfig,
    ));
}

/// Sets the initial current working directory of processes created with this configuration.
/// # Safety
/// This is safe as long as a valid handle and a valid NULL-terminated string path are passed.
#[no_mangle]
pub unsafe extern "C" fn iris_process_config_current_working_directory(
    process_config: IrisProcessConfigHandle,
    cwd: *const c_char,
) -> IrisStatus {
    if process_config.is_null() {
        return IrisStatus::InvalidArguments;
    }
    let cwd = if cwd.is_null() {
        None
    } else {
        Some(CStr::from_ptr(cwd).to_owned())
    };
    let mut process_config = Box::from_raw(process_config as *mut SelfContainedProcessConfig);
    let res = process_config
        .inner
        .set_current_working_directory(cwd)
        .map(|_| ());
    Box::leak(process_config);
    match res {
        Ok(_) => IrisStatus::Success,
        Err(e) => IrisStatus::from(e),
    }
}

/// Sets an environment variable of processes created with this configuration. The variable should
/// be in KEY=VALUE format.
/// # Safety
/// This is safe as long as a valid handle and a valid NULL-terminated string are passed.
#[no_mangle]
pub unsafe extern "C" fn iris_process_config_environment_variable(
    process_config: IrisProcessConfigHandle,
    env_var: *const c_char,
) -> IrisStatus {
    if process_config.is_null() || env_var.is_null() {
        return IrisStatus::InvalidArguments;
    }
    let env_var = CStr::from_ptr(env_var).to_owned();
    let mut process_config = Box::from_raw(process_config as *mut SelfContainedProcessConfig);
    let res = process_config
        .inner
        .set_environment_variable(env_var)
        .map(|_| ());
    Box::leak(process_config);
    match res {
        Ok(_) => IrisStatus::Success,
        Err(e) => IrisStatus::from(e),
    }
}

/// Sets the standard input handle or file descriptor of processes created with this configuration.
/// # Safety
/// This is safe as long as a valid process configuration handle and a valid file descriptor or handle is passed.
#[no_mangle]
pub unsafe extern "C" fn iris_process_config_redirect_stdin(
    process_config: IrisProcessConfigHandle,
    new_stdin: u64,
) -> IrisStatus {
    if process_config.is_null() {
        return IrisStatus::InvalidArguments;
    }
    let new_stdin = if new_stdin == u64::MAX {
        None
    } else {
        match Handle::from_raw(new_stdin) {
            Ok(h) => Some(h),
            Err(e) => return IrisStatus::from(e),
        }
    };
    let mut process_config = Box::from_raw(process_config as *mut SelfContainedProcessConfig);
    process_config.stdin_handle = new_stdin;
    // Make the reference 'static. This is unsafe, but right now there is no simple
    // way to show the borrow checker that the handle will remain valid for at least
    // as long as the Policy
    let handle_ref = process_config
        .stdin_handle
        .as_ref()
        .map(|r| &*(r as *const Handle));
    let res = process_config.inner.redirect_stdin(handle_ref).map(|_| ());
    Box::leak(process_config);
    match res {
        Ok(_) => IrisStatus::Success,
        Err(e) => IrisStatus::from(e),
    }
}

/// Sets the standard output handle or file descriptor of processes created with this configuration.
/// # Safety
/// This is safe as long as a valid process configuration handle and a valid file descriptor or handle is passed.
#[no_mangle]
pub unsafe extern "C" fn iris_process_config_redirect_stdout(
    process_config: IrisProcessConfigHandle,
    new_stdout: u64,
) -> IrisStatus {
    if process_config.is_null() {
        return IrisStatus::InvalidArguments;
    }
    let new_stdout = if new_stdout == u64::MAX {
        None
    } else {
        match Handle::from_raw(new_stdout) {
            Ok(h) => Some(h),
            Err(e) => return IrisStatus::from(e),
        }
    };
    let mut process_config = Box::from_raw(process_config as *mut SelfContainedProcessConfig);
    process_config.stdout_handle = new_stdout;
    // Make the reference 'static. This is unsafe, but right now there is no simple
    // way to show the borrow checker that the handle will remain valid for at least
    // as long as the Policy
    let handle_ref = process_config
        .stdout_handle
        .as_ref()
        .map(|r| &*(r as *const Handle));
    let res = process_config.inner.redirect_stdout(handle_ref).map(|_| ());
    Box::leak(process_config);
    match res {
        Ok(_) => IrisStatus::Success,
        Err(e) => IrisStatus::from(e),
    }
}

/// Sets the standard error handle or file descriptor of processes created with this configuration.
/// # Safety
/// This is safe as long as a valid process configuration handle and a valid file descriptor or handle is passed.
#[no_mangle]
pub unsafe extern "C" fn iris_process_config_redirect_stderr(
    process_config: IrisProcessConfigHandle,
    new_stderr: u64,
) -> IrisStatus {
    if process_config.is_null() {
        return IrisStatus::InvalidArguments;
    }
    let new_stderr = if new_stderr == u64::MAX {
        None
    } else {
        match Handle::from_raw(new_stderr) {
            Ok(h) => Some(h),
            Err(e) => return IrisStatus::from(e),
        }
    };
    let mut process_config = Box::from_raw(process_config as *mut SelfContainedProcessConfig);
    process_config.stderr_handle = new_stderr;
    // Make the reference 'static. This is unsafe, but right now there is no simple
    // way to show the borrow checker that the handle will remain valid for at least
    // as long as the Policy
    let handle_ref = process_config
        .stderr_handle
        .as_ref()
        .map(|r| &*(r as *const Handle));
    let res = process_config.inner.redirect_stderr(handle_ref).map(|_| ());
    Box::leak(process_config);
    match res {
        Ok(_) => IrisStatus::Success,
        Err(e) => IrisStatus::from(e),
    }
}
