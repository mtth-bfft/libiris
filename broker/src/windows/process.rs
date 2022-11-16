use crate::os::proc_thread_attribute_list::ProcThreadAttributeList;
use crate::process::CrossPlatformSandboxedProcess;
use core::ptr::null_mut;
use iris_policy::{CrossPlatformHandle, Handle, Policy};
use log::{info, warn};
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use winapi::ctypes::c_void;
use winapi::shared::basetsd::DWORD_PTR;
use winapi::shared::minwindef::{DWORD, MAX_PATH};
use winapi::shared::winerror::ERROR_ALREADY_EXISTS;
use winapi::shared::winerror::HRESULT_FROM_WIN32;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::minwinbase::STILL_ACTIVE;
use winapi::um::processthreadsapi::{
    CreateProcessA, GetExitCodeProcess, GetProcessId, PROCESS_INFORMATION,
};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::sysinfoapi::GetSystemWindowsDirectoryA;
use winapi::um::winbase::{
    DETACHED_PROCESS, EXTENDED_STARTUPINFO_PRESENT, INFINITE, STARTF_FORCEOFFFEEDBACK,
    STARTF_USESTDHANDLES, STARTUPINFOEXA, WAIT_OBJECT_0,
};
use winapi::um::winnt::{HANDLE, SECURITY_CAPABILITIES, HRESULT, PCWSTR, PSID, PSID_AND_ATTRIBUTES};

// Waiting for these constants from WinSDK to be included in winapi
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: DWORD_PTR = 0x20002;
const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: DWORD_PTR = 0x20007;
const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: DWORD_PTR = 0x20009;
const PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY: DWORD_PTR = 0x2000f;
const PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY: DWORD_PTR = 0x2000e;
const PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT: DWORD = 1;
const PROCESS_CREATION_CHILD_PROCESS_RESTRICTED: DWORD = 1;
const PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE: DWORD = 1;
const PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE: DWORD = 4;
const PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON: DWORD = 0x100;
const PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON_REQ_RELOCS: DWORD = 0x300;
const PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON: DWORD = 0x1000;
const PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON: DWORD = 0x10000;
const PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON: DWORD = 0x100000;
const PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON: DWORD = 0x10000000;

const PROCESS_SANITIZED_ENVIRONMENT: &[(&str, Option<&str>)] = &[
    // Avoid leaking the username/hostname whenever possible
    ("COMPUTERNAME", Some("PC")),
    ("LOGONSERVER", Some("\\\\PC")),
    ("USERDOMAIN", Some("PC")),
    ("USERDOMAIN_ROAMINGPROFILE", Some("PC")),
    ("USERNAME", Some("User")),
    // Generic paths/system information are often required and don't leak user data
    ("COMMONPROGRAMFILES", None),
    ("COMMONPROGRAMFILES(X86)", None),
    ("COMMONPROGRAMW6432", None),
    ("COMSPEC", None),
    ("DRIVERDATA", None),
    ("HOMEDRIVE", None),
    ("OS", None),
    ("PATHEXT", None),
    ("PROGRAMDATA", None),
    ("PROGRAMFILES", None),
    ("PROGRAMFILES(X86)", None),
    ("PROGRAMW6432", None),
    ("PUBLIC", None),
    ("SESSIONNAME", None),
    ("SYSTEMDRIVE", None),
    ("SYSTEMROOT", None),
    ("WINDIR", None),
    ("NUMBER_OF_PROCESSORS", None),
    ("PROCESSOR_ARCHITECTURE", None),
    ("PROCESSOR_IDENTIFIER", None),
    ("PROCESSOR_LEVEL", None),
    ("PROCESSOR_REVISION", None),
    ("LOCALAPPDATA", None), // TODO: required for AppContainer start. Find out if we can do better (leaks username).
];

static mut PER_PROCESS_APPCONTAINER_ID: std::sync::atomic::AtomicUsize = AtomicUsize::new(0);

pub(crate) struct OSSandboxedProcess {
    pid: u64,
    h_process: HANDLE,
    appcontainer_name: Option<String>,
}

type CreateAppContainerProfileFn = unsafe extern "C" fn(
    appcontainer_name: PCWSTR,
    display_name: PCWSTR,
    description: PCWSTR,
    capabilities: PSID_AND_ATTRIBUTES,
    capability_count: DWORD,
    appcontainer_sid: *mut PSID,
) -> HRESULT;
type DeleteAppContainerProfileFn = unsafe extern "C" fn(PCWSTR) -> HRESULT;

struct AppContainerProfileFunctions {
    create: CreateAppContainerProfileFn,
    delete: DeleteAppContainerProfileFn,
}

lazy_static! {
    static ref APPCONTAINER_PROFILE_FN: Option<AppContainerProfileFunctions> = {
        let dllname = CString::new("userenv.dll").unwrap();
        let h_dll = unsafe { LoadLibraryA(dllname.as_ptr()) };
        if h_dll.is_null() {
            None
        } else {
            let procname = CString::new("CreateAppContainerProfile").unwrap();
            let create = unsafe { GetProcAddress(h_dll, procname.as_ptr()) };
            let procname = CString::new("DeleteAppContainerProfile").unwrap();
            let delete = unsafe { GetProcAddress(h_dll, procname.as_ptr()) };
            if create.is_null() || delete.is_null() {
                None
            } else {
                let create = unsafe { std::mem::transmute::<_, CreateAppContainerProfileFn>(create) };
                let delete = unsafe { std::mem::transmute::<_, DeleteAppContainerProfileFn>(delete) };
                Some(AppContainerProfileFunctions { create, delete })
            }
        }
    };
}

impl Drop for OSSandboxedProcess {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.h_process);
        }
        if let Some(appcontainer_profile_fn) = APPCONTAINER_PROFILE_FN.as_ref() {
            if let Some(appcontainer_name) = &self.appcontainer_name {
                let name_buf: Vec<u16> = appcontainer_name
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
                unsafe { (appcontainer_profile_fn.delete)(name_buf.as_ptr() as *const _) };
            }
        }
    }
}

impl CrossPlatformSandboxedProcess for OSSandboxedProcess {
    fn new(
        policy: &Policy,
        exe: &CStr,
        argv: &[&CStr],
        envp: &[&CStr],
        stdin: Option<&Handle>,
        stdout: Option<&Handle>,
        stderr: Option<&Handle>,
    ) -> Result<Self, String> {
        if argv.len() < 1 {
            return Err("Invalid argument: empty argv".to_owned());
        }
        for handle in vec![stdin, stdout, stderr] {
            if let Some(handle) = handle {
                if !handle.is_inheritable()? {
                    return Err("Stdin, stdout, and stderr handles must be set as inheritable for them to be usable by a worker".to_owned());
                }
            }
        }

        // Build the full commandline with quotes to protect prevent C:\Program Files\a.exe from launching C:\Program.exe
        let mut cmdline = vec![b'"'];
        cmdline.extend_from_slice(exe.to_bytes());
        cmdline.push(b'"');
        for arg in &argv[1..] {
            let arg = arg.to_bytes();
            cmdline.push(b' ');
            if arg.contains(&b' ') {
                cmdline.push(b'"');
            }
            cmdline.extend_from_slice(arg);
            if arg.contains(&b' ') {
                cmdline.push(b'"');
            }
        }
        let cmdline = CString::new(cmdline).unwrap();

        // Build the concatenated environment block (NULL-terminated strings, the last one with a double-NULL terminator)
        // Merge the caller-provided values with sanitized system environment variables
        let mut merged_envp: Vec<CString> = envp
            .iter()
            .map(|s| CString::new(s.to_bytes()).unwrap())
            .collect();
        for (var_name, forced_val) in PROCESS_SANITIZED_ENVIRONMENT {
            let var_name_c = CString::new(*var_name).unwrap().into_bytes();
            let mut explicitly_set = false;
            for entry in &merged_envp {
                let entry = entry.to_bytes();
                if entry.get(..var_name_c.len()) == Some(&var_name_c[..])
                    && entry.get(var_name_c.len()) == Some(&b'=')
                {
                    explicitly_set = true;
                    break;
                }
            }
            if !explicitly_set {
                if let Some(forced_val) = forced_val {
                    merged_envp.push(CString::new(format!("{}={}", var_name, forced_val)).unwrap());
                } else if let Ok(system_val) = std::env::var(var_name) {
                    merged_envp.push(CString::new(format!("{}={}", var_name, system_val)).unwrap());
                }
            }
        }
        let envblock: Vec<u8> = merged_envp
            .iter()
            .flat_map(|s| s.to_bytes_with_nul())
            .chain(std::iter::once(&0))
            .cloned()
            .collect();

        // Build the starting directory as C:\Windows so that it doesn't keep a handle on any other directory
        let mut cwd = vec![0u8; MAX_PATH + 1];
        let res = unsafe {
            GetSystemWindowsDirectoryA(cwd.as_mut_ptr() as *mut _, cwd.len().try_into().unwrap())
        };
        if res == 0 || res > cwd.len().try_into().unwrap() {
            return Err(format!(
                "GetSystemDirectory() failed with error {}",
                unsafe { GetLastError() }
            ));
        }
        cwd.truncate(res.try_into().unwrap());
        let cwd = CString::new(cwd).unwrap();

        // Prepare a process creation attribute list. It must be pre-allocated, and any unused slot
        // would make CreateProcess() fails with ERROR_INVALID_PARAMETER, so we need to predict
        // how many settings we will use, and we don't know in advance which policies are usable
        // (some may not be supported on the Windows kernel version currently running), so we try
        // in a loop.
        let mut in_appcontainer = true;
        let mut in_less_privileged_appcontainer = in_appcontainer;
        let mut filter_inherited_handles = true;
        let mut block_child_process_by_token_policy = true;
        let mut with_mitigation_policies = true;

        loop {
            if !in_appcontainer {
                in_less_privileged_appcontainer = false; // meaningless without an AppContainer
            }
            let num_attributes = [in_appcontainer, in_less_privileged_appcontainer, filter_inherited_handles, block_child_process_by_token_policy, with_mitigation_policies].iter().filter(|v| **v).count() as DWORD;
            let mut ptal = ProcThreadAttributeList::new(num_attributes)?;

            // Start as an AppContainer whenever possible
            let mut security_capabilities: SECURITY_CAPABILITIES = unsafe { std::mem::zeroed() };
            let lpac_policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
            let appcontainer_name = if in_appcontainer {
                let appcontainer_name = if let Some(appcontainer_profile_fn) = APPCONTAINER_PROFILE_FN.as_ref() {
                    let appcontainer_id =
                        unsafe { PER_PROCESS_APPCONTAINER_ID.fetch_add(1, Ordering::Relaxed) };
                    let appcontainer_name = format!(
                        "IrisAppContainer_{}_{}",
                        std::process::id(),
                        appcontainer_id
                    );
                    let name_buf: Vec<u16> = appcontainer_name
                        .encode_utf16()
                        .chain(std::iter::once(0))
                        .collect();
                    let mut res = unsafe {
                        (appcontainer_profile_fn.create)(
                            name_buf.as_ptr() as *const _,
                            name_buf.as_ptr() as *const _,
                            name_buf.as_ptr() as *const _,
                            null_mut(),
                            0,
                            &mut security_capabilities.AppContainerSid as *mut PSID,
                        )
                    };
                    if res == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) {
                        // There is a leftover appcontainer profile from a previous process with our PID which did not clean up on exit. Retry
                        unsafe { (appcontainer_profile_fn.delete)(name_buf.as_ptr() as *const _) };
                        res = unsafe {
                            (appcontainer_profile_fn.create)(
                                name_buf.as_ptr() as *const _,
                                name_buf.as_ptr() as *const _,
                                name_buf.as_ptr() as *const _,
                                null_mut(),
                                0,
                                &mut security_capabilities.AppContainerSid as *mut PSID,
                            )
                        };
                    }
                    if res != 0 {
                        in_appcontainer = false;
                        warn!(
                            "CreateAppContainerProfile({}) failed with error {}, cannot use AppContainers",
                            appcontainer_name, res
                        );
                        continue;
                    }
                    if let Err(e) = ptal.set(
                        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                        &security_capabilities as *const _ as *const _,
                        std::mem::size_of_val(&security_capabilities),
                    ) {
                        in_appcontainer = false;
                        warn!("Using an AppContainer failed ({}), only using legacy restricted token", e);
                        continue;
                    }
                    Some(appcontainer_name)
                }
                else {
                    in_appcontainer = false;
                    warn!("AppContainers not supported on this system, using legacy restricted token");
                    continue;
                };

                // Start as a Less Privileged AppContainer whenever possible
                if let Err(e) = ptal.set(
                    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                    &lpac_policy as *const _ as *const _,
                    std::mem::size_of_val(&lpac_policy),
                ) {
                    in_less_privileged_appcontainer = false;
                    warn!("Less privileged AppContainers not supported on this system ({}), using AppContainers with ALL_APPLICATION_PACKAGES SID", e);
                    continue;
                }

                appcontainer_name
            } else {
                None
            };

            // Restrict inherited handles to only those explicitly allowed.
            // List is computed outside the if() check so that it lives as long
            // as the ProcThreadAttributeList.
            let mut handles_to_inherit = policy
                .get_inherited_handles()
                .into_iter()
                .map(|n| n.as_raw() as *mut c_void)
                .collect::<Vec<HANDLE>>();
            handles_to_inherit.sort();
            handles_to_inherit.dedup(); // CreateProcess fails with ERROR_INVALID_PARAMETER if a handle is set to be inherited twice
            if filter_inherited_handles {
                if let Err(e) = ptal.set(
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    handles_to_inherit.as_ptr() as *const _,
                    handles_to_inherit.len() * std::mem::size_of::<HANDLE>(),
                ) {
                    warn!("Handle inheritance filtering is not supported on this system ({}), only relying on worker process cleanup at startup", e);
                    filter_inherited_handles = false;
                    continue;
                }
            }

            // Always prevent child process creation, as it would break many security features we implement here
            // Store value outside of the if() check so that it lives as long as the ProcThreadAttributeList
            let child_proc_policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
            if block_child_process_by_token_policy {
                if let Err(e) = ptal.set(
                    PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                    &child_proc_policy as *const _ as *const _,
                    std::mem::size_of_val(&child_proc_policy),
                ) {
                    warn!("Child process creation policy not supported on this system ({}), only using legacy job restriction", e);
                    block_child_process_by_token_policy = false;
                    continue;
                }
            }

            // Always apply sane defaults for process mitigation policies
            // Store value outside of the if() check so that it lives as long as the ProcThreadAttributeList
            let mut mitigation_policy: DWORD = 0;
            if with_mitigation_policies {
                mitigation_policy |= PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE;
                mitigation_policy |= PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE;
                mitigation_policy |= PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON;
                mitigation_policy |=
                    PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON_REQ_RELOCS;
                mitigation_policy |= PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON;
                mitigation_policy |= PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON;
                mitigation_policy |= PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON;
                mitigation_policy |=
                    PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON;
                //mitigation_policy |= PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON;
                //mitigation_policy |= PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON; // loading extension DLLs will crash us if they are not win32k-filtering-aware or make syscalls with bad handles
                //mitigation_policy |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON;
                //mitigation_policy |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON;
                //mitigation_policy |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON;
                //mitigation_policy |= PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON;
                //mitigation_policy |= PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
                if let Err(e) = ptal.set(
                    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                    &mitigation_policy as *const _ as *const _,
                    std::mem::size_of_val(&mitigation_policy),
                ) {
                    with_mitigation_policies = false;
                    warn!("Process mitigation policies not supported on this system ({}), only using legacy job restriction", e);
                    continue;
                }
            }

            // Start the actual child process
            let mut proc_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
            let mut start_info: STARTUPINFOEXA = unsafe { std::mem::zeroed() };
            start_info.StartupInfo.cb = std::mem::size_of_val(&start_info).try_into().unwrap();
            start_info.StartupInfo.dwFlags = STARTF_FORCEOFFFEEDBACK | STARTF_USESTDHANDLES;
            start_info.StartupInfo.hStdInput = stdin
                .and_then(|x| Some(x.as_raw() as HANDLE))
                .unwrap_or(INVALID_HANDLE_VALUE);
            start_info.StartupInfo.hStdOutput = stdout
                .and_then(|x| Some(x.as_raw() as HANDLE))
                .unwrap_or(INVALID_HANDLE_VALUE);
            start_info.StartupInfo.hStdError = stderr
                .and_then(|x| Some(x.as_raw() as HANDLE))
                .unwrap_or(INVALID_HANDLE_VALUE);
            start_info.lpAttributeList = ptal.as_ptr() as *const _ as *mut _;
            // TODO: use CREATE_BREAKAWAY_FROM_JOB if necessary on older OSes where nesting isn't supported
            let res = unsafe {
                CreateProcessA(
                    null_mut(),
                    cmdline.as_ptr() as *mut _,
                    null_mut(),
                    null_mut(),
                    1, // handle inheritance is filtered by PROC_THREAD_ATTRIBUTE_HANDLE_LIST instead
                    EXTENDED_STARTUPINFO_PRESENT | DETACHED_PROCESS,
                    envblock.as_ptr() as *mut _,
                    cwd.as_ptr() as *mut _,
                    &mut start_info as *mut _ as *mut _,
                    &mut proc_info as *mut _,
                )
            };
            if res == 0 {
                let err = unsafe { GetLastError() };
                if with_mitigation_policies {
                    with_mitigation_policies = false;
                    warn!("Process mitigation policies might not be supported on this system (process creation failed with code {})", err);
                    continue;
                }
                return Err(format!(
                    "CreateProcess({}) failed with error {}",
                    cmdline.to_string_lossy(),
                    err
                ));
            }
            unsafe {
                CloseHandle(proc_info.hThread);
            }
            let pid = unsafe { GetProcessId(proc_info.hProcess) };
            if pid == 0 {
                return Err(format!("GetProcessId() failed with error {}", unsafe {
                    GetLastError()
                }));
            }
            // Debrief about the settings that worked
            if filter_inherited_handles {
                info!("Filtering inherited handles to only: {:?}", &handles_to_inherit);
            }
            if with_mitigation_policies {
                info!("Process mitigation policies set to 0x{:X}", &mitigation_policy);
            }
            if let Some(appcontainer_name) = appcontainer_name.as_ref() {
                info!("Using AppContainer {}", appcontainer_name);
            }
            info!("Worker created (PID {})", pid);
            return Ok(Self {
                pid: pid.into(),
                h_process: proc_info.hProcess,
                appcontainer_name,
            })
        }
    }

    fn get_pid(&self) -> u64 {
        self.pid
    }

    fn wait_for_exit(&mut self) -> Result<u64, String> {
        let mut exit_code: DWORD = STILL_ACTIVE;
        loop {
            let res = unsafe { GetExitCodeProcess(self.h_process, &mut exit_code as *mut _) };
            if res == 0 {
                return Err(format!(
                    "GetExitCodeProcess() failed with error {}",
                    unsafe { GetLastError() }
                ));
            }
            if exit_code != STILL_ACTIVE {
                return Ok(exit_code.into());
            }
            let res = unsafe { WaitForSingleObject(self.h_process, INFINITE) };
            if res != WAIT_OBJECT_0 {
                return Err(format!(
                    "WaitForSingleObject() failed with error {}",
                    unsafe { GetLastError() }
                ));
            }
        }
    }
}
