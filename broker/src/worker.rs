use crate::os::brokered_syscalls::handle_os_specific_request;
use crate::os::process::OSSandboxedProcess;
use crate::process::CrossPlatformSandboxedProcess;
use iris_ipc::{
    CrossPlatformMessagePipe, IPCMessagePipe, IPCRequestV1, IPCResponseV1, IPCVersion, MessagePipe,
    IPC_HANDLE_ENV_NAME,
};
use iris_policy::{CrossPlatformHandle, Handle, Policy};
use std::ffi::{CStr, CString};

pub struct Worker {
    process: OSSandboxedProcess,
}

impl Worker {
    pub fn new<'a>(
        policy: &'a Policy,
        exe: &'a CStr,
        argv: &[&'a CStr],
        envp: &[&'a CStr],
        stdin: Option<&'a Handle>,
        stdout: Option<&'a Handle>,
        stderr: Option<&'a Handle>,
    ) -> Result<Self, String> {
        let mut policy = policy.clone();
        let (mut broker_pipe, worker_pipe) = MessagePipe::new()?;
        let mut worker_pipe_handle = worker_pipe.into_handle();
        worker_pipe_handle.set_inheritable(true)?;
        policy.allow_inherit_handle(&worker_pipe_handle)?;
        for handle in vec![stdin, stdout, stderr] {
            if let Some(handle) = handle {
                policy.allow_inherit_handle(handle)?;
            }
        }
        for handle in policy.get_inherited_handles() {
            // On Linux, exec() will close all CLOEXEC handles.
            // On Windows, CreateProcess() with bInheritHandles = TRUE doesn't automatically set the given
            // handles as inheritable, and instead returns a ERROR_INVALID_PARAMETER if one of them is not.
            // We cannot just set the handles as inheritable behind the caller's back, since they might
            // reset it or depend on it in another thread. They have to get this right by themselves.
            if !handle.is_inheritable()? {
                return Err(format!(
                    "Cannot make worker inherit handle {:?} which is not set as inheritable",
                    handle
                ));
            }
        }
        for env_var in envp {
            if env_var.to_string_lossy().starts_with(IPC_HANDLE_ENV_NAME) {
                return Err(format!(
                    "Workers cannot use the reserved {} environment variable",
                    IPC_HANDLE_ENV_NAME
                ));
            }
        }
        let mut envp = Vec::from(envp);
        let ipc_handle_var = CString::new(format!(
            "{}={}",
            IPC_HANDLE_ENV_NAME,
            worker_pipe_handle.as_raw().to_string()
        ))
        .unwrap();
        envp.push(&ipc_handle_var);
        let process = OSSandboxedProcess::new(&policy, exe, argv, &envp, stdin, stdout, stderr)?;
        broker_pipe.set_remote_process(process.get_pid())?;
        let mut broker_pipe = IPCMessagePipe::new_server(broker_pipe, IPCVersion::V1)?;
        let policy = policy.get_runtime_policy(); // free resources kept open before passing it to the 'static manager thread
        std::thread::spawn(move || {
            // TODO: wait for the initial child message before returning
            // TODO: bind manager thread lifetime to the worker lifetime (cleanup in drop?)
            let mut has_lowered_privileges = false;
            loop {
                let request = match broker_pipe.recv() {
                    Ok(Some(m)) => m,
                    Ok(None) => {
                        if !has_lowered_privileges {
                            println!(" [!] Manager thread exiting, child closed its IPC socket before lowering privileges");
                            break;
                        }
                        println!(
                            " [.] Manager thread exiting cleanly, worker closed its IPC socket"
                        );
                        break;
                    }
                    Err(e) => {
                        println!(
                            " [!] Manager thread exiting: error when receiving IPC: {}",
                            e
                        );
                        break;
                    }
                };
                println!(" [.] Received request: {:?}", &request);
                let (resp, handle) = match request {
                    // Handle OS-agnostic requests
                    IPCRequestV1::LowerFinalSandboxPrivilegesAsap if !has_lowered_privileges => {
                        has_lowered_privileges = true;
                        (IPCResponseV1::PolicyApplied(policy.clone()), None)
                    }
                    other => handle_os_specific_request(other, &policy),
                };
                println!(" [.] Sending response: {:?}", &resp);
                if let Err(e) = broker_pipe.send(&resp, handle.as_ref()) {
                    println!(" [!] Manager thread exiting: error when sending IPC: {}", e);
                    break;
                }
            }
        });
        Ok(Self { process: process })
    }

    pub fn get_pid(&self) -> u64 {
        self.process.get_pid()
    }

    pub fn wait_for_exit(&mut self) -> Result<u64, String> {
        self.process.wait_for_exit()
    }
}
