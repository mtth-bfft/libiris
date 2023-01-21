use crate::BrokerError;
use iris_policy::Handle;
use std::ffi::{CStr, CString};

#[derive(Debug, Clone)]
pub struct ProcessConfig<'a> {
    pub(crate) executable_path: CString,
    pub(crate) argv: Vec<CString>,
    pub(crate) envp: Vec<CString>,
    pub(crate) cwd: Option<CString>,
    pub(crate) stdin: Option<&'a Handle>,
    pub(crate) stdout: Option<&'a Handle>,
    pub(crate) stderr: Option<&'a Handle>,
}

fn name_from_env(env: &CStr) -> &[u8] {
    let bytes = env.to_bytes();
    if let Some(pos) = bytes.iter().position(|b| *b == b'=') {
        &bytes[..pos]
    } else {
        bytes
    }
}

impl<'a> ProcessConfig<'a> {
    pub fn new(executable_path: CString, argv: &[CString]) -> Self {
        Self {
            executable_path,
            argv: argv.to_owned(),
            envp: vec![],
            cwd: None,
            stdin: None,
            stdout: None,
            stderr: None,
        }
    }

    pub fn with_current_working_directory(mut self, cwd: CString) -> Result<Self, BrokerError> {
        self.cwd = Some(cwd);
        Ok(self)
    }

    pub fn with_environment_variable(mut self, env_var: CString) -> Result<Self, BrokerError> {
        let name = name_from_env(&env_var);
        for prev in &self.envp {
            if name_from_env(prev) == name {
                let env_var = env_var.to_string_lossy();
                let (name, _) = env_var.split_once('=').unwrap_or((&env_var, ""));
                return Err(BrokerError::ConflictingEnvironmentVariable {
                    name: name.to_owned(),
                });
            }
        }
        self.envp.push(env_var);
        Ok(self)
    }

    pub fn with_stdin_redirected(mut self, new_stdin: &'a Handle) -> Result<Self, BrokerError> {
        self.stdin = Some(new_stdin);
        Ok(self)
    }

    pub fn with_stdout_redirected(mut self, new_stdout: &'a Handle) -> Result<Self, BrokerError> {
        self.stdout = Some(new_stdout);
        Ok(self)
    }

    pub fn with_stderr_redirected(mut self, new_stderr: &'a Handle) -> Result<Self, BrokerError> {
        self.stderr = Some(new_stderr);
        Ok(self)
    }
}
