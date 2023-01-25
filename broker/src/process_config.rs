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

    pub fn set_current_working_directory(
        &mut self,
        cwd: Option<CString>,
    ) -> Result<&mut Self, BrokerError> {
        self.cwd = cwd;
        Ok(self)
    }

    pub fn set_environment_variable(&mut self, env_var: CString) -> Result<&mut Self, BrokerError> {
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

    pub fn redirect_stdin(
        &mut self,
        new_stdin: Option<&'a Handle>,
    ) -> Result<&mut Self, BrokerError> {
        self.stdin = new_stdin;
        Ok(self)
    }

    pub fn redirect_stdout(
        &mut self,
        new_stdout: Option<&'a Handle>,
    ) -> Result<&mut Self, BrokerError> {
        self.stdout = new_stdout;
        Ok(self)
    }

    pub fn redirect_stderr(
        &mut self,
        new_stderr: Option<&'a Handle>,
    ) -> Result<&mut Self, BrokerError> {
        self.stderr = new_stderr;
        Ok(self)
    }
}
