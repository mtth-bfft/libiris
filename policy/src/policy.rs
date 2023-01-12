use crate::error::PolicyError;
use crate::handle::CrossPlatformHandle;
use crate::os::path::{OS_PATH_SEPARATOR, derive_all_file_paths_from_path};
use crate::{PolicyRequest, Handle, strip_one_component};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Policy<'a> {
    #[serde(skip)]
    pub(crate) inherit_handles: HashSet<&'a Handle>,
    pub(crate) file_access: HashMap<String, (bool, bool, bool, bool, bool)>,
    pub(crate) dir_access: HashMap<String, (bool, bool, bool, bool, bool)>,
    pub(crate) regkey_access: HashMap<String, (bool, bool)>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyVerdict {
    Granted,
    DeniedByPolicy {
        why: String,
    },
    DelegationToSandboxNotSupported {
        why: String,
    },
    InvalidRequestParameters {
        argument_name: String,
        reason: String,
    },
}

impl<'a> Policy<'a> {
    pub fn nothing_allowed() -> Self {
        Self {
            inherit_handles: HashSet::new(),
            file_access: HashMap::new(),
            dir_access: HashMap::new(),
            regkey_access: HashMap::new(),
        }
    }

    pub fn get_runtime_policy(&self) -> Policy<'static> {
        Policy {
            inherit_handles: HashSet::new(),
            file_access: self.file_access.clone(),
            dir_access: self.dir_access.clone(),
            regkey_access: self.regkey_access.clone(),
        }
    }

    pub fn allow_inherit_handle(&mut self, handle: &'a Handle) -> Result<(), PolicyError> {
        // On Linux, exec() will close all CLOEXEC handles.
        // On Windows, CreateProcess() with bInheritHandles = TRUE doesn't automatically set the given
        // handles as inheritable, and instead returns a ERROR_INVALID_PARAMETER if one of them is not.
        // We cannot just set the handles as inheritable behind the caller's back, since they might
        // reset it or depend on it in another thread. They have to get this right by themselves.
        if !handle.is_inheritable()? {
            return Err(PolicyError::HandleNotInheritable {
                handle_raw_value: handle.as_raw(),
            });
        }
        self.inherit_handles.insert(handle);
        Ok(())
    }

    pub fn get_inherited_handles(&self) -> HashSet<&Handle> {
        self.inherit_handles.clone()
    }

    fn allow_file_access(&mut self, path: &str, dir: bool, access: (bool, bool, bool, bool, bool)) -> Result<(), PolicyError> {
        let (new_read, new_write, new_block_readers, new_block_writers, new_block_deleters) = access;
        for path in derive_all_file_paths_from_path(path)? {
            let path = match path.strip_suffix(OS_PATH_SEPARATOR) {
                Some(rest) => rest,
                None => &path,
            };
            let map = if dir { &mut self.dir_access } else { &mut self.file_access };
            let (prev_read, prev_write, prev_block_readers, prev_block_writers, prev_block_deleters) = map
                .get(path)
                .copied()
                .unwrap_or((false, false, false, false, false));
            map.insert(
                path.to_owned(),
                (
                    prev_read | new_read,
                    prev_write | new_write,
                    prev_block_readers | new_block_readers,
                    prev_block_writers | new_block_writers,
                    prev_block_deleters | new_block_deleters,
                )
            );
        }
        Ok(())
    }

    pub fn allow_file_read(&mut self, path: &str) -> Result<(), PolicyError> {
        self.allow_file_access(path, false, (true, false, false, false, false))
    }

    pub fn allow_file_write(&mut self, path: &str) -> Result<(), PolicyError> {
        self.allow_file_access(path, false, (false, true, false, false, false))
    }

    pub fn allow_file_lock(
        &mut self,
        path: &str,
        block_other_readers: bool,
        block_other_writers: bool,
        block_other_deleters: bool,
    ) -> Result<(), PolicyError> {
        self.allow_file_access(path, false, (false, false, block_other_readers, block_other_writers, block_other_deleters))
    }

    pub fn allow_dir_read(&mut self, path: &str) -> Result<(), PolicyError> {
        self.allow_file_access(path, true, (true, false, false, false, false))
    }

    pub fn allow_dir_write(&mut self, path: &str) -> Result<(), PolicyError> {
        self.allow_file_access(path, true, (false, true, false, false, false))
    }

    pub fn allow_dir_lock(
        &mut self,
        path: &str,
        block_other_readers: bool,
        block_other_writers: bool,
        block_other_deleters: bool,
    ) -> Result<(), PolicyError> {
        self.allow_file_access(path, true, (false, false, block_other_readers, block_other_writers, block_other_deleters))
    }

    pub(crate) fn get_filepath_allowed_access(&self, path: &str) -> (bool, bool, bool, bool, bool) {
        let path = path.strip_suffix(OS_PATH_SEPARATOR).unwrap_or(path);
        let mut verdict_read = false;
        let mut verdict_write = false;
        let mut verdict_block_readers = false;
        let mut verdict_block_writers = false;
        let mut verdict_block_deleters = false;
        if let Some((read, write, block_readers, block_writers, block_deleters)) = self.file_access.get(path) {
            verdict_read |= read;
            verdict_write |= write;
            verdict_block_readers |= block_readers;
            verdict_block_writers |= block_writers;
            verdict_block_deleters |= block_deleters;
        }
        let mut current_path = path;
        while !verdict_read || !verdict_write || !verdict_block_readers || !verdict_block_writers || !verdict_block_deleters {
            if let Some((read, write, block_readers, block_writers, block_deleters)) = self.dir_access.get(current_path) {
                verdict_read |= read;
                verdict_write |= write;
                verdict_block_readers |= block_readers;
                verdict_block_writers |= block_writers;
                verdict_block_deleters |= block_deleters;
            }
            match strip_one_component(current_path, OS_PATH_SEPARATOR) {
                Some(parent_path) => current_path = parent_path,
                None => break,
            }
        }
        (
            verdict_read,
            verdict_write,
            verdict_block_readers,
            verdict_block_writers,
            verdict_block_deleters,
        )
    }

    pub(crate) fn log_verdict(&self, request: &PolicyRequest, verdict: &PolicyVerdict) {
        match &verdict {
            PolicyVerdict::Granted => {
                info!("Worker granted access to {}", request);
            },
            PolicyVerdict::DelegationToSandboxNotSupported { why } => {
                warn!("Worker tried to access {} but delegation is not supported: {}", request, why);
            },
            PolicyVerdict::DeniedByPolicy { why } => {
                warn!("Worker tried to access {} but it is not allowed by its policy: {}", request, why);
            },
            PolicyVerdict::InvalidRequestParameters { argument_name, reason } => {
                warn!("Worker tried to access {} but \"{}\" was unexpected: {}", request, argument_name, reason);
            },
        }
    }
}
