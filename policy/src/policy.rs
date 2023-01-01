use crate::error::PolicyError;
use crate::handle::CrossPlatformHandle;
use crate::os::path::derive_all_file_paths_from_path;
#[cfg(windows)]
use crate::os::path::derive_all_reg_key_paths_from_path;
use crate::Handle;
use glob::Pattern;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// TODO: Eq required for serializability here. Replace Vec<> with unordered sets
// to avoid making the semantics of == and != non-intuitive.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Policy<'a> {
    #[serde(skip)]
    inherit_handles: Vec<&'a Handle>,
    file_access: HashMap<String, (bool, bool, bool)>,
    file_lock: HashMap<String, (bool, bool, bool)>,
    regkey_access: HashMap<String, (bool, bool)>,
}

impl<'a> Policy<'a> {
    #[deprecated(note = "Use nothing_allowed() instead to explicitly create an empty policy")]
    pub fn new() -> Self {
        Self::nothing_allowed()
    }

    pub fn nothing_allowed() -> Self {
        Self {
            inherit_handles: Vec::new(),
            file_access: HashMap::new(),
            file_lock: HashMap::new(),
            regkey_access: HashMap::new(),
        }
    }

    pub fn get_runtime_policy(&self) -> Policy<'static> {
        Policy {
            inherit_handles: Vec::new(),
            file_access: self.file_access.clone(),
            file_lock: self.file_lock.clone(),
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
        self.inherit_handles.push(handle);
        Ok(())
    }

    pub fn get_inherited_handles(&self) -> &[&Handle] {
        &self.inherit_handles[..]
    }

    // TODO: split into file_readonly, file_write, file_append
    pub fn allow_file_access(
        &mut self,
        path: &str,
        readable: bool,
        writable: bool,
        restrict_to_append_only: bool,
    ) -> Result<(), PolicyError> {
        if restrict_to_append_only && !writable {
            return Err(PolicyError::AppendOnlyRequiresWriteAccess {
                path: path.to_owned(),
            });
        }
        for path in derive_all_file_paths_from_path(path)? {
            if let Err(e) = Pattern::new(&path) {
                return Err(PolicyError::InvalidPathPattern {
                    pattern: path.clone(),
                    description: e.msg.to_owned(),
                });
            }
            let (prev_readable, prev_writable, prev_restrict_to_append_only) = self
                .file_access
                .get(&path)
                .copied()
                .unwrap_or((false, false, false));
            let mut restrict_to_append_only = restrict_to_append_only;
            if writable && prev_writable {
                // grant the union of both rights: only restrict if both restrict
                restrict_to_append_only = prev_restrict_to_append_only && restrict_to_append_only;
            }
            self.file_access.insert(
                path.to_owned(),
                (
                    prev_readable || readable,
                    prev_writable || writable,
                    restrict_to_append_only,
                ),
            );
        }
        Ok(())
    }

    #[cfg(windows)]
    pub fn allow_regkey_access(
        &mut self,
        path: &str,
        readable: bool,
        writable: bool,
    ) -> Result<(), PolicyError> {
        let (prev_readable, prev_writable) = self
            .regkey_access
            .get(path)
            .copied()
            .unwrap_or((false, false));
        for path in derive_all_reg_key_paths_from_path(path)? {
            self.regkey_access
                .insert(path, (prev_readable || readable, prev_writable || writable));
        }
        Ok(())
    }

    pub fn get_file_allowed_access(&self, path: &str) -> (bool, bool, bool) {
        let mut result_readable = false;
        let mut result_writable = false;
        let mut result_restrict_to_append_only = false;
        for (pattern, (readable, writable, restrict_to_append_only)) in self.file_access.iter() {
            let pattern = Pattern::new(pattern).unwrap();
            if pattern.matches(path) {
                result_readable |= readable;
                if *writable {
                    if result_writable {
                        // grant the union of matching rules: only restrict if both do
                        result_restrict_to_append_only =
                            *restrict_to_append_only && result_restrict_to_append_only;
                    } else {
                        result_restrict_to_append_only = *restrict_to_append_only;
                    }
                    result_writable |= writable;
                }
            }
            if result_readable && result_writable && !result_restrict_to_append_only {
                break;
            }
        }
        (
            result_readable,
            result_writable,
            result_restrict_to_append_only,
        )
    }

    #[cfg(windows)]
    pub fn get_regkey_allowed_access(&self, path: &str) -> (bool, bool) {
        let mut result_readable = false;
        let mut result_writable = false;
        for (pattern, (readable, writable)) in self.regkey_access.iter() {
            let pattern = Pattern::new(pattern).unwrap();
            if pattern.matches(path) {
                result_readable |= readable;
                result_writable |= writable;
            }
            if result_readable && result_writable {
                break;
            }
        }
        (result_readable, result_writable)
    }

    pub fn allow_file_lock(
        &mut self,
        path: &str,
        readers: bool,
        writers: bool,
        deleters: bool,
    ) -> Result<(), PolicyError> {
        for path in derive_all_file_paths_from_path(path)? {
            if let Err(e) = Pattern::new(&path) {
                return Err(PolicyError::InvalidPathPattern {
                    pattern: path.clone(),
                    description: e.msg.to_owned(),
                });
            }
            if let Some((prev_readers, prev_writers, prev_deleters)) = self
                .file_lock
                .insert(path.to_owned(), (readers, writers, deleters))
            {
                self.file_lock.insert(
                    path.to_owned(),
                    (
                        (readers || prev_readers),
                        (writers || prev_writers),
                        (deleters || prev_deleters),
                    ),
                );
            }
        }
        Ok(())
    }

    pub fn get_file_allowed_lock(&self, path: &str) -> (bool, bool, bool) {
        let mut result_readers = false;
        let mut result_writers = false;
        let mut result_deleters = false;
        for (pattern, (readers, writers, deleters)) in self.file_lock.iter() {
            let pattern = Pattern::new(pattern).unwrap();
            if pattern.matches(path) {
                result_readers |= readers;
                result_writers |= writers;
                result_deleters |= deleters;
            }
            if result_readers && result_writers && result_deleters {
                break;
            }
        }
        (result_readers, result_writers, result_deleters)
    }
}

impl<'a> Default for Policy<'a> {
    fn default() -> Self {
        Self::nothing_allowed()
    }
}
