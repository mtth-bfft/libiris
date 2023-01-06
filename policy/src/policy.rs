use crate::error::PolicyError;
use crate::handle::CrossPlatformHandle;
use crate::os::path::derive_all_file_paths_from_path;
#[cfg(windows)]
use crate::os::path::derive_all_reg_key_paths_from_path;
use std::ffi::{CString, CStr};
use crate::Handle;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(unix)]
const OS_PATH_SEPARATOR: u8 = b'/';
#[cfg(windows)]
const OS_PATH_SEPARATOR: u8 = b'\\';

// TODO: Eq required for serializability here. Replace Vec<> with unordered sets
// to avoid making the semantics of == and != non-intuitive.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Policy<'a> {
    #[serde(skip)]
    inherit_handles: Vec<&'a Handle>,
    file_access: HashMap<CString, (bool, bool, bool, bool, bool)>,
    dir_access: HashMap<CString, (bool, bool, bool, bool, bool)>,
    regkey_access: HashMap<CString, (bool, bool)>,
}

fn strip_one_component_and_separator(path: CString) -> Option<CString> {
    let mut bytes = path.into_bytes();
    while !bytes.is_empty() && bytes.last() != Some(&OS_PATH_SEPARATOR) {
        bytes.pop();
    }
    bytes.pop(); // remove the trailing / (or no-op if the buffer is empty)
    if bytes.is_empty() {
        None
    } else {
        bytes.push(0);
        Some(CString::from_vec_with_nul(bytes).unwrap())
    }
}

impl<'a> Policy<'a> {
    pub fn nothing_allowed() -> Self {
        Self {
            inherit_handles: Vec::new(),
            file_access: HashMap::new(),
            dir_access: HashMap::new(),
            regkey_access: HashMap::new(),
        }
    }

    pub fn get_runtime_policy(&self) -> Policy<'static> {
        Policy {
            inherit_handles: Vec::new(),
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
        self.inherit_handles.push(handle);
        Ok(())
    }

    pub fn get_inherited_handles(&self) -> &[&Handle] {
        &self.inherit_handles[..]
    }

    fn add_file_access(&mut self, path: &CStr, dir: bool, access: (bool, bool, bool, bool, bool)) -> Result<(), PolicyError> {
        let (new_read, new_write, new_block_readers, new_block_writers, new_block_deleters) = access;
        for path in derive_all_file_paths_from_path(path)? {
            let mut path = path.clone();
            if dir && path.as_bytes().last() != Some(&OS_PATH_SEPARATOR) {
                let mut v = path.into_bytes();
                v.push(OS_PATH_SEPARATOR);
                v.push(0);
                path = CString::from_vec_with_nul(v).unwrap();
            }
            let map = if dir { &mut self.dir_access } else { &mut self.file_access };
            let (prev_read, prev_write, prev_block_readers, prev_block_writers, prev_block_deleters) = map
                .get(&path)
                .copied()
                .unwrap_or((false, false, false, false, false));
            map.insert(
                path,
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

    pub fn allow_file_read(&mut self, path: &CStr) -> Result<(), PolicyError> {
        self.add_file_access(path, false, (true, false, false, false, false))
    }

    pub fn allow_file_write(&mut self, path: &CStr) -> Result<(), PolicyError> {
        self.add_file_access(path, false, (false, true, false, false, false))
    }

    pub fn allow_file_lock(
        &mut self,
        path: &CStr,
        block_other_readers: bool,
        block_other_writers: bool,
        block_other_deleters: bool,
    ) -> Result<(), PolicyError> {
        self.add_file_access(path, false, (false, false, block_other_readers, block_other_writers, block_other_deleters))
    }

    pub fn allow_dir_read(&mut self, path: &CStr) -> Result<(), PolicyError> {
        self.add_file_access(path, true, (true, false, false, false, false))
    }

    pub fn allow_dir_write(&mut self, path: &CStr) -> Result<(), PolicyError> {
        self.add_file_access(path, true, (false, true, false, false, false))
    }

    pub fn allow_dir_lock(
        &mut self,
        path: &CStr,
        block_other_readers: bool,
        block_other_writers: bool,
        block_other_deleters: bool,
    ) -> Result<(), PolicyError> {
        self.add_file_access(path, true, (false, false, block_other_readers, block_other_writers, block_other_deleters))
    }

    pub fn get_path_allowed_access(&self, path: &CStr, dir: bool) -> (bool, bool, bool, bool, bool) {
        let path = if dir && path.to_bytes().last() != Some(&OS_PATH_SEPARATOR) {
            let mut v = path.to_bytes().to_owned();
            v.push(OS_PATH_SEPARATOR);
            v.push(0);
            CString::from_vec_with_nul(v).unwrap()
        } else {
            path.to_owned()
        };
        let mut verdict_read = false;
        let mut verdict_write = false;
        let mut verdict_block_readers = false;
        let mut verdict_block_writers = false;
        let mut verdict_block_deleters = false;
        if let Some((read, write, block_readers, block_writers, block_deleters)) = self.file_access.get(&path) {
            verdict_read |= read;
            verdict_write |= write;
            verdict_block_readers |= block_readers;
            verdict_block_writers |= block_writers;
            verdict_block_deleters |= block_deleters;
        }
        let mut current_path = path.to_owned();
        while !verdict_read || !verdict_write || !verdict_block_readers || !verdict_block_writers || !verdict_block_deleters {
            if let Some((read, write, block_readers, block_writers, block_deleters)) = self.dir_access.get(&current_path) {
                verdict_read |= read;
                verdict_write |= write;
                verdict_block_readers |= block_readers;
                verdict_block_writers |= block_writers;
                verdict_block_deleters |= block_deleters;
            }
            match strip_one_component_and_separator(current_path) {
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

    #[cfg(windows)]
    fn add_regkey_access(&mut self, path: &CStr, access: (bool, bool)) -> Result<(), PolicyError> {
        let (new_read, new_write) = access;
        for path in derive_all_reg_key_paths_from_path(path)? {
            let path = strip_last_separator(&path);
            let (prev_read, prev_write) = self.regkey_access.get(&path)
                .copied()
                .unwrap_or((false, false));
            self.regkey_access.insert(
                path,
                (
                    prev_read | new_read,
                    prev_write | new_write,
                )
            );
        }
        Ok(())

    }

    #[cfg(windows)]
    pub fn allow_regkey_read(&mut self, path: &CStr) -> Result<(), PolicyError> {
        self.add_regkey_access(path, (true, false))
    }

    #[cfg(windows)]
    pub fn allow_regkey_write(&mut self, path: &CStr) -> Result<(), PolicyError> {
        self.add_regkey_access(path, (false, true))
    }

    #[cfg(windows)]
    pub fn get_regkey_allowed_access(&self, path: &CStr, dir: bool) -> (bool, bool) {
        let mut verdict_read = false;
        let mut verdict_write = false;
        let mut current_path = strip_last_separator(path);
        while !verdict_read || !verdict_write {
            if let Some((read, write)) = self.regkey_access.get(&current_path) {
                verdict_read |= read;
                verdict_write |= write;
            }
            match strip_one_component_and_separator(current_path) {
                Some(parent_path) => current_path = parent_path,
                None => break,
            }
        }
        (
            verdict_read,
            verdict_write,
        )
    }
}
