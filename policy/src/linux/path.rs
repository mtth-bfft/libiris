use std::ffi::{CStr, CString};
use crate::PolicyError;

pub fn derive_all_file_paths_from_path(path: &CStr) -> Result<Vec<CString>, PolicyError> {
    // Nothing to do here. As long as paths are absolute, they have no
    // "equivalent" that we need to allow. There may be other ways to
    // access the same file/directory (e.g. multiple mount points
    // exposing one of the parent directories or the target itself), but
    // we do not need to introduce this complexity here.
    if path.to_bytes().get(0) != Some(&b'/') {
        return Err(PolicyError::UnsupportedFilesystemPath { path: path.to_owned() });
    }
    Ok(vec![path.to_owned()])
}
