use crate::PolicyError;

pub(crate) const OS_PATH_SEPARATOR: char = '/';

pub(crate) fn path_is_sane(path: &str) -> bool {
    let path = match path.strip_prefix('/') {
        Some(rest) => rest.strip_suffix('/').unwrap_or(rest),
        None => return false, // paths need to be absolute
    };
    for component in path.split('/') {
        if component.is_empty() {
            return false;
        }
        if component == "." || component == ".." {
            return false;
        }
    }
    true
}

pub(crate) fn derive_all_file_paths_from_path(path: &str) -> Result<Vec<String>, PolicyError> {
    // Nothing to do here. As long as paths are absolute, they have no
    // "equivalent" that we need to allow. There may be other ways to
    // access the same file/directory (e.g. multiple mount points
    // exposing one of the parent directories or the target itself), but
    // we do not need to introduce this complexity here.
    if !path.starts_with('/') {
        return Err(PolicyError::UnsupportedFilesystemPath { path: path.to_owned() });
    }
    Ok(vec![path.to_owned()])
}
