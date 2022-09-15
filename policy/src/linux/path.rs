pub fn derive_all_file_paths_from_path(path: &str) -> Vec<String> {
    // Nothing to do here. As long as paths are absolute, they have no
    // "equivalent" that we need to allow. There may be other ways to
    // access to the same file/directory (e.g. multiple mount points
    // exposing one of the parent directories), but there is no
    // usecase (at least for now) where we need to take this into
    // account.
    vec![path.to_owned()]
}
