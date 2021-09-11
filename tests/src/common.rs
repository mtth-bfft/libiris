use iris_broker::set_unmanaged_handle_inheritable;
use std::ffi::{CString, OsString};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

// Common functions used by all tests for setup / check / teardown
pub fn main() {
    println!("This crate is not designed to be run directly, use 'cargo test' to run each module in tests/*.rs");
}

// OS-specific modules
#[cfg_attr(target_family = "unix", path = "unix/common.rs")]
#[cfg_attr(target_family = "windows", path = "windows/common.rs")]
pub mod os;

// Multi-platform implementations
pub use os::check_worker_handles;

// Cross-platform implementations
pub fn open_tmp_file() -> (File, PathBuf) {
    let mut tmpdir = std::env::temp_dir();
    for i in 1..1000 {
        tmpdir.push(format!("tmp_test_{}", i));
        if let Ok(f) = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&tmpdir)
        {
            println!(" [.] Storing temporary output to {}", tmpdir.display());
            set_unmanaged_handle_inheritable(&f, true).unwrap();
            return (f, tmpdir);
        }
        tmpdir.pop();
    }
    panic!("No writable location found for temporary test file");
}

// Don't implement this as a standard Drop trait on a struct, we want precise
// control over when the tmp file is cleaned up between different assert/panic()s (which would trigger drop())
pub fn cleanup_tmp_file(path: &Path) {
    std::fs::remove_file(path).expect(&format!(
        "Unable to remove temporary file {}",
        path.display()
    ));
}

pub fn get_worker_bin_path() -> CString {
    let exe = std::env::current_exe().unwrap();
    let test_name = exe
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .rsplitn(2, '-')
        .last()
        .unwrap();
    let file_name = format!("{}_worker", test_name);
    let ext = exe.extension().and_then(|e| Some(OsString::from(e)));
    let mut dir = exe.clone();
    let mut worker_binary;
    loop {
        dir = dir
            .parent()
            .expect(&format!(
                "worker binary {} not found in any parent directory of {}",
                &file_name,
                exe.to_string_lossy()
            ))
            .to_path_buf();
        worker_binary = dir.with_file_name(&file_name);
        if let Some(ext) = &ext {
            worker_binary.set_extension(ext);
        }
        if worker_binary.exists() {
            break;
        }
    }
    println!(" [.] Worker binary: {}", worker_binary.display());
    CString::new(worker_binary.as_os_str().to_string_lossy().as_bytes()).unwrap()
}
