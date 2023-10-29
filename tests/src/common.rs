use crate::os::set_unmanaged_handle_inheritable;
use log::{debug, info};
use simple_logger::SimpleLogger;
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::sync::Once;

// Common functions used by all tests for setup / check / teardown
pub fn main() {
    panic!("This crate is not designed to be run directly, use 'cargo test' to run each module in tests/*.rs");
}

// OS-specific modules
#[cfg_attr(target_family = "unix", path = "unix/common.rs")]
#[cfg_attr(target_family = "windows", path = "windows/common.rs")]
pub mod os;

// Multi-platform implementations
pub use os::check_worker_handles;

// Cross-platform implementations

static INIT_LOGGING: Once = Once::new();
pub fn common_test_setup() {
    INIT_LOGGING.call_once(|| {
        SimpleLogger::new()
            .init()
            .expect("unable to initialize logging");
    });
    std::env::set_var("RUST_BACKTRACE", "full");
}

pub fn open_tmp_file() -> (File, CString) {
    let mut tmpdir = std::env::temp_dir();
    for i in 1..1000 {
        tmpdir.push(format!("tmp_test_{i}"));
        if let Ok(f) = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&tmpdir)
        {
            debug!("Storing temporary output to {}", tmpdir.display());
            set_unmanaged_handle_inheritable(&f, true).unwrap();
            let path = CString::new(tmpdir.to_string_lossy().to_string()).unwrap();
            return (f, path);
        }
        tmpdir.pop();
    }
    panic!("No writable location found for temporary test file");
}

// Don't implement this as a standard Drop trait on a struct, we want precise
// control over when the tmp file is cleaned up between different assert/panic()s (which would trigger drop())
pub fn cleanup_tmp_file(path: &CStr) {
    let path = path.to_string_lossy().to_string();
    if let Err(e) = std::fs::remove_file(&path) {
        panic!("Unable to remove temporary file {path} : {e}");
    }
}

pub fn read_tmp_file(path: &CStr) -> String {
    let path = path.to_string_lossy().to_string();
    std::fs::read_to_string(&path).unwrap_or_else(|_| format!("<Unable to read {path:?}>"))
}

pub fn get_worker_abs_path(name: &str) -> CString {
    let exe = std::env::current_exe().unwrap();
    let file_name = if let Some(ext) = exe.extension() {
        format!("{}.{}", name, ext.to_string_lossy())
    } else {
        name.to_owned()
    };
    let workers_subdir_path = {
        let mut p = exe.clone();
        p.pop();
        p.push("workers");
        p.push(&file_name);
        p
    };
    let abspath = if workers_subdir_path.exists() {
        // try in ./workers/ for CI
        Some(workers_subdir_path)
    } else {
        // try in ../ for cargo test
        if let Some(parent_dir) = exe.parent() {
            debug!(
                "Trying worker binary {}",
                parent_dir.with_file_name(&file_name).display()
            );
            if parent_dir.with_file_name(&file_name).exists() {
                Some(parent_dir.with_file_name(&file_name))
            } else {
                None
            }
        } else {
            None
        }
    };
    let abspath = abspath.unwrap_or_else(|| panic!("worker binary {} not found in same directory, workers/ subdirectory, or parent directory of {}", &file_name, exe.to_string_lossy()));
    info!("Worker executable: {}", abspath.display());
    CString::new(abspath.as_os_str().to_string_lossy().as_bytes()).unwrap()
}
