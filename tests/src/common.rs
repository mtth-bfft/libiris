use iris_broker::set_unmanaged_handle_inheritable;
use log::{debug, info};
use simple_logger::SimpleLogger;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
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
            debug!("Storing temporary output to {}", tmpdir.display());
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

pub fn get_worker_abs_path(name: &str) -> CString {
    let exe = std::env::current_exe().unwrap();
    let file_name = format!("{}{}", name, exe.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or("".to_owned()));
    let workers_subdir_path = {
        let mut p = exe.clone();
        p.pop();
        p.push("workers");
        p.push(&file_name);
        p
    };
    let abspath = if workers_subdir_path.exists() { // try in ./workers/ for CI
        Some(workers_subdir_path)
    } else { // try in ../ for cargo test
        if let Some(parent_dir) = exe.parent() {
            debug!("Trying worker binary {}", parent_dir.with_file_name(&file_name).display());
            if parent_dir.with_file_name(&file_name).exists() {
                Some(parent_dir.with_file_name(&file_name))
            } else {
                None
            }
        } else {
            None
        }
    };
    let abspath = abspath.expect(&format!(
        "worker binary {} not found in same directory, workers/ subdirectory, or parent directory of {}",
        &file_name, exe.to_string_lossy()
    ));
    info!("Worker executable: {}", abspath.display());
    CString::new(abspath.as_os_str().to_string_lossy().as_bytes()).unwrap()
}
