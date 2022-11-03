use common::common_test_setup;
use iris_worker::lower_final_sandbox_privileges_asap;

#[cfg(windows)]
fn check() {
    use std::ffi::CString;
    use winapi::um::debugapi::{IsDebuggerPresent, OutputDebugStringA};
    while unsafe { IsDebuggerPresent() } == 0 {
        ()
    }
    let msg = CString::new("Ready for inspection").unwrap();
    unsafe {
        OutputDebugStringA(msg.as_ptr());
    }
    // Parent will kill us after inspecting our handles, so this last call will never return
}

#[cfg(unix)]
fn check() {
    unimplemented!();
}

fn main() {
    lower_final_sandbox_privileges_asap();
    common_test_setup();
    check();
}
