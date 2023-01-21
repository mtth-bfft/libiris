use common::common_test_setup;
use iris_worker::lower_final_sandbox_privileges_asap;

#[cfg(windows)]
fn check() {
    use log::info;
    use std::ffi::CString;
    use winapi::um::debugapi::{IsDebuggerPresent, OutputDebugStringA};

    // We need a way to synchronize with our parent, so that they
    // know we finished initialization and we are ready for resource
    // leak inspection
    info!("Waiting for parent to debug us...");
    while unsafe { IsDebuggerPresent() } == 0 {}
    info!("Parent is watching us, signaling we're ready");
    let out_str = CString::new("Ready for inspection").unwrap();
    unsafe {
        OutputDebugStringA(out_str.as_ptr());
    }
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
