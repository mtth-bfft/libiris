use common::common_test_setup;
use iris_worker::lower_final_sandbox_privileges_asap;

#[cfg(windows)]
fn check() {
    use log::info;
    use winapi::um::debugapi::{DebugBreak, IsDebuggerPresent};

    // Just wait for our parent to finish checking which resources
    // we currently hold then kill us.
    info!("Waiting for parent to debug us...");
    while unsafe { IsDebuggerPresent() } == 0 {
        ()
    }
    info!("Parent is watching us, signaling we're ready");
    unsafe {
        DebugBreak();
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
