#[cfg(windows)]
fn main() {
    use winapi::um::debugapi::{DebugBreak, IsDebuggerPresent};
    // Just wait for our parent to finish checking which resources
    // we currently hold then kill us.
    println!("Waiting for parent to debug us...");
    while unsafe { IsDebuggerPresent() } == 0 {
        ()
    }
    println!("Parent is watching us, signaling we're ready");
    unsafe {
        DebugBreak();
    }
}

#[cfg(unix)]
fn main() {
    unimplemented!();
}
