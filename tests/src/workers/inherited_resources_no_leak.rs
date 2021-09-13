#[cfg(windows)]
fn main() {
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
fn main() {
    unimplemented!();
}
