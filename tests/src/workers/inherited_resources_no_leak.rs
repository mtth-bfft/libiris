#[cfg(windows)]
fn main() {
    use std::ffi::CString;
    use winapi::um::debugapi::{IsDebuggerPresent, OutputDebugStringA};
    while unsafe { IsDebuggerPresent() } == 0 {
        ()
    }
    unsafe {
        OutputDebugStringA(CString::new("Ready for inspection").unwrap().as_ptr());
    }
    // Parent will kill us after inspecting our handles, so this last call will never return
}

#[cfg(unix)]
fn main() {
    unimplemented!();
}
