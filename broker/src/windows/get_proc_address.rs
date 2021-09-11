use core::ptr::null_mut;
use std::ffi::CString;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::winnt::PVOID;

pub(crate) fn get_proc_address(dll_name: &str, func_name: &str) -> PVOID {
    let dll_name = match CString::new(dll_name) {
        Ok(s) => s,
        _ => return null_mut(),
    };
    let func_name = match CString::new(func_name) {
        Ok(s) => s,
        _ => return null_mut(),
    };
    let h_dll = unsafe { GetModuleHandleA(dll_name.as_ptr()) };
    if h_dll.is_null() {
        return null_mut();
    }
    unsafe { GetProcAddress(h_dll, func_name.as_ptr()) as PVOID }
}
