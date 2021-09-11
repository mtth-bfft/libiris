use winapi::um::handleapi::{GetHandleInformation, SetHandleInformation};
use winapi::um::winbase::HANDLE_FLAG_INHERIT;
use winapi::um::errhandlingapi::GetLastError;
use winapi::shared::minwindef::DWORD;

pub fn set_handle_inheritable(handle: u64, allow_inherit: bool) -> Result<(), String> {
    let res = unsafe { SetHandleInformation(handle as *mut _, HANDLE_FLAG_INHERIT, if allow_inherit { HANDLE_FLAG_INHERIT } else { 0 }) };
    if res == 0 {
        return Err(format!("SetHandleInformation() failed with error {}", unsafe { GetLastError() }));
    }
    Ok(())
}

pub fn is_handle_inheritable(handle: u64) -> Result<bool, String> {
    let mut flags: DWORD = 0;
    let res = unsafe { GetHandleInformation(handle as *mut _, &mut flags as *mut _) };
    if res == 0 {
        return Err(format!("GetHandleInformation() failed with error {}", unsafe { GetLastError() }));
    }
    Ok((flags & HANDLE_FLAG_INHERIT) != 0)
}


