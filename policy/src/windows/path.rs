use crate::error::PolicyError;
use crate::handle::{CrossPlatformHandle, Handle};
use core::ptr::null_mut;
use std::ffi::CStr;
use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::HANDLE;
use winapi::shared::sddl::ConvertSidToStringSidA;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::GetFullPathNameW;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::GetTokenInformation;
use winapi::um::winbase::LocalFree;
use winapi::um::winnt::{TokenUser, TOKEN_QUERY, TOKEN_USER};

pub(crate) const OS_PATH_SEPARATOR: char = '\\';

pub(crate) fn path_is_sane(path: &str) -> bool {
    if !path.starts_with('\\') {
        return false;
    }
    // TODO: check for access to named streams
    true
}

pub(crate) fn derive_all_file_paths_from_path(path: &str) -> Result<Vec<String>, PolicyError> {
    let relative: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let str_len = unsafe { GetFullPathNameW(relative.as_ptr(), 0, null_mut(), null_mut()) };
    let absolute = if str_len == 0 {
        println!(
            " [!] GetFullPathNameW({}) failed with error {}",
            path,
            unsafe { GetLastError() }
        );
        path.to_owned()
    } else {
        let mut buf = vec![0u16; str_len as usize];
        let res =
            unsafe { GetFullPathNameW(relative.as_ptr(), str_len, buf.as_mut_ptr(), null_mut()) };
        if res == 0 || res > str_len {
            println!(
                " [!] GetFullPathNameW({}) failed with error {}",
                path,
                unsafe { GetLastError() }
            );
            path.to_owned()
        } else {
            match String::from_utf16(&buf[..str_len as usize - 1]) {
                Ok(s) => s,
                Err(e) => {
                    println!(
                        " [!] GetFullPathNameW({path}) returned a non-unicode result, {e}: {buf:?}"
                    );
                    path.to_owned()
                }
            }
        }
    };
    let mut res = vec![];
    // Drive-absolute path type
    if absolute.get(1..3) == Some(":\\") {
        res.push(format!("\\??\\{absolute}")); // \??\C:\Windows\Temp\a.txt
    }
    // TODO: improve validation, fail on unsupported types (e.g. relative ones)
    Ok(res)
}

pub fn derive_all_reg_key_paths_from_path(path: &str) -> Result<Vec<String>, PolicyError> {
    if let Some(rest) = path.strip_prefix("HKEY_CURRENT_USER") {
        Ok(vec![format!(
            "\\REGISTRY\\USER\\{}{}",
            get_current_user_sid(),
            rest
        )])
    } else if let Some(rest) = path.strip_prefix("HKEY_USERS") {
        Ok(vec![format!("\\REGISTRY\\USER{rest}")])
    } else if let Some(rest) = path.strip_prefix("HKEY_LOCAL_MACHINE") {
        Ok(vec![format!("\\REGISTRY\\MACHINE{rest}")])
    } else if let Some(rest) = path.strip_prefix("HKEY_CLASSES_ROOT") {
        Ok(vec![format!(
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes{rest}"
        )])
    } else if let Some(rest) = path.strip_prefix("HKEY_CURRENT_CONFIG") {
        Ok(vec![format!(
            "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current{rest}"
        )])
    } else {
        Err(PolicyError::UnsupportedRegistryPath {
            path: path.to_owned(),
        })
    }
}

fn get_current_user_sid() -> String {
    let handle = unsafe {
        let mut handle: HANDLE = null_mut();
        let res = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle as *mut _);
        if res == 0 {
            panic!(
                "Unable to open current process token, OpenProcessToken failed with code {}",
                GetLastError()
            );
        }
        Handle::new(handle as u64).unwrap()
    };
    let buf = unsafe {
        let mut buf_size: DWORD = 0;
        GetTokenInformation(
            handle.as_raw() as HANDLE,
            TokenUser,
            null_mut(),
            0,
            &mut buf_size as *mut _,
        );
        let mut buf = vec![0u8; buf_size as usize];
        let res = GetTokenInformation(
            handle.as_raw() as HANDLE,
            TokenUser,
            buf.as_mut_ptr() as *mut _,
            buf_size,
            &mut buf_size as *mut _,
        );
        if res == 0 {
            panic!(
                "Unable to read current process token, GetTokenInformation failed with code {}",
                GetLastError()
            );
        }
        buf
    };
    unsafe {
        let psid = (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid;
        let mut pstr: *mut i8 = null_mut();
        let res = ConvertSidToStringSidA(psid, &mut pstr as *mut _);
        if res == 0 {
            panic!(
                "Unable to format current user SID to string, failed with code {}",
                GetLastError()
            );
        }
        let sid = CStr::from_ptr(pstr).to_string_lossy().into_owned();
        LocalFree(pstr as *mut _);
        sid
    }
}
