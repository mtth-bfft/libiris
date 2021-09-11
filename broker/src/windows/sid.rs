use core::ptr::null_mut;
use std::ffi::CStr;
use std::fmt;
use winapi::shared::sddl::ConvertSidToStringSidA;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::userenv::DeriveAppContainerSidFromAppContainerName;
use winapi::um::winbase::LocalFree;
use winapi::um::winnt::PSID;

pub(crate) struct Sid {
    psid: PSID,
}

impl Drop for Sid {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.psid);
        }
    }
}

impl Sid {
    pub(crate) fn from_appcontainer_name(name: &str) -> Result<Self, String> {
        let mut psid: PSID = null_mut();
        let name_buf: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let res = unsafe {
            DeriveAppContainerSidFromAppContainerName(name_buf.as_ptr(), &mut psid as *mut _)
        };
        if res != 0 || psid.is_null() {
            return Err(format!(
                "DeriveAppContainerSidFromAppContainerName() failed with error {}",
                unsafe { GetLastError() }
            ));
        }
        Ok(Self { psid })
    }

    pub(crate) fn as_ptr(&self) -> PSID {
        self.psid
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut pstr: *mut i8 = null_mut();
        let res = unsafe { ConvertSidToStringSidA(self.psid, &mut pstr as *mut _) };
        if res == 0 {
            return write!(f, "<Unable to format SID: error {}>", unsafe {
                GetLastError()
            });
        }
        let sid = unsafe { CStr::from_ptr(pstr) };
        let res = write!(f, "{}", &sid.to_string_lossy());
        unsafe {
            LocalFree(pstr as *mut _);
        }
        res
    }
}
