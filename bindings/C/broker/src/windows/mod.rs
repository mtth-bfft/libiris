use core::ffi::c_char;
use iris_policy::os::PolicyRequest;
use std::ffi::CString;
use winapi::shared::ntdef::ULONG;
use winapi::um::winnt::ACCESS_MASK;

#[repr(C, u8)]
pub enum IrisPolicyRequest {
    FileOpen {
        path: *const c_char,
        desired_access: ACCESS_MASK,
        file_attributes: ULONG,
        share_access: ULONG,
        create_disposition: ULONG,
        create_options: ULONG,
        ea: *const u8,
        ea_length: u64,
    },
    RegKeyOpen {
        path: *const c_char,
        desired_access: ACCESS_MASK,
        create_options: ULONG,
        do_create: bool,
    },
}

impl From<&PolicyRequest<'_>> for IrisPolicyRequest {
    fn from(rust_enum: &PolicyRequest) -> Self {
        match *rust_enum {
            PolicyRequest::FileOpen {
                path,
                desired_access,
                file_attributes,
                share_access,
                create_disposition,
                create_options,
                ea,
            } => {
                let ea_length = ea.len() as u64;
                // There is no way in Stable to reconstruct a Vec from a ptr and size info.
                // We could convert the Vec to a boxed slice, but then leaking the box would
                // mean we rely on the internal memory layout of the box to not include an
                // intermediary object for the slice (e.g. a length field). To avoid this, we
                // just copy to a raw heap buffer with the exact right length.
                let ea = unsafe {
                    let layout = std::alloc::Layout::from_size_align(ea.len(), 16).unwrap();
                    let ptr = std::alloc::alloc(layout);
                    std::ptr::copy_nonoverlapping(ea.as_ptr(), ptr, ea.len());
                    ptr
                };
                Self::FileOpen {
                    path: CString::new(path).unwrap().into_raw(),
                    desired_access,
                    file_attributes,
                    share_access,
                    create_disposition,
                    create_options,
                    ea,
                    ea_length,
                }
            }
            PolicyRequest::RegKeyOpen {
                path,
                desired_access,
                create_options,
                do_create,
            } => Self::RegKeyOpen {
                path: CString::new(path).unwrap().into_raw(),
                desired_access,
                create_options,
                do_create,
            },
        }
    }
}

impl Drop for IrisPolicyRequest {
    fn drop(&mut self) {
        match *self {
            Self::FileOpen {
                path,
                ea,
                ea_length,
                ..
            } => {
                drop(unsafe { CString::from_raw(path as *mut i8) });
                let layout = std::alloc::Layout::from_size_align(ea_length as usize, 16).unwrap();
                unsafe {
                    std::alloc::dealloc(ea as *mut u8, layout);
                }
            }
            Self::RegKeyOpen { path, .. } => {
                drop(unsafe { CString::from_raw(path as *mut i8) });
            }
        }
    }
}
