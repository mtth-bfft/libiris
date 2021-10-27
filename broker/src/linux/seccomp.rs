use core::ffi::c_void;
use seccomp_sys::{
    seccomp_init,
    seccomp_release,
    seccomp_attr_set,
    scmp_filter_attr,
};

pub(crate) struct SeccompFilter {
    pub(crate) context: *mut c_void,
}

impl SeccompFilter {
    pub fn new(default_action: u32) -> Result<Self, String> {
        let context = unsafe { seccomp_init(default_action) };
        if context.is_null() {
            return Err("seccomp_init() failed, no error information available".to_owned());
        }
        let res = unsafe { seccomp_attr_set(context, scmp_filter_attr::SCMP_FLTATR_CTL_TSYNC, 1) };
        if res != 0 {
            return Err(format!(
                "seccomp_attr_set(SCMP_FLTATR_CTL_TSYNC) failed with error {}",
                -res
            ));
        }
        Ok(Self {
            context,
        })
    }
}

impl Drop for SeccompFilter {
    fn drop(&mut self) {
        unsafe { seccomp_release(self.context) };
    }
}
