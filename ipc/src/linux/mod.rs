pub(crate) mod handle;
pub(crate) mod messagepipe;

pub(crate) fn errno() -> libc::c_int {
    unsafe { *(libc::__errno_location()) }
}
