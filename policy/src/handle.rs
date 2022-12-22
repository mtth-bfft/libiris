#[derive(Debug, Eq, PartialEq)]
pub struct Handle {
    pub(crate) val: Option<u64>,
}

pub trait CrossPlatformHandle: core::fmt::Debug {
    /// # Safety
    /// Only call this function with raw_handle a valid file descriptor or handle,
    /// and do not use raw_handle after it is passed here. This method takes ownership
    /// of the handle and takes care of closing it when out of scope.
    unsafe fn new(raw_handle: u64) -> Result<Self, String>
    where
        Self: Sized;

    fn as_raw(&self) -> u64;

    /// # Safety
    /// After reducing back the file descriptor/handle to a primitive u64, callers are
    /// in charge of closing them. Failure to do so will result in a resource leak.
    unsafe fn into_raw(self) -> u64
    where
        Self: Sized;

    fn set_inheritable(&mut self, allow_inherit: bool) -> Result<(), String>;

    fn is_inheritable(&self) -> Result<bool, String>;
}
