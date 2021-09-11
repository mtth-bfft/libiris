#[derive(Debug, Eq, PartialEq)]
pub struct Handle {
    pub(crate) val: Option<u64>,
}

pub trait CrossPlatformHandle: core::fmt::Debug {
    unsafe fn new(raw_handle: u64) -> Result<Self, String>
    where
        Self: Sized;

    fn as_raw(&self) -> u64;

    unsafe fn into_raw(self) -> u64
    where
        Self: Sized;

    fn set_inheritable(&mut self, allow_inherit: bool) -> Result<(), String>;

    fn is_inheritable(&self) -> Result<bool, String>;
}
