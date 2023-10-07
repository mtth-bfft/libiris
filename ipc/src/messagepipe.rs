use crate::error::IpcError;
use iris_policy::os::Handle;

pub trait CrossPlatformMessagePipe {
    fn into_handle(self) -> Handle;

    /**
     * Must only be called with handles returned by the same implementation of CrossPlatformMessagePipe
     * when called with as_handles() in order to be safe.
     */
    fn from_handle(handle: Handle) -> Self
    where
        Self: std::marker::Sized;

    fn new() -> Result<(Self, Self), IpcError<'static>>
    where
        Self: std::marker::Sized;

    fn recv<'a>(&mut self, buffer: &'a mut [u8]) -> Result<Option<&'a mut [u8]>, IpcError<'a>>;

    fn recv_with_handle<'a>(
        &mut self,
        buffer: &'a mut [u8],
    ) -> Result<Option<(&'a mut [u8], Option<Handle>)>, IpcError<'a>>;

    fn set_remote_process(&mut self, remote_pid: u64) -> Result<(), IpcError<'static>>;

    fn send<'a>(
        &mut self,
        message: &'a [u8],
        handle: Option<&'a Handle>,
    ) -> Result<(), IpcError<'a>>;
}
