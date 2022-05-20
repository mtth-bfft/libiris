use iris_policy::Handle;
use crate::ipc::IPCError;

pub trait CrossPlatformMessagePipe {
    fn into_handle(self) -> Handle;

    fn as_handle(&mut self) -> &mut Handle;

    /**
     * Must only be called with handles returned by the same implementation of CrossPlatformMessagePipe
     * when called with into_handle() in order to be safe.
     */
    fn from_handle(handle: Handle) -> Self
    where
        Self: core::marker::Sized;

    fn new() -> Result<(Self, Self), IPCError>
    where
        Self: core::marker::Sized;

    fn recv<'a>(&mut self, buffer: &'a mut [u8]) -> Result<&'a [u8], IPCError>;

    fn recv_with_handle<'a>(&mut self, buffer: &'a mut [u8]) -> Result<(&'a [u8], Option<Handle>), IPCError>;

    fn set_remote_process(&mut self, remote_pid: u64) -> Result<(), IPCError>;

    fn send(&mut self, message: &[u8], handle: Option<&Handle>) -> Result<(), IPCError>;
}
