use iris_policy::Handle;

pub trait CrossPlatformMessagePipe {
    fn into_handle(self) -> Handle;

    /**
     * Must only be called with handles returned by the same implementation of CrossPlatformMessagePipe
     * when called with into_handle() in order to be safe.
     */
    fn from_handle(handle: Handle) -> Self
    where
        Self: std::marker::Sized;

    fn new() -> Result<(Self, Self), String>
    where
        Self: std::marker::Sized;

    fn recv(&mut self) -> Result<Vec<u8>, String>;

    fn recv_with_handle(&mut self) -> Result<(Vec<u8>, Option<Handle>), String>;

    fn set_remote_process(&mut self, remote_pid: u64) -> Result<(), String>;

    fn send(&mut self, message: &[u8], handle: Option<&Handle>) -> Result<(), String>;
}
