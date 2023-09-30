use crate::error::IpcError;
use crate::messagepipe::CrossPlatformMessagePipe;
use crate::os::messagepipe::OSMessagePipe;
use crate::Handle;
use serde::{Deserialize, Serialize};

pub struct IPCMessagePipe {
    pipe: OSMessagePipe,
}

impl IPCMessagePipe {
    pub fn new(pipe: OSMessagePipe) -> Self {
        Self { pipe }
    }

    pub fn send<'a, T: Serialize>(
        &mut self,
        msg: &'a T,
        handle: Option<&'a Handle>,
        buffer: &'a mut [u8],
    ) -> Result<(), IpcError<'a>> {
        let slice = postcard::to_slice(msg, buffer).expect("serialization error");
        self.pipe.send(slice, handle)?;
        Ok(())
    }

    pub fn recv<'de, T>(&mut self, buffer: &'de mut [u8]) -> Result<Option<T>, IpcError<'de>>
    where
        T: Deserialize<'de>,
    {
        let buffer = match self.pipe.recv(buffer)? {
            Some(buf) => buf,
            None => return Ok(None),
        };
        let msg: T = postcard::from_bytes(buffer).unwrap();
        Ok(Some(msg))
    }

    pub fn recv_with_handle<'de, T>(
        &mut self,
        buffer: &'de mut [u8],
    ) -> Result<Option<(T, Option<Handle>)>, IpcError<'de>>
    where
        T: Deserialize<'de>,
    {
        match self.pipe.recv_with_handle(buffer)? {
            None => Ok(None),
            Some((bytes, handle)) => {
                let msg: T = postcard::from_bytes(&*bytes).unwrap();
                Ok(Some((msg, handle)))
            }
        }
    }
}
