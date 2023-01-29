use crate::error::IpcError;
use crate::messagepipe::CrossPlatformMessagePipe;
use crate::os::messagepipe::OSMessagePipe;
use bincode::{ErrorKind, Options};
use core::fmt::Debug;
use iris_policy::Handle;
use serde::{de::DeserializeOwned, Serialize};

// Maximum message size that can be serialized and deserialized over an
// IPC channel. Larger messages should use other (more efficient)
// strategies to send/receive data, like shared memory sections.
pub(crate) const IPC_MESSAGE_MAX_SIZE: u32 = 1024 * 1024;

pub struct IPCMessagePipe {
    pipe: OSMessagePipe,
}

impl IPCMessagePipe {
    pub fn new(pipe: OSMessagePipe) -> Self {
        Self { pipe }
    }

    pub fn send<T: Serialize + Debug>(
        &mut self,
        msg: &T,
        handle: Option<&Handle>,
    ) -> Result<(), IpcError> {
        let bincode_config = bincode::DefaultOptions::new()
            .with_limit(IPC_MESSAGE_MAX_SIZE.into())
            .with_native_endian()
            .with_fixint_encoding()
            .reject_trailing_bytes();
        let bytes = match bincode_config.serialize(&msg).map_err(|e| *e) {
            Ok(v) => v,
            Err(ErrorKind::SizeLimit) => {
                return Err(IpcError::PayloadTooBigToSerialize {
                    payload: format!("{msg:?}"),
                })
            }
            Err(e) => {
                return Err(IpcError::InternalSerializationError {
                    payload: format!("{msg:?}"),
                    description: e.to_string(),
                })
            }
        };
        self.pipe.send(&bytes, handle)?;
        Ok(())
    }

    pub fn recv<T: DeserializeOwned>(&mut self) -> Result<Option<T>, IpcError> {
        let bincode_config = bincode::DefaultOptions::new()
            .with_limit(IPC_MESSAGE_MAX_SIZE.into())
            .with_native_endian()
            .with_fixint_encoding()
            .reject_trailing_bytes();
        let bytes = self.pipe.recv()?;
        if bytes.is_empty() {
            return Ok(None);
        }
        let msg = match bincode_config.deserialize(&bytes).map_err(|e| *e) {
            Ok(r) => r,
            Err(ErrorKind::SizeLimit) => {
                return Err(IpcError::PayloadTooBigToDeserialize { payload: bytes })
            }
            Err(e) => {
                return Err(IpcError::InternalDeserializationError {
                    payload: bytes,
                    description: e.to_string(),
                })
            }
        };
        Ok(Some(msg))
    }

    pub fn recv_with_handle<T: DeserializeOwned>(
        &mut self,
    ) -> Result<(Option<T>, Option<Handle>), IpcError> {
        let bincode_config = bincode::DefaultOptions::new()
            .with_limit(IPC_MESSAGE_MAX_SIZE.into())
            .with_native_endian()
            .with_fixint_encoding()
            .reject_trailing_bytes();
        let (bytes, handle) = self.pipe.recv_with_handle()?;
        if bytes.is_empty() {
            return Ok((None, handle));
        }
        let msg = match bincode_config.deserialize(&bytes).map_err(|e| *e) {
            Ok(r) => r,
            Err(ErrorKind::SizeLimit) => {
                return Err(IpcError::PayloadTooBigToDeserialize { payload: bytes })
            }
            Err(e) => {
                return Err(IpcError::InternalDeserializationError {
                    payload: bytes,
                    description: e.to_string(),
                })
            }
        };
        Ok((Some(msg), handle))
    }
}
