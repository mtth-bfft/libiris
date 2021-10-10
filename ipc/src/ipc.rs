use crate::messagepipe::CrossPlatformMessagePipe;
use crate::os::messagepipe::OSMessagePipe;
use bincode::Options;
use iris_policy::Handle;
use serde::{de::DeserializeOwned, Serialize};

// Maximum message size that can be serialized and deserialized over an
// IPC channel. Larger messages should use other (more efficient)
// strategies to send/receive data, like shared memory sections.
pub(crate) const IPC_MESSAGE_MAX_SIZE: u32 = 1 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum IPCVersion {
    V1 = 1,
}

pub struct IPCMessagePipe {
    pipe: OSMessagePipe,
}

impl IPCMessagePipe {
    pub fn new_server(mut pipe: OSMessagePipe, version: IPCVersion) -> Result<Self, String> {
        pipe.send(&[version as u8], None)?;
        Ok(Self { pipe })
    }
    pub fn new_client(mut pipe: OSMessagePipe) -> Result<(Self, IPCVersion), String> {
        let ver = pipe.recv()?;
        if ver.len() != 1 {
            return Err(format!(
                "Unexpected IPC received: expected 1-byte version, received {} bytes",
                ver.len()
            ));
        }
        if ver[0] == (IPCVersion::V1 as u8) {
            Ok((Self { pipe }, IPCVersion::V1))
        } else {
            Err(format!(
                "Unexpected IPC version received from server: {}",
                ver[0]
            ))
        }
    }

    pub fn send<T: Serialize>(&mut self, msg: &T, handle: Option<&Handle>) -> Result<(), String> {
        let bincode_config = bincode::DefaultOptions::new()
            .with_limit(IPC_MESSAGE_MAX_SIZE.into())
            .with_native_endian()
            .with_fixint_encoding()
            .reject_trailing_bytes();
        let bytes = match bincode_config.serialize(&msg) {
            Ok(v) => v,
            Err(e) => return Err(format!("Unable to serialize request: {}", e)),
        };
        self.pipe.send(&bytes, handle)?;
        Ok(())
    }

    pub fn recv<T: DeserializeOwned>(&mut self) -> Result<Option<T>, String> {
        let bincode_config = bincode::DefaultOptions::new()
            .with_limit(IPC_MESSAGE_MAX_SIZE.into())
            .with_native_endian()
            .with_fixint_encoding()
            .reject_trailing_bytes();
        let bytes = self.pipe.recv()?;
        if bytes.len() == 0 {
            return Ok(None);
        }
        let msg = match bincode_config.deserialize(&bytes) {
            Ok(r) => r,
            Err(e) => return Err(format!("Unable to deserialize message: {}", e)),
        };
        Ok(Some(msg))
    }

    pub fn recv_with_handle<T: DeserializeOwned>(
        &mut self,
    ) -> Result<(Option<T>, Option<Handle>), String> {
        let bincode_config = bincode::DefaultOptions::new()
            .with_limit(IPC_MESSAGE_MAX_SIZE.into())
            .with_native_endian()
            .with_fixint_encoding()
            .reject_trailing_bytes();
        let (bytes, handle) = self.pipe.recv_with_handle()?;
        if bytes.len() == 0 {
            return Ok((None, handle));
        }
        let msg = match bincode_config.deserialize(&bytes) {
            Ok(r) => r,
            Err(e) => return Err(format!("Unable to deserialize message: {}", e)),
        };
        Ok((Some(msg), handle))
    }
}
