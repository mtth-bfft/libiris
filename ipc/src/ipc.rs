use crate::messagepipe::CrossPlatformMessagePipe;
use crate::os::messagepipe::OSMessagePipe;
use bincode::{Options, ErrorKind};
use iris_policy::Handle;
use serde::{de::Deserialize, Serialize};
use core::fmt::{Display, Formatter};

// Maximum message size that can be serialized and deserialized over an
// IPC channel. Larger messages should use other (more efficient)
// strategies to send/receive data, like shared memory sections.
pub const IPC_MESSAGE_MAX_SIZE: usize = 1 * 1024;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum IPCVersion {
    V1 = 1,
}

#[derive(Debug)]
pub enum IPCError {
    UnsupportedServerVersion,
    OSError(i64),
    Serialization(ErrorKind),
    MessageTruncated,
    AncillaryDataTruncated,
    UnexpectedAncillaryData {
        clevel: libc::c_int,
        ctype: libc::c_int,
    },
}


impl Display for IPCError {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        match self {
            IPCError::UnsupportedServerVersion =>
                write!(f, "server exposes an unsupported IPC version"),
            IPCError::OSError(n) =>
                write!(f, "OS returned error code {}", n),
            IPCError::Serialization(e) =>
                write!(f, "serialization failed: {}", e),
            IPCError::MessageTruncated =>
                write!(f, "message truncated"),
            IPCError::AncillaryDataTruncated =>
                write!(f, "ancillary data truncated"),
            IPCError::UnexpectedAncillaryData { clevel, ctype }=>
                write!(f, "unexpected ancillary data (level {} type {})", clevel, ctype),
        }
    }
}

pub struct IPCMessagePipe {
    pipe: OSMessagePipe,
}

impl IPCMessagePipe {
    pub fn new_server(mut pipe: OSMessagePipe, version: IPCVersion, _buffer: &mut [u8]) -> Result<Self, IPCError> {
        pipe.send(&[version as u8], None)?;
        Ok(Self { pipe })
    }
    pub fn new_client(mut pipe: OSMessagePipe, buffer: &mut [u8]) -> Result<(Self, IPCVersion), IPCError> {
        let ver = pipe.recv(buffer)?;
        if ver.len() != 1 || ver[0] != (IPCVersion::V1 as u8) {
            return Err(IPCError::UnsupportedServerVersion);
        }
        Ok((Self { pipe }, IPCVersion::V1))
    }

    pub fn send<T: Serialize>(&mut self, msg: &T, handle: Option<&Handle>, buffer: &mut [u8]) -> Result<(), IPCError> {
        let bincode_config = bincode::DefaultOptions::new()
            .with_limit(buffer.len() as u64)
            .with_native_endian()
            .with_fixint_encoding()
            .reject_trailing_bytes();
        let bytes = match bincode_config.serialize(&msg) {
            Ok(v) => v,
            Err(e) => return Err(IPCError::Serialization(*e)),
        };
        self.pipe.send(&bytes, handle)?;
        Ok(())
    }

    pub fn recv<'de, T: Deserialize<'de>>(&mut self, buffer: &'de mut [u8]) -> Result<Option<T>, IPCError> {
        let bincode_config = bincode::DefaultOptions::new()
            .with_limit(buffer.len() as u64)
            .with_native_endian()
            .with_fixint_encoding()
            .reject_trailing_bytes();
        let bytes = self.pipe.recv(buffer)?;
        if bytes.len() == 0 {
            return Ok(None);
        }
        let msg = match bincode_config.deserialize(&bytes) {
            Ok(r) => r,
            Err(e) => return Err(IPCError::Serialization(*e)),
        };
        Ok(Some(msg))
    }

    pub fn recv_with_handle<'de, T: Deserialize<'de>>(
        &mut self,
        buffer: &'de mut [u8]
    ) -> Result<(Option<T>, Option<Handle>), IPCError> {
        let bincode_config = bincode::DefaultOptions::new()
            .with_limit(buffer.len() as u64)
            .with_native_endian()
            .with_fixint_encoding()
            .reject_trailing_bytes();
        let (bytes, handle) = self.pipe.recv_with_handle(buffer)?;
        if bytes.len() == 0 {
            return Ok((None, handle));
        }
        let msg = match bincode_config.deserialize(&bytes) {
            Ok(r) => r,
            Err(e) => return Err(IPCError::Serialization(*e)),
        };
        Ok((Some(msg), handle))
    }
}
