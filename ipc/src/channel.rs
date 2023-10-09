use crate::IpcError;
use crate::os::Handle;
use serde::{Serialize, Deserialize};

pub trait CrossPlatformIpcChannel {
    fn new() -> Result<(Self, Self), IpcError<'static>> where Self: Sized;

    fn into_handle(self) -> Handle;
    
    fn from_handle(handle: Handle) -> Self;

    fn set_remote_process(&mut self, pid: u64) -> Result<(), IpcError<'static>>;

    fn send<'a, T: Serialize>(
        &mut self,
        msg: &'a T,
        handle: Option<&'a Handle>,
        buffer: &'a mut [u8],
    ) -> Result<(), IpcError<'a>>;

    fn recv<'de, T: Deserialize<'de>>(
        &mut self,
        buffer: &'de mut [u8],
    ) -> Result<Option<(T, Option<Handle>)>, IpcError<'de>>;
}

pub(crate) fn serialize<'a, T: Serialize>(msg: &'a T, buffer: &'a mut [u8]) -> Result<&'a mut [u8], IpcError<'static>> {
    postcard::to_slice(msg, buffer).map_err(|e| IpcError::InternalSerializationError {
        description: match e {
            postcard::Error::WontImplement => "tried to use a feature postcard won't support",
            postcard::Error::NotYetImplemented => "tried to use a feature not supported by postcard",
            postcard::Error::SerializeBufferFull => "message too long",
            postcard::Error::SerializeSeqLengthUnknown => "postcard requires sequence length to be known",
            postcard::Error::SerdeSerCustom => "postcard serde serialization error",
            postcard::Error::CollectStrError => "postcard collect_str error",
            _ => "unknown",
        },
    })
}

pub(crate) fn deserialize<'de, T: Deserialize<'de>>(buffer: &'de [u8]) -> Result<T, IpcError<'de>> {
    postcard::from_bytes(buffer).map_err(|e| IpcError::InternalDeserializationError {
        payload: buffer,
        description: match e {
            postcard::Error::WontImplement => "tried to use a feature postcard won't support",
            postcard::Error::NotYetImplemented => "tried to use a feature not supported by postcard",
            postcard::Error::DeserializeUnexpectedEnd => "postcard expected more data",
            postcard::Error::DeserializeBadVarint => "postcard found a varint that did not terminate",
            postcard::Error::DeserializeBadBool => "postcard found a bool that was neither 0 nor 1",
            postcard::Error::DeserializeBadChar | postcard::Error::DeserializeBadUtf8 => "postcard found an invalid unicode char",
            postcard::Error::DeserializeBadOption => "postcard found an option discriminant that was neither 0 nor 1",
            postcard::Error::DeserializeBadEnum => "postcard found an enum discriminant that was >u32max",
            postcard::Error::DeserializeBadEncoding => "postcard reports invalid encoding",
            postcard::Error::SerdeDeCustom => "postcard serde deserialization error",
            _ => "unknown",
        },
    })
}
