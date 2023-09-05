use crate::error::IpcError;
use crate::messagepipe::CrossPlatformMessagePipe;
use core::ptr::null_mut;
use iris_policy::{CrossPlatformHandle, Handle};
use log::debug;
use std::convert::TryInto;
use std::ffi::CString;
use winapi::shared::minwindef::DWORD;
use winapi::shared::winerror::{ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_PIPE_CONNECTED};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{CreateFileA, ReadFile, WriteFile, OPEN_EXISTING};
use winapi::um::handleapi::{DuplicateHandle, INVALID_HANDLE_VALUE};
use winapi::um::namedpipeapi::{ConnectNamedPipe, SetNamedPipeHandleState};
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess};
use winapi::um::winbase::CreateNamedPipeA;
use winapi::um::winbase::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX, PIPE_READMODE_MESSAGE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE,
};
use winapi::um::winnt::{
    DUPLICATE_SAME_ACCESS, FILE_READ_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, HANDLE,
    PROCESS_DUP_HANDLE,
};

const PIPE_BUFFER_SIZE: u32 = 64 * 1024;
const PIPE_FOOTER_SIZE: u32 = std::mem::size_of::<u64>() as u32;

pub struct OSMessagePipe {
    pipe_handle: Handle,
    remote_process_handle: Option<Handle>,
}

impl CrossPlatformMessagePipe for OSMessagePipe {
    fn into_handle(self) -> Handle {
        self.pipe_handle
    }

    fn from_handle(handle: Handle) -> Self {
        Self {
            pipe_handle: handle,
            remote_process_handle: None,
        }
    }

    fn new() -> Result<(Self, Self), IpcError<'static>> {
        let mut pipe_id = 0;
        loop {
            pipe_id += 1;
            let name = format!("\\\\.\\pipe\\ipc-{}-{}", std::process::id(), pipe_id);
            let name_nul = CString::new(name).unwrap();
            let handle1 = unsafe {
                let res = CreateNamedPipeA(
                    name_nul.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
                    2,
                    PIPE_BUFFER_SIZE,
                    PIPE_BUFFER_SIZE,
                    0,
                    null_mut(),
                );
                if res.is_null() || res == INVALID_HANDLE_VALUE {
                    // No handle was returned, it is safe to just exit the unsafe block
                    let err = GetLastError();
                    if err == ERROR_ACCESS_DENIED {
                        // pipe already exists
                        continue;
                    }
                    return Err(IpcError::InternalOsOperationFailed {
                        description: "CreateNamedPipe() failed",
                        os_code: err.into(),
                    });
                }
                Handle::new(res as u64).unwrap()
            };
            let handle2 = unsafe {
                let res = CreateFileA(
                    name_nul.as_ptr(),
                    FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES,
                    0,
                    null_mut(),
                    OPEN_EXISTING,
                    0,
                    null_mut(),
                );
                // FILE_WRITE_ATTRIBUTES is required to set the pipe mode to "messages" afterwards.
                if res == INVALID_HANDLE_VALUE {
                    // No handle was returned, it is safe to just exit the unsafe block
                    // Continuing will also destroy handle1 created just above
                    return Err(IpcError::InternalOsOperationFailed {
                        description: "CreateFile() failed",
                        os_code: GetLastError().into(),
                    });
                }
                Handle::new(res as u64).unwrap()
            };
            let res = unsafe { ConnectNamedPipe(handle1.as_raw() as HANDLE, null_mut()) };
            if res == 0 {
                let err = unsafe { GetLastError() };
                if err != ERROR_PIPE_CONNECTED {
                    return Err(IpcError::InternalOsOperationFailed {
                        description: "ConnectNamedPipe() failed",
                        os_code: err.into(),
                    });
                }
            }
            debug!("Using ipc pipe {}", name_nul.to_string_lossy());
            let mut new_mode: DWORD = PIPE_READMODE_MESSAGE;
            let res = unsafe {
                SetNamedPipeHandleState(
                    handle2.as_raw() as HANDLE,
                    &mut new_mode as *mut _,
                    null_mut(),
                    null_mut(),
                )
            };
            if res == 0 {
                return Err(IpcError::InternalOsOperationFailed {
                    description: "SetNamedPipeHandleState() failed",
                    os_code: unsafe { GetLastError() }.into(),
                });
            }
            return Ok((Self::from_handle(handle1), Self::from_handle(handle2)));
        }
    }

    fn recv<'a>(&mut self, buffer: &'a mut [u8]) -> Result<Option<&'a mut [u8]>, IpcError<'a>> {
        let mut bytes_read: DWORD = 0;
        let res = unsafe {
            ReadFile(
                self.pipe_handle.as_raw() as HANDLE,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut bytes_read as *mut _,
                null_mut(),
            )
        };
        if res == 0 || bytes_read < PIPE_FOOTER_SIZE {
            let err = unsafe { GetLastError() };
            if res == 0 && err == ERROR_BROKEN_PIPE {
                return Ok(None); // read of length 0 <=> end of file
            }
            return Err(IpcError::InternalOsOperationFailed {
                description: "ReadFile() failed",
                os_code: err.into(),
            });
        }
        Ok(Some(
            &mut buffer[0..(bytes_read - PIPE_FOOTER_SIZE) as usize],
        ))
    }

    fn recv_with_handle<'a>(
        &mut self,
        buffer: &'a mut [u8],
    ) -> Result<Option<(&'a mut [u8], Option<Handle>)>, IpcError<'a>> {
        let mut bytes_read: DWORD = 0;
        unsafe {
            let res = ReadFile(
                self.pipe_handle.as_raw() as HANDLE,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut bytes_read as *mut _,
                null_mut(),
            );
            if res == 0 || bytes_read < PIPE_FOOTER_SIZE {
                let err = GetLastError();
                if res == 0 && err == ERROR_BROKEN_PIPE {
                    return Ok(None); // read of length 0 <=> end of file
                }
                return Err(IpcError::InternalOsOperationFailed {
                    description: "ReadFile() failed",
                    os_code: err.into(),
                });
            }
            let payload_size = (bytes_read - PIPE_FOOTER_SIZE) as usize;
            let read_size = bytes_read as usize;
            let handle = match u64::from_be_bytes(
                buffer[payload_size..read_size]
                    .try_into()
                    .unwrap_or([0u8; 8]),
            ) {
                n if n > 0 => Some(Handle::new(n).map_err(IpcError::HandleOperationFailed)?),
                _n => None,
            };
            Ok(Some((&mut buffer[..payload_size], handle)))
        }
    }

    fn set_remote_process(&mut self, remote_pid: u64) -> Result<(), IpcError<'static>> {
        let remote_pid: u32 = match remote_pid.try_into() {
            Ok(n) => n,
            Err(_) => return Err(IpcError::InvalidProcessID { pid: remote_pid }),
        };
        self.remote_process_handle = unsafe {
            let res = OpenProcess(PROCESS_DUP_HANDLE, 0, remote_pid);
            if res.is_null() {
                // It is safe to return here, OpenProcess() failed to open any handle
                return Err(IpcError::UnableToOpenProcessOnTheOtherEnd {
                    pid: remote_pid.into(),
                    os_code: GetLastError().into(),
                });
            }
            Some(Handle::new(res as u64).unwrap())
        };
        Ok(())
    }

    fn send<'a>(&mut self, message: &'a [u8], handle: Option<&Handle>) -> Result<(), IpcError<'a>> {
        let remote_handle = match handle {
            None => 0,
            Some(handle_to_send) => {
                let remote_process_handle = self
                    .remote_process_handle
                    .as_ref()
                    .expect("cannot send handles before set_remote_process() is called on pipe")
                    .as_raw();
                let mut remote_handle: HANDLE = null_mut();
                let res = unsafe {
                    DuplicateHandle(
                        GetCurrentProcess(),
                        handle_to_send.as_raw() as HANDLE,
                        remote_process_handle as HANDLE,
                        &mut remote_handle as *mut HANDLE,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS,
                    )
                };
                if res == 0 {
                    return Err(IpcError::InternalOsOperationFailed {
                        description: "DuplicateHandle() failed",
                        os_code: unsafe { GetLastError() }.into(),
                    });
                }
                remote_handle as u64
            }
        };
        let remote_handle = remote_handle.to_be_bytes();
        let mut buf = Vec::from(message);
        buf.extend_from_slice(&remote_handle);
        let mut bytes_written: DWORD = 0;
        let res = unsafe {
            WriteFile(
                self.pipe_handle.as_raw() as HANDLE,
                buf.as_ptr() as *const _,
                buf.len() as u32,
                &mut bytes_written as *mut _,
                null_mut(),
            )
        };
        if res == 0 {
            return Err(IpcError::InternalOsOperationFailed {
                description: "WriteFile() failed",
                os_code: unsafe { GetLastError() }.into(),
            });
        }
        Ok(())
    }
}
