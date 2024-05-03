use crate::channel::{deserialize, serialize, CrossPlatformIpcChannel};
use crate::error::IpcError;
use crate::stackbuffer::StackBuffer;
use crate::IPC_MESSAGE_MAX_SIZE;
use crate::{os::Handle, CrossPlatformHandle};
use core::convert::TryInto;
use core::fmt::Write;
use core::ptr::null_mut;
use log::debug;
use serde::{Deserialize, Serialize};
use winapi::shared::minwindef::DWORD;
use winapi::shared::winerror::{ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_PIPE_CONNECTED};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{CreateFileA, ReadFile, WriteFile, OPEN_EXISTING};
use winapi::um::handleapi::{DuplicateHandle, INVALID_HANDLE_VALUE};
use winapi::um::namedpipeapi::{ConnectNamedPipe, SetNamedPipeHandleState};
use winapi::um::processthreadsapi::{GetCurrentProcess, GetCurrentProcessId, OpenProcess};
use winapi::um::winbase::CreateNamedPipeA;
use winapi::um::winbase::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX, PIPE_READMODE_MESSAGE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE,
};
use winapi::um::winnt::{
    DUPLICATE_SAME_ACCESS, FILE_READ_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, HANDLE,
    PROCESS_DUP_HANDLE,
};

pub struct IpcChannel {
    pipe_handle: Handle,
    remote_process_handle: Option<Handle>,
}

impl CrossPlatformIpcChannel for IpcChannel {
    fn new() -> Result<(Self, Self), IpcError<'static>> {
        let pid: DWORD = unsafe { GetCurrentProcessId() };
        let mut pipe_id = 0;
        loop {
            let mut pipe_path = StackBuffer::<100>::default();
            pipe_id += 1;
            if write!(&mut pipe_path, "\\\\.\\pipe\\ipc-{}-{}\x00", pid, pipe_id).is_err() {
                return Err(IpcError::InternalOsOperationFailed {
                    description: "unable to format pipe path",
                    os_code: 0,
                });
            }
            let handle1 = unsafe {
                let res = CreateNamedPipeA(
                    pipe_path.as_bytes().as_ptr() as *const _,
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
                    2,
                    IPC_MESSAGE_MAX_SIZE as u32,
                    IPC_MESSAGE_MAX_SIZE as u32,
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
                Handle::from_raw(res as u64).unwrap()
            };
            let handle2 = unsafe {
                let res = CreateFileA(
                    pipe_path.as_bytes().as_ptr() as *const _,
                    FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES,
                    0,
                    null_mut(),
                    OPEN_EXISTING,
                    0,
                    null_mut(),
                );
                // FILE_WRITE_ATTRIBUTES is required to set the pipe mode to "messages" afterwards.
                if res == INVALID_HANDLE_VALUE {
                    // No handle was returned, it is safe to just return
                    // as it will also destroy handle1 created just above
                    return Err(IpcError::InternalOsOperationFailed {
                        description: "CreateFile() failed",
                        os_code: GetLastError().into(),
                    });
                }
                Handle::from_raw(res as u64).unwrap()
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
            debug!(
                "Using ipc pipe {}",
                core::str::from_utf8(pipe_path.as_bytes()).unwrap_or("?")
            );
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

    fn into_handle(self) -> Handle {
        self.pipe_handle
    }

    fn from_handle(handle: Handle) -> Self {
        Self {
            pipe_handle: handle,
            remote_process_handle: None,
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
            Some(Handle::from_raw(res as u64).unwrap())
        };
        Ok(())
    }

    fn send<'a, T: Serialize>(
        &mut self,
        msg: &'a T,
        handle: Option<&'a Handle>,
        buffer: &'a mut [u8],
    ) -> Result<(), IpcError<'a>> {
        let remote_handle = if let Some(local_handle) = handle {
            // TODO: see if GetNamedPipeClientProcessId() can't replace set_remote_process() altogether
            let remote_process_handle = self
                .remote_process_handle
                .as_ref()
                .expect("cannot send handles before set_remote_process() is called on pipe")
                .as_raw();
            let mut remote_handle: HANDLE = null_mut();
            let res = unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    local_handle.as_raw() as HANDLE,
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
            Some(remote_handle as u64)
        } else {
            None
        };
        let wrapped_msg = (msg, remote_handle);
        let slice = serialize(&wrapped_msg, buffer)?;
        let mut bytes_written: DWORD = 0;
        let res = unsafe {
            WriteFile(
                self.pipe_handle.as_raw() as HANDLE,
                slice.as_ptr() as *const _,
                slice.len() as u32,
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

    fn recv<'de, T: Deserialize<'de>>(
        &mut self,
        buffer: &'de mut [u8],
    ) -> Result<Option<(T, Option<Handle>)>, IpcError<'de>> {
        let mut read_bytes: DWORD = 0;
        let res = unsafe {
            ReadFile(
                self.pipe_handle.as_raw() as HANDLE,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut read_bytes as *mut _,
                null_mut(),
            )
        };
        if res == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_BROKEN_PIPE {
                return Ok(None); // read of length 0 <=> end of file
            }
            return Err(IpcError::InternalOsOperationFailed {
                description: "ReadFile() failed",
                os_code: err.into(),
            });
        }
        let (msg, raw_handle): (T, Option<u64>) = deserialize(&buffer[0..(read_bytes as usize)])?;
        // FIXME: only workers should accept incoming handles. Otherwise a worker
        // could send its broker "hey I just sent you handle X" and make the
        // broker do something with one of its own handles, expecting it to be
        // a new handle from its worker.
        let handle = if let Some(raw_handle) = raw_handle {
            Some(unsafe { Handle::from_raw(raw_handle) }.map_err(IpcError::from)?)
        } else {
            None
        };
        Ok(Some((msg, handle)))
    }
}
