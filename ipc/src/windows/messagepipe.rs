use crate::ipc::IPC_MESSAGE_MAX_SIZE;
use crate::messagepipe::CrossPlatformMessagePipe;
use core::ptr::null_mut;
use iris_policy::{CrossPlatformHandle, Handle};
use std::convert::TryInto;
use std::ffi::CString;
use winapi::shared::minwindef::DWORD;
use winapi::shared::winerror::ERROR_BROKEN_PIPE;
use winapi::shared::winerror::ERROR_PIPE_CONNECTED;
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

const PIPE_BUFFER_SIZE: u32 = (std::mem::size_of::<u64>() as u32) + IPC_MESSAGE_MAX_SIZE;
const PIPE_FOOTER_SIZE: usize = std::mem::size_of::<u64>();
const PIPE_MAX_INSTANCES_PER_PROCESS: usize = 1000;

pub struct OSMessagePipe {
    pipe_handle: Handle,
    remote_process_handle: Option<Handle>,
}

impl CrossPlatformMessagePipe for OSMessagePipe {
    fn into_handle(self) -> Handle {
        self.pipe_handle
    }

    fn as_handle(&mut self) -> &mut Handle {
        &mut self.pipe_handle
    }

    fn from_handle(handle: Handle) -> Self {
        Self {
            pipe_handle: handle,
            remote_process_handle: None,
        }
    }

    fn new() -> Result<(Self, Self), String> {
        for pipe_id in 1..PIPE_MAX_INSTANCES_PER_PROCESS {
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
                if res == null_mut() || res == INVALID_HANDLE_VALUE {
                    continue;
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
                    return Err(format!(
                        "CreateFile({:?}) failed with code {}",
                        name_nul,
                        GetLastError()
                    ));
                }
                Handle::new(res as u64).unwrap()
            };
            let res = unsafe { ConnectNamedPipe((&handle1).as_raw() as HANDLE, null_mut()) };
            if res == 0 {
                let err = unsafe { GetLastError() };
                if err != ERROR_PIPE_CONNECTED {
                    return Err(format!("ConnectNamedPipe() failed with code {}", err));
                }
            }
            println!("Using ipc pipe {}", name_nul.to_string_lossy());
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
                return Err(format!(
                    "SetNamedPipeHandleState() failed with code {}",
                    unsafe { GetLastError() }
                ));
            }
            return Ok((Self::from_handle(handle1), Self::from_handle(handle2)));
        }
        return Err(format!("Unable to create a named pipe: error {}", unsafe {
            GetLastError()
        }));
    }

    fn recv(&mut self) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; PIPE_BUFFER_SIZE.try_into().unwrap()];
        let mut bytes_read: DWORD = 0;
        let res = unsafe {
            ReadFile(
                self.pipe_handle.as_raw() as HANDLE,
                buf.as_mut_ptr() as *mut _,
                buf.len().try_into().unwrap(),
                &mut bytes_read as *mut _,
                null_mut(),
            )
        };
        let bytes_read: usize = bytes_read.try_into().unwrap_or(0);
        if res == 0 || bytes_read < PIPE_FOOTER_SIZE {
            let err = unsafe { GetLastError() };
            if res == 0 && err == ERROR_BROKEN_PIPE {
                buf.truncate(0);
                return Ok(buf); // read of length 0 <=> end of file
            }
            return Err(format!(
                "ReadFile() returned {} bytes and failed with code {}",
                bytes_read,
                unsafe { GetLastError() }
            ));
        }
        buf.truncate(bytes_read - PIPE_FOOTER_SIZE);
        Ok(buf)
    }

    fn recv_with_handle(&mut self) -> Result<(Vec<u8>, Option<Handle>), String> {
        let mut buf = vec![0u8; PIPE_BUFFER_SIZE.try_into().unwrap()];
        let mut bytes_read: DWORD = 0;
        let handle = unsafe {
            let res = ReadFile(
                self.pipe_handle.as_raw() as HANDLE,
                buf.as_mut_ptr() as *mut _,
                buf.len().try_into().unwrap(),
                &mut bytes_read as *mut _,
                null_mut(),
            );
            let bytes_read = bytes_read as usize;
            if res == 0 || bytes_read < PIPE_FOOTER_SIZE {
                let err = GetLastError();
                if res == 0 && err == ERROR_BROKEN_PIPE {
                    buf.truncate(0);
                    return Ok((buf, None)); // read of length 0 <=> end of file
                }
                return Err(format!("ReadFile() failed with code {}", err));
            }
            let handle = match u64::from_be_bytes(
                buf[bytes_read - PIPE_FOOTER_SIZE..bytes_read]
                    .try_into()
                    .unwrap(),
            ) {
                n if n > 0 => Some(Handle::new(n).unwrap()),
                _ => None,
            };
            buf.truncate(bytes_read - PIPE_FOOTER_SIZE);
            handle
        };
        Ok((buf, handle))
    }

    fn set_remote_process(&mut self, remote_pid: u64) -> Result<(), String> {
        let remote_pid: u32 = match remote_pid.try_into() {
            Ok(n) => n,
            Err(_) => return Err(format!("Invalid PID: {}", remote_pid)),
        };
        self.remote_process_handle = unsafe {
            let res = OpenProcess(PROCESS_DUP_HANDLE, 0, remote_pid);
            if res == null_mut() {
                // It is safe to return here, OpenProcess() failed to open any handle
                return Err(format!("Cannot get handle to pipe client process: OpenProcess({}) failed with error {}", remote_pid, GetLastError()));
            }
            Some(Handle::new(res as u64).unwrap())
        };
        Ok(())
    }

    fn send(&mut self, message: &[u8], handle: Option<&Handle>) -> Result<(), String> {
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
                    return Err(format!("DuplicateHandle() failed with code {}", unsafe {
                        GetLastError()
                    }));
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
            return Err(format!("WriteFile() failed with code {}", unsafe {
                GetLastError()
            }));
        }
        Ok(())
    }
}
