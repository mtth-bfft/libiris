use crate::error::IpcError;
use crate::ipc::IPC_MESSAGE_MAX_SIZE;
use crate::messagepipe::CrossPlatformMessagePipe;
use core::ptr::null_mut;
use iris_policy::{CrossPlatformHandle, Handle};
use libc::{c_int, c_void};
use std::convert::TryInto;
use std::io::Error;

pub struct OSMessagePipe {
    fd: Handle,
}

impl CrossPlatformMessagePipe for OSMessagePipe {
    fn into_handle(self) -> Handle {
        self.fd
    }

    fn from_handle(handle: Handle) -> Self {
        Self { fd: handle }
    }

    fn new() -> Result<(Self, Self), IpcError> {
        let mut socks: Vec<c_int> = vec![-1, 2];
        // This is safe as long as we don't return in the middle of this unsafe block. The file
        // descriptors are owned by this block and this block only
        let (fd0, fd1) = unsafe {
            let res = libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, socks.as_mut_ptr());
            if res < 0 {
                return Err(IpcError::InternalOsOperationFailed {
                    os_code: Error::last_os_error().raw_os_error().unwrap_or(0) as u64,
                    description: "socketpair()".to_owned(),
                });
            }
            (
                Handle::new(socks[0] as u64).unwrap(),
                Handle::new(socks[1] as u64).unwrap(),
            )
        };
        Ok((Self { fd: fd0 }, Self { fd: fd1 }))
    }

    fn recv(&mut self) -> Result<Vec<u8>, IpcError> {
        let mut buffer = vec![0u8; IPC_MESSAGE_MAX_SIZE.try_into().unwrap()];
        let msg_iovec = libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut c_void,
            iov_len: buffer.len(),
        };
        let mut msg = libc::msghdr {
            msg_name: null_mut(), // socket is already connected, no need for this
            msg_namelen: 0,
            msg_iov: &msg_iovec as *const libc::iovec as *mut libc::iovec, // mut is not used here, just required by API
            msg_iovlen: 1,
            msg_control: null_mut(),
            msg_controllen: 0,
            msg_flags: 0, // unused
        };
        let res = unsafe {
            libc::recvmsg(
                self.fd.as_raw().try_into().unwrap(),
                &mut msg as *mut libc::msghdr,
                libc::MSG_NOSIGNAL | libc::MSG_CMSG_CLOEXEC | libc::MSG_WAITALL,
            )
        };
        if res < 0 {
            return Err(IpcError::InternalOsOperationFailed {
                os_code: Error::last_os_error().raw_os_error().unwrap_or(0) as u64,
                description: "recvmsg()".to_owned(),
            });
        }
        buffer.truncate(res.try_into().unwrap());
        if (msg.msg_flags & libc::MSG_CTRUNC) != 0 {
            // truncated due to ancillary data
            return Err(IpcError::UnexpectedHandleWithPayload { payload: buffer });
        }
        if (msg.msg_flags & libc::MSG_TRUNC) != 0 {
            return Err(IpcError::PayloadTooBigToTransmit {
                truncated_payload: buffer,
            });
        }
        Ok(buffer)
    }

    fn recv_with_handle(&mut self) -> Result<(Vec<u8>, Option<Handle>), IpcError> {
        // This call is just a C arithmetic macro translated into rust, in practice it's safe (at least in this libc release)
        let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<c_int>() as u32) } as usize;
        let mut cbuf = vec![0u8; cmsg_space];
        let mut buffer = vec![0u8; IPC_MESSAGE_MAX_SIZE.try_into().unwrap()];
        let msg_iovec = libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut c_void,
            iov_len: buffer.len(),
        };
        let mut msg = libc::msghdr {
            msg_name: null_mut(), // socket is already connected, no need for this
            msg_namelen: 0,
            msg_iov: &msg_iovec as *const libc::iovec as *mut libc::iovec, // mut is not used here, just required by API
            msg_iovlen: 1,
            msg_control: cbuf.as_mut_ptr() as *mut c_void,
            msg_controllen: cmsg_space,
            msg_flags: 0, // unused
        };
        // This unsafe block encapsulates the libc call, and file descriptors received from libc. Safe because we
        // are the only owners of these file descriptors.
        let (received_bytes, fd) = unsafe {
            let res = libc::recvmsg(
                self.fd.as_raw().try_into().unwrap(),
                &mut msg as *mut libc::msghdr,
                libc::MSG_NOSIGNAL | libc::MSG_CMSG_CLOEXEC | libc::MSG_WAITALL,
            );
            match res.try_into() {
                Ok(received_bytes) => buffer.truncate(received_bytes),
                Err(_) => {
                    // Safe to return here: if recvmsg() reports an error, no file descriptor can be received and leaked
                    return Err(IpcError::InternalOsOperationFailed {
                        os_code: Error::last_os_error().raw_os_error().unwrap_or(0) as u64,
                        description: "recvmsg() failed".to_owned(),
                    });
                }
            }
            buffer.truncate(res.try_into().unwrap());
            // Iterate on ancillary payloads, if any (we allocated just enough space for one file descriptor, so we
            // should never be able to receive more at a time, but iterate and check to match the "safe" way of using
            // this API)
            let mut res = Ok((buffer, None));
            let mut cmsghdr = libc::CMSG_FIRSTHDR(&msg as *const libc::msghdr);
            while !cmsghdr.is_null() {
                let (clevel, ctype) = ((*cmsghdr).cmsg_level, (*cmsghdr).cmsg_type);
                if (clevel, ctype) != (libc::SOL_SOCKET, libc::SCM_RIGHTS) {
                    // We possibly leak a resource here, but the libc handed us something other than a file descriptor
                    res = Err(IpcError::InternalOsOperationFailed {
                        os_code: 0,
                        description: format!(
                            "recvmsg() returned unknown ancillary data level={clevel} type={ctype}"
                        ),
                    });
                    continue;
                }
                // CMSG_DATA() pointers are not aligned and require the use of an intermediary memcpy (see man cmsg)
                let mut aligned: c_int = -1;
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsghdr),
                    &mut aligned as *mut _ as *mut _,
                    std::mem::size_of_val(&aligned),
                );
                let fd = Handle::new(aligned as u64).unwrap();
                res = match res {
                    Ok((res, None)) => Ok((res, Some(fd))),
                    Ok((res, Some(_))) => Err(IpcError::TooManyHandlesWithPayload { payload: res }),
                    Err(e) => Err(e),
                };

                cmsghdr = libc::CMSG_NXTHDR(&msg as *const libc::msghdr, cmsghdr);
            }
            res?
        };
        if msg.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
            return Err(IpcError::PayloadTooBigToTransmit {
                truncated_payload: received_bytes,
            });
        }
        Ok((received_bytes, fd))
    }

    fn set_remote_process(&mut self, _unused_remote_pid: u64) -> Result<(), IpcError> {
        // no-op on Linux, having a handle to the target process is not necessary with Unix sockets
        Ok(())
    }

    fn send(&mut self, message: &[u8], handle: Option<&Handle>) -> Result<(), IpcError> {
        // This call is just a C arithmetic macro translated into rust, in practice it's safe (at least in this libc release)
        let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<c_int>() as u32) } as usize;
        let mut cbuf = vec![0u8; cmsg_space];
        // All these calls are libc calls (which are either C arithmetic macros translated into rust, in practice safe for this libc release),
        // or pointer dereferencing which are safe as long as the libc macros get the arithmetic right and as long as we keep the
        // `msg` variable alive and its contents valid
        let res = unsafe {
            let msg_iovec = libc::iovec {
                iov_base: message.as_ptr() as *mut c_void, // mut is not used here, just required because iovec is used by recvmsg too
                iov_len: message.len(),
            };
            let msg = libc::msghdr {
                msg_name: null_mut(), // socket is already connected, no need for this
                msg_namelen: 0,
                msg_iov: &msg_iovec as *const libc::iovec as *mut libc::iovec, // mut is not really used here either
                msg_iovlen: 1,
                msg_control: cbuf.as_mut_ptr() as *mut c_void,
                msg_controllen: cmsg_space * usize::from(handle.is_some()),
                msg_flags: 0, // unused
            };
            if let Some(handle) = handle {
                let fd: c_int = handle.as_raw().try_into().unwrap();
                let cmsghdr = libc::CMSG_FIRSTHDR(&msg as *const _ as *mut libc::msghdr);
                (*cmsghdr).cmsg_level = libc::SOL_SOCKET;
                (*cmsghdr).cmsg_type = libc::SCM_RIGHTS;
                (*cmsghdr).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<c_int>() as u32) as usize;
                std::ptr::copy_nonoverlapping(
                    &fd as *const c_int,
                    libc::CMSG_DATA(cmsghdr) as *mut c_int,
                    1,
                );
            }
            // This libc call is safe as long as we get the parameters right (fd is necessarily a file descriptor
            // owned by us, because only Self::new() can create us and that call makes sure self.fd is a handle to
            // our socket, and msg is under our control)
            libc::sendmsg(
                self.fd.as_raw().try_into().unwrap(),
                &msg as *const libc::msghdr,
                libc::MSG_NOSIGNAL,
            )
        };
        if res < 0 {
            return Err(IpcError::InternalOsOperationFailed {
                os_code: Error::last_os_error().raw_os_error().unwrap_or(0) as u64,
                description: "sendmsg() failed".to_owned(),
            });
        }
        Ok(())
    }
}
