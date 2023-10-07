use crate::error::IpcError;
use crate::messagepipe::CrossPlatformMessagePipe;
use crate::os::errno;
use core::ptr::null_mut;
use iris_policy::CrossPlatformHandle;
use iris_policy::os::Handle;
use libc::{c_int, c_void};

// This call is just a C arithmetic macro translated into rust, in practice it's safe (at least in this libc release)
const CMSG_SIZE: usize = unsafe { libc::CMSG_SPACE(core::mem::size_of::<c_int>() as u32) } as usize;

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

    fn new() -> Result<(Self, Self), IpcError<'static>> {
        let mut socks: [c_int; 2] = [-1, -1];
        // This is safe as long as we don't return in the middle of this unsafe block. The file
        // descriptors are owned by this block and this block only
        let (fd0, fd1) = unsafe {
            let res = libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, socks.as_mut_ptr());
            if res < 0 {
                return Err(IpcError::InternalOsOperationFailed {
                    os_code: errno() as u64,
                    description: "socketpair() failed",
                });
            }
            (
                Handle::from_raw(socks[0] as u64).unwrap(),
                Handle::from_raw(socks[1] as u64).unwrap(),
            )
        };
        Ok((Self { fd: fd0 }, Self { fd: fd1 }))
    }

    fn recv<'a>(&mut self, buffer: &'a mut [u8]) -> Result<Option<&'a mut [u8]>, IpcError<'a>> {
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
        let received_bytes = match res {
            0 => return Ok(None),
            n if n < 0 => {
                return Err(IpcError::InternalOsOperationFailed {
                    os_code: errno() as u64,
                    description: "recvmsg() failed",
                })
            }
            n => n as usize,
        };
        let buffer = &mut buffer[0..received_bytes];
        if (msg.msg_flags & libc::MSG_CTRUNC) != 0 {
            // truncated due to ancillary data
            return Err(IpcError::UnexpectedHandleWithPayload { payload: buffer });
        }
        if (msg.msg_flags & libc::MSG_TRUNC) != 0 {
            return Err(IpcError::PayloadTooBigToTransmit {
                truncated_payload: buffer,
            });
        }
        Ok(Some(buffer))
    }

    fn recv_with_handle<'a>(
        &mut self,
        buffer: &'a mut [u8],
    ) -> Result<Option<(&'a mut [u8], Option<Handle>)>, IpcError<'a>> {
        let mut cbuf = [0u8; CMSG_SIZE];
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
            msg_controllen: CMSG_SIZE,
            msg_flags: 0, // unused
        };
        // This unsafe block encapsulates the libc call and handling of file descriptors received from libc
        // which we might leak unintentionally
        let (read_bytes, handle) = unsafe {
            let res = libc::recvmsg(
                self.fd.as_raw().try_into().unwrap(),
                &mut msg as *mut libc::msghdr,
                libc::MSG_NOSIGNAL | libc::MSG_CMSG_CLOEXEC | libc::MSG_WAITALL,
            );
            if res < 0 {
                return Err(IpcError::InternalOsOperationFailed {
                    os_code: errno() as u64,
                    description: "recvmsg() failed",
                });
            }
            // Iterate on ancillary payloads, if any (we allocated just enough space for one
            // file descriptor, so we should never be able to receive more at a time, but
            // iterate and check to match the documented way of using this API)
            let mut handle = Ok(None);
            let mut cmsghdr = libc::CMSG_FIRSTHDR(&msg as *const libc::msghdr);
            while !cmsghdr.is_null() {
                let (clevel, ctype) = ((*cmsghdr).cmsg_level, (*cmsghdr).cmsg_type);
                if (clevel, ctype) != (libc::SOL_SOCKET, libc::SCM_RIGHTS) {
                    // The libc handed us something unexpected other than a file descriptor,
                    // quit with an error in case it could cause a resource leak.
                    handle = Err(IpcError::InternalOsOperationFailed {
                        os_code: 0,
                        description: "recvmsg() returned unknown ancillary data level or type",
                    });
                    break;
                }
                // CMSG_DATA() pointers are not aligned and require the use of an intermediary memcpy (see man cmsg)
                let mut aligned: c_int = -1;
                core::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsghdr),
                    &mut aligned as *mut _ as *mut _,
                    std::mem::size_of_val(&aligned),
                );
                handle = match Handle::from_raw(aligned as u64) {
                    Ok(h) => Ok(Some(h)),
                    Err(e) => Err(IpcError::from(e)),
                };
                cmsghdr = libc::CMSG_NXTHDR(&msg as *const libc::msghdr, cmsghdr);
            }
            (res as usize, handle?)
        };
        if msg.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
            Err(IpcError::PayloadTooBigToTransmit {
                truncated_payload: &buffer[0..read_bytes],
            })
        } else if read_bytes == 0 {
            Ok(None)
        } else {
            Ok(Some((&mut buffer[0..read_bytes], handle)))
        }
    }

    fn set_remote_process(&mut self, _unused_remote_pid: u64) -> Result<(), IpcError<'static>> {
        // no-op on Linux, having a handle to the target process is not necessary with Unix sockets
        Ok(())
    }

    fn send<'a>(
        &mut self,
        message: &'a [u8],
        handle: Option<&'a Handle>,
    ) -> Result<(), IpcError<'a>> {
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
                os_code: errno() as u64,
                description: "sendmsg() failed",
            });
        }
        Ok(())
    }
}
