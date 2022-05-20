use crate::ipc::IPCError;
use crate::messagepipe::CrossPlatformMessagePipe;
use crate::os::errno;
use core::ptr::null_mut;
use iris_policy::{CrossPlatformHandle, Handle};
use libc::{c_int, c_void};
use core::convert::TryInto;

pub struct OSMessagePipe {
    fd: Handle,
}

impl CrossPlatformMessagePipe for OSMessagePipe {
    fn into_handle(self) -> Handle {
        self.fd
    }

    fn as_handle(&mut self) -> &mut Handle {
        &mut self.fd
    }

    fn from_handle(handle: Handle) -> Self {
        Self { fd: handle }
    }

    fn new() -> Result<(Self, Self), IPCError> {
        let mut socks: [c_int; 2] = [-1, -1];
        // This is safe as long as we don't return in the middle of this unsafe block. The file
        // descriptors are owned by this block and this block only
        let (fd0, fd1) = unsafe {
            let res = libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, socks.as_mut_ptr());
            if res < 0 {
                return Err(IPCError::OSError(errno().into()));
            }
            (
                Handle::new(socks[0] as u64).unwrap(),
                Handle::new(socks[1] as u64).unwrap(),
            )
        };
        Ok((Self { fd: fd0 }, Self { fd: fd1 }))
    }

    fn recv<'a>(&mut self, buffer: &'a mut [u8]) -> Result<&'a [u8], IPCError> {
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
            return Err(IPCError::OSError(errno().into()));
        }
        if (msg.msg_flags & libc::MSG_CTRUNC) != 0 {
            return Err(IPCError::AncillaryDataTruncated);
        }
        if (msg.msg_flags & libc::MSG_TRUNC) != 0 {
            return Err(IPCError::MessageTruncated);
        }
        Ok(&buffer[..res.try_into().unwrap()])
    }

    fn recv_with_handle<'a>(&mut self, buffer: &'a mut [u8]) -> Result<(&'a [u8], Option<Handle>), IPCError> {
        // This call is just a C arithmetic macro translated into rust, in practice it's safe (at least in this libc release)
        let cmsg_space = unsafe { libc::CMSG_SPACE(core::mem::size_of::<c_int>() as u32) } as usize;
        let (cbuf, buf) = buffer.split_at_mut(cmsg_space);
        let msg_iovec = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut c_void,
            iov_len: buf.len(),
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
            if res < 0 {
                // Safe to return here: if recvmsg() reports an error, no file descriptor can be received and leaked
                return Err(IPCError::OSError(errno().into()));
            }
            if msg.msg_controllen > 0 {
                let cmsghdr = libc::CMSG_FIRSTHDR(&msg as *const libc::msghdr);
                if cmsghdr.is_null() {
                    // This should not happen according to libc man pages. We possibly
                    // leak a file descriptor by returning here, but this is the best we can do.
                    return Err(IPCError::OSError(0));
                }
                let (clevel, ctype) = ((*cmsghdr).cmsg_level, (*cmsghdr).cmsg_type);
                if (clevel, ctype) != (libc::SOL_SOCKET, libc::SCM_RIGHTS) {
                    // We possibly leak a resource here, but the libc handed us something other than a file descriptor
                    return Err(IPCError::UnexpectedAncillaryData { clevel, ctype });
                }
                let fd = *(libc::CMSG_DATA(cmsghdr) as *const c_int);
                (res, Some(Handle::new(fd as u64).unwrap()))
            } else {
                (res, None)
            }
        };
        if (msg.msg_flags & libc::MSG_CTRUNC) != 0 {
            return Err(IPCError::AncillaryDataTruncated);
        }
        if (msg.msg_flags & libc::MSG_TRUNC) != 0 {
            return Err(IPCError::MessageTruncated);
        }
        Ok((&buf[..received_bytes.try_into().unwrap()], fd))
    }

    fn set_remote_process(&mut self, _unused_remote_pid: u64) -> Result<(), IPCError> {
        // no-op on Linux, having a handle to the target process is not necessary with Unix sockets
        Ok(())
    }

    fn send(&mut self, message: &[u8], handle: Option<&Handle>) -> Result<(), IPCError> {
        // This call is just a C arithmetic macro translated into rust, in practice it's safe (at least in this libc release)
        let cmsg_space = unsafe { libc::CMSG_SPACE(core::mem::size_of::<c_int>() as u32) } as usize;
        // FIXME: cmsg_space is computed at runtime from libc, but we cannot make dynamic
        // allocations here.
        let mut cbuf = [0u8; 128];
        if cmsg_space > cbuf.len() {
            return Err(IPCError::OSError(0));
        }
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
                msg_controllen: cmsg_space * (if handle.is_some() { 1 } else { 0 }),
                msg_flags: 0, // unused
            };
            if let Some(handle) = handle {
                let fd: c_int = handle.as_raw().try_into().unwrap();
                let cmsghdr = libc::CMSG_FIRSTHDR(&msg as *const _ as *mut libc::msghdr);
                (*cmsghdr).cmsg_level = libc::SOL_SOCKET;
                (*cmsghdr).cmsg_type = libc::SCM_RIGHTS;
                (*cmsghdr).cmsg_len = libc::CMSG_LEN(core::mem::size_of::<c_int>() as u32) as usize;
                *(libc::CMSG_DATA(cmsghdr) as *mut c_int) = fd;
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
            return Err(IPCError::OSError(errno().into()));
        }
        Ok(())
    }
}
