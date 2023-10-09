use crate::channel::{CrossPlatformIpcChannel, serialize, deserialize};
use crate::error::IpcError;
use crate::CrossPlatformHandle;
use core::ptr::null_mut;
use crate::os::{Handle, errno};
use libc::{c_int, c_void};
use serde::{Serialize, Deserialize};

// This call is just a C arithmetic macro translated into rust, in practice it's safe (at least in this libc release)
const CMSG_SIZE: usize = unsafe { libc::CMSG_SPACE(core::mem::size_of::<c_int>() as u32) } as usize;

pub struct IpcChannel {
    fd: Handle,
}

impl CrossPlatformIpcChannel for IpcChannel {
    fn new() -> Result<(Self, Self), IpcError<'static>> {
        // Safety: we must not return in the middle of this block. The file
        // descriptors are owned by this block and this block only.
        // If socketpair() fails, no file descriptors are returned, so no
        // resource is leaked.
        let (fd0, fd1) = unsafe {
            let mut socks: [c_int; 2] = [-1, -1];
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

    fn into_handle(self) -> Handle {
        self.fd
    }

    fn from_handle(handle: Handle) -> Self {
        Self { fd: handle }
    }

    fn set_remote_process(&mut self, _pid: u64) -> Result<(), IpcError<'static>> {
        // no-op on Linux, no need to know the target PID to send a file descriptor.
        Ok(())
    }

    fn send<'a, T: Serialize>(
        &mut self,
        msg: &'a T,
        handle: Option<&'a Handle>,
        buffer: &'a mut [u8],
    ) -> Result<(), IpcError<'a>> {
        let slice = serialize(msg, buffer)?;
        let msg_iovec = libc::iovec {
            // mut is not used here, just required because iovec is used by recvmsg too
            iov_base: slice.as_ptr() as *mut c_void,
            iov_len: slice.len(),
        };
        let mut cbuf = [0u8; CMSG_SIZE];
        let mut msg = libc::msghdr {
            msg_name: null_mut(), // socket is already connected, no need for this
            msg_namelen: 0,
            // mut is not actually used here either, just because iovec is used by recvmsg too
            msg_iov: &msg_iovec as *const libc::iovec as *mut libc::iovec,
            msg_iovlen: 1,
            msg_control: cbuf.as_mut_ptr() as *mut c_void,
            msg_controllen: if handle.is_some() { CMSG_SIZE } else { 0 },
            msg_flags: 0, // unused
        };
        // Safety: pointers in the iovec{} must point to valid buffers of the indicated length
        // up until the sendmsg() call, pointers into the msghdr must not be directly assigned
        // (they might not be aligned).
        let res = unsafe {
            if let Some(handle) = handle {
                let fd = handle.as_raw() as c_int;
                let cmsghdr = libc::CMSG_FIRSTHDR(&mut msg as *mut libc::msghdr);
                let (clevel, ctype, clen) = (libc::SOL_SOCKET, libc::SCM_RIGHTS, CMSG_SIZE);
                core::ptr::copy_nonoverlapping(
                    &clevel as *const c_int,
                    &mut (*cmsghdr).cmsg_level as *mut c_int,
                    1
                );
                core::ptr::copy_nonoverlapping(
                    &ctype as *const c_int,
                    &mut (*cmsghdr).cmsg_type as *mut c_int,
                    1
                );
                core::ptr::copy_nonoverlapping(
                    &clen as *const usize,
                    &mut (*cmsghdr).cmsg_len as *mut libc::size_t,
                    1
                );
                core::ptr::copy_nonoverlapping(
                    &fd as *const c_int,
                    libc::CMSG_DATA(cmsghdr) as *mut c_int,
                    1,
                );
            }
            libc::sendmsg(
                self.fd.as_raw() as c_int,
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

    fn recv<'de, T: Deserialize<'de>>(
        &mut self,
        buffer: &'de mut [u8],
    ) -> Result<Option<(T, Option<Handle>)>, IpcError<'de>> {
        let msg_iovec = libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut c_void,
            iov_len: buffer.len(),
        };
        let mut cbuf = [0u8; CMSG_SIZE];
        let mut msg = libc::msghdr {
            msg_name: null_mut(), // socket is already connected, no need for this
            msg_namelen: 0,
            msg_iov: &msg_iovec as *const libc::iovec as *mut libc::iovec, // mut is not used here
            msg_iovlen: 1,
            msg_control: cbuf.as_mut_ptr() as *mut c_void,
            msg_controllen: cbuf.len(),
            msg_flags: 0, // unused
        };
        // Safety: pointers in the iovec{} must point to valid buffers of the indicated length
        // up until the recvmsg() call. There must be no early return that leaks a file descriptor
        // received. Any received cmsg header and payload pointers must not be dereferenced directly:
        // they may not be aligned within the reception buffer.
        let (read_bytes, handle) = unsafe {
            let res = libc::recvmsg(
                self.fd.as_raw() as c_int,
                &mut msg as *mut libc::msghdr,
                libc::MSG_NOSIGNAL | libc::MSG_CMSG_CLOEXEC | libc::MSG_WAITALL,
            );
            if res < 0 { // if recvmsg() failed altogether, we can return without leaking a fd
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
                let mut clevel: c_int = -1;
                let mut ctype: c_int = -1;
                core::ptr::copy_nonoverlapping(
                    &(*cmsghdr).cmsg_level as *const c_int,
                    &mut clevel as *mut c_int,
                    1,
                );
                core::ptr::copy_nonoverlapping(
                    &(*cmsghdr).cmsg_type as *const c_int,
                    &mut ctype as *mut c_int,
                    1,
                );
                if (clevel, ctype) != (libc::SOL_SOCKET, libc::SCM_RIGHTS) {
                    // The libc handed us something unexpected other than a file descriptor,
                    // quit with an error in case it could cause a resource leak.
                    handle = Err(IpcError::InternalOsOperationFailed {
                        os_code: 0,
                        description: "recvmsg() returned unknown ancillary data level or type",
                    });
                }
                let mut fd: c_int = -1;
                core::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsghdr),
                    &mut fd as *mut c_int as *mut libc::c_uchar,
                    core::mem::size_of_val(&fd),
                );
                match Handle::from_raw(fd as u64) {
                    Ok(h) => {
                        if handle.is_ok() { // don't overwrite a prior error
                            handle = Ok(Some(h));
                        }
                    },
                    Err(e) => {
                        handle = Err(IpcError::from(e));
                    },
                };
                cmsghdr = libc::CMSG_NXTHDR(&msg as *const libc::msghdr, cmsghdr);
            }
            (res as usize, handle?)
        };
        // All error conditions below will implictly close any handle receveived,
        // no leak at this point once outside the unsafe{} block.
        if msg.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
            return Err(IpcError::PayloadTooBigToTransmit {
                truncated_payload: &buffer[0..read_bytes],
            });
        } else if read_bytes == 0 {
            return Ok(None);
        }
        let msg = deserialize(&buffer[0..read_bytes])?;
        Ok(Some((msg, handle)))
    }
}
