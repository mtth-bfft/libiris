mod channel;
mod handle;

pub use channel::IpcChannel;
pub use handle::Handle;

// Arbitrary placeholder value used by the broker when generating Seccomp filters
// on Linux, and replaced by actual addresses by the worker. We could inspect the
// worker's memory from the broker to resolve addresses directly, but this constant
// is way simpler. Put here since it is a form of "communication" between both
// parts, and it needs to be kept in sync between both.
pub const IPC_SECCOMP_CALL_SITE_PLACEHOLDER: u64 = 0xCAFECAFEC0DEC0DE;

pub(crate) fn errno() -> libc::c_int {
    unsafe { *(libc::__errno_location()) }
}
