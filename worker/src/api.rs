use crate::late_mitigations::apply_late_mitigations;
use core::ptr::null;
use iris_ipc::{
    CrossPlatformMessagePipe, IPCMessagePipe, IPCResponseV1, IPCVersion, MessagePipe,
    IPC_HANDLE_ENV_NAME, IPC_MESSAGE_MAX_SIZE
};
use iris_policy::{CrossPlatformHandle, Handle};
use std::sync::{Mutex, MutexGuard};

// TODO: use a thread_local!{} pipe, and a global mutex-protected pipe to request new thread-specific ones
// OR: create a global pool of threads which wait on a global lock-free queue
// AND/OR: make the ipc pipe multiplexed by adding random transaction IDs
static mut IPC_PIPE_SINGLETON: *const Mutex<IPCMessagePipe> = null();
pub(crate) fn get_ipc_pipe() -> MutexGuard<'static, IPCMessagePipe> {
    unsafe { (*IPC_PIPE_SINGLETON).lock().unwrap() }
}

pub fn initialize_sandbox_as_soon_as_possible() {
    let handle = std::env::var(IPC_HANDLE_ENV_NAME)
        .expect("missing environment variable containing the IPC handle");
    std::env::remove_var(IPC_HANDLE_ENV_NAME);
    let handle = handle
        .parse::<u64>()
        .expect("invalid IPC handle environment variable contents");
    // This unsafe block takes possession of the handle, which is safe since we are the only ones aware
    // of this environment variable, and we erase it as soon as it is used.
    let handle = unsafe { Handle::new(handle).expect("invalid IPC handle environment variable") };
    let pipe = MessagePipe::from_handle(handle);
    let mut buf = [0u8; IPC_MESSAGE_MAX_SIZE];
    let (ipc, version) =
        IPCMessagePipe::new_client(pipe, &mut buf).expect("unable to open IPC channel to broker");
    if version != IPCVersion::V1 {
        panic!("unsupported IPC server version {:?}", version);
    }
    // Initialization of globals. This is safe as long as we are only called once
    unsafe {
        // Store the IPC pipe to handle all future syscall requests
        IPC_PIPE_SINGLETON = Box::leak(Box::new(Mutex::new(ipc))) as *const _;
    }

    let mut ipc = get_ipc_pipe();
    let msg = ipc
        .recv(&mut buf)
        .expect("unable to read worker late mitigations from broker");
    let resp = if let Some(IPCResponseV1::LateMitigations { .. }) = &msg {
        apply_late_mitigations(&msg.unwrap())
    } else {
        panic!("unexpected initial message received from broker: {:?}", msg);
    };
    ipc.send(&resp, None, &mut buf)
        .expect("unable to report late mitigation status to broker");
}
