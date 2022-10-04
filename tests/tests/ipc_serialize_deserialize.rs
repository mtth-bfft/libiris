use common::common_test_setup;
use iris_ipc::{CrossPlatformMessagePipe, IPCMessagePipe, IPCRequest, MessagePipe};

#[test]
fn ipc_serialize_deserialize() {
    common_test_setup();
    let (broker_pipe, worker_pipe) = MessagePipe::new().unwrap();
    let (mut broker_ipc, mut worker_ipc) = (
        IPCMessagePipe::new(broker_pipe),
        IPCMessagePipe::new(worker_pipe),
    );
    worker_ipc
        .send(&IPCRequest::LowerFinalSandboxPrivilegesAsap, None)
        .unwrap();
    assert_eq!(
        broker_ipc.recv(),
        Ok(Some(IPCRequest::LowerFinalSandboxPrivilegesAsap))
    );
}
