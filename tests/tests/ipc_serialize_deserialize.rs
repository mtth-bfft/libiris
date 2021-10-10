use iris_ipc::{CrossPlatformMessagePipe, IPCMessagePipe, IPCRequestV1, IPCVersion, MessagePipe};

#[test]
fn ipc_serialize_deserialize() {
    let (broker_pipe, worker_pipe) = MessagePipe::new().unwrap();
    let (mut broker_ipc, (mut worker_ipc, vers)) = (
        IPCMessagePipe::new_server(broker_pipe, IPCVersion::V1).unwrap(),
        IPCMessagePipe::new_client(worker_pipe).unwrap(),
    );
    assert_eq!(vers, IPCVersion::V1);
    worker_ipc
        .send(&IPCRequestV1::LowerFinalSandboxPrivilegesAsap, None)
        .unwrap();
    assert_eq!(
        broker_ipc.recv(),
        Ok(Some(IPCRequestV1::LowerFinalSandboxPrivilegesAsap))
    );
}

#[test]
fn ipc_client_checks_version() {
    let future_nonexisting_version: IPCVersion = unsafe { std::mem::transmute(u8::MAX) };
    let (broker_pipe, worker_pipe) = MessagePipe::new().unwrap();
    let broker_ipc = IPCMessagePipe::new_server(broker_pipe, future_nonexisting_version).unwrap();
    assert!(
        IPCMessagePipe::new_client(worker_pipe).is_err(),
        "connecting to a server with unknown version should fail"
    );
    drop(broker_ipc);
}
