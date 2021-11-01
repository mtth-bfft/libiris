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
        .send(&IPCRequestV1::Syscall {
            arch: 0xCAFE0001,
            nr: 0xCAFE00000000,
            arg1: 0xCAFE00000001,
            arg2: 0xCAFE00000002,
            arg3: 0xCAFE00000003,
            arg4: 0xCAFE00000004,
            arg5: 0xCAFE00000005,
            arg6: 0xCAFE00000006,
            ip: 0xCAFE00000007,
        }, None)
        .unwrap();
    let res: Option<IPCRequestV1> = broker_ipc.recv().expect("did not receive initial broker response");
    match res {
        Some(IPCRequestV1::Syscall { arch, nr, arg1, arg2, arg3, arg4, arg5, arg6, ip }) if arch == 0xCAFE0001 &&
            nr == 0xCAFE00000000 &&
            arg1 == 0xCAFE00000001 &&
            arg2 == 0xCAFE00000002 &&
            arg3 == 0xCAFE00000003 &&
            arg4 == 0xCAFE00000004 &&
            arg5 == 0xCAFE00000005 &&
            arg6 == 0xCAFE00000006 &&
            ip == 0xCAFE00000007 => (),
        other => panic!("unexpected message from broker: {:?}", other),
    }
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
