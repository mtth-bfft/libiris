use iris_ipc::{CrossPlatformMessagePipe, IPCMessagePipe, IPCRequestV1, IPCVersion, MessagePipe, IPC_MESSAGE_MAX_SIZE};

#[test]
fn ipc_serialize_deserialize() {
    #[cfg(target_os = "windows")]
    let test_message = IPCRequestV1::NtCreateFile {
        desired_access: 0x01F0FF,
        path: "C:\\Windows\\System32\\notepad.exe".to_owned(),
        allocation_size: 0xCAFE0001,
        file_attributes: 0xCAFE0002,
        share_access: 0xCAFE0003,
        create_disposition: 0xCAFE0004,
        create_options: 0xCAFE0005,
        ea: vec![0xCA, 0xFE, 0x00, 0x06],
    };
    #[cfg(target_os = "linux")]
    let test_message = IPCRequestV1::Syscall {
        arch: 0xCAFE0001,
        nr: 0xCAFE00000000,
        arg1: 0xCAFE00000001,
        arg2: 0xCAFE00000002,
        arg3: 0xCAFE00000003,
        arg4: 0xCAFE00000004,
        arg5: 0xCAFE00000005,
        arg6: 0xCAFE00000006,
        ip: 0xCAFE00000007,
    };
    let mut buffer = [0u8; IPC_MESSAGE_MAX_SIZE];
    let (broker_pipe, worker_pipe) = MessagePipe::new().unwrap();
    let (mut broker_ipc, (mut worker_ipc, vers)) = (
        IPCMessagePipe::new_server(broker_pipe, IPCVersion::V1, &mut buffer).unwrap(),
        IPCMessagePipe::new_client(worker_pipe, &mut buffer).unwrap(),
    );
    assert_eq!(vers, IPCVersion::V1);
    worker_ipc.send(&test_message, None, &mut buffer).unwrap();
    let res: Option<IPCRequestV1> = broker_ipc
        .recv(&mut buffer)
        .expect("did not receive initial broker response");
    if res != Some(test_message) {
        panic!("unexpected message from broker: {:?}", res);
    }
}

#[test]
fn ipc_client_checks_version() {
    let future_nonexisting_version: IPCVersion = unsafe { std::mem::transmute(u8::MAX) };
    let (broker_pipe, worker_pipe) = MessagePipe::new().unwrap();
    let mut buffer = [0u8; IPC_MESSAGE_MAX_SIZE];
    let broker_ipc = IPCMessagePipe::new_server(broker_pipe, future_nonexisting_version, &mut buffer).unwrap();
    assert!(
        IPCMessagePipe::new_client(worker_pipe, &mut buffer).is_err(),
        "connecting to a server with unknown version should fail"
    );
    drop(broker_ipc);
}
