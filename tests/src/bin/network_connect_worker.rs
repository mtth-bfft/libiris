#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use common::common_test_setup;
use iris_worker::lower_final_sandbox_privileges_asap;
use log::info;

#[cfg(target_family = "unix")]
fn check(_ip: &str, _port: u16) {
    info!("Not implemented");
}

#[cfg(target_family = "windows")]
fn check(ip: &str, port: u16) {
    use std::ffi::CString;
    use winapi::shared::minwindef::MAKEWORD;
    use winapi::shared::ws2def::{AF_INET, IPPROTO_TCP, SOCKADDR_IN};
    use winapi::um::winsock2::{
        connect, htons, inet_addr, socket, WSAGetLastError, WSAStartup, INVALID_SOCKET,
        SOCKET_ERROR, SOCK_STREAM, WSADATA,
    };

    let mut wsa_data: WSADATA = unsafe { std::mem::zeroed() };
    let res = unsafe { WSAStartup(MAKEWORD(2, 2), &mut wsa_data as *mut _) };
    if res != 0 {
        panic!("WSAStartup failed with code {res}");
    }
    let sock = unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_TCP as i32) };
    if sock == INVALID_SOCKET {
        panic!("socket() failed with code {}", unsafe { WSAGetLastError() });
    }
    let mut addr: SOCKADDR_IN = unsafe { std::mem::zeroed() };
    addr.sin_family = AF_INET as u16;
    addr.sin_port = unsafe { htons(port) };
    let ip = CString::new(ip).unwrap();
    unsafe { *(addr.sin_addr.S_un.S_addr_mut()) = inet_addr(ip.as_ptr()) };

    use winapi::um::debugapi::DebugBreak;
    unsafe { DebugBreak() };

    let res = unsafe {
        connect(
            sock,
            &addr as *const _ as *const _,
            std::mem::size_of_val(&addr).try_into().unwrap(),
        )
    };
    if res == SOCKET_ERROR {
        panic!("connect() failed with code {}", unsafe {
            WSAGetLastError()
        });
    }
}

fn main() {
    lower_final_sandbox_privileges_asap();
    common_test_setup();

    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 3, "invalid argument count");
    let (ip, port) = (&args[1], args[2].parse::<u16>().expect("invalid port"));
    info!("Connecting to {} on port {} ...", ip, port);
    check(ip, port);
}
