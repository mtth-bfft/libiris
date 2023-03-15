#[cfg(target_os = "linux")]
fn main() {
    use common::common_test_setup;
    use iris_worker::lower_final_sandbox_privileges_asap;
    use log::info;

    common_test_setup();
    lower_final_sandbox_privileges_asap();
    info!("Filter loaded, about to run unsupported syscall");
    let res = unsafe { libc::syscall(999, 1usize, 2usize, 3usize, 4usize, 5usize, 6usize) };
    assert_eq!(res, -1, "unsupported syscall should have failed");
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    assert_eq!(
        errno,
        libc::ENOSYS,
        "unsupported syscall failed with the wrong errno"
    );
}

#[cfg(not(target_os = "linux"))]
fn main() {}
