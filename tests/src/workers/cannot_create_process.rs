fn main()
{
    if cfg!(target_os="linux") {
        try_fork();
    } else if cfg!(target_os="windows") {
        try_createprocess();
    } else {
        notimplemented!();
    };
}

fn try_fork() {
    use libc;
    let res = libc::syscall(libc::SYS_fork);
}

