use common::common_test_setup;
use iris_worker::lower_final_sandbox_privileges_asap;

fn main() {
    let seccomp_applied = std::sync::Arc::new(std::sync::Barrier::new(2));
    let ready_to_check_perms = seccomp_applied.clone();
    let thread = std::thread::spawn(move || {
        ready_to_check_perms.wait();
        match std::fs::read_to_string("/etc/hosts") {
            Err(e) => println!("{:?}", e),
            Ok(_) => {
                panic!("Opening file from pre-existing thread should have failed, succeeded");
            }
        }
        println!("Thread done");
    });
    lower_final_sandbox_privileges_asap();
    common_test_setup();
    seccomp_applied.wait();
    thread.join().expect("thread reported a failure");
    std::process::exit(0);
}
