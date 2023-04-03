use common::common_test_setup;
use iris_worker::lower_final_sandbox_privileges_asap;

fn main() {
    lower_final_sandbox_privileges_asap();
    common_test_setup();
    loop {
        let wakeup_interval = std::time::Duration::from_millis(1000);
        std::thread::sleep(wakeup_interval);
    }
}
