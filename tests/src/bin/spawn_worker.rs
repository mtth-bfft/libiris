use common::common_test_setup;
use iris_worker::lower_final_sandbox_privileges_asap;
use log::info;

fn main() {
    lower_final_sandbox_privileges_asap();
    common_test_setup();
    info!("Worker main reached");
    std::process::exit(42);
}
