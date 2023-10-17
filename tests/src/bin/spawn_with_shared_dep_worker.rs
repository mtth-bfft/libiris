use common::common_test_setup;
use iris_worker::lower_final_sandbox_privileges_asap;
use log::info;

extern { fn foo() -> i32; }

fn main() {
    lower_final_sandbox_privileges_asap();
    common_test_setup();
    info!("Worker main reached");
    let code = unsafe { foo() };
    std::process::exit(code);
}
