use common::common_test_setup;
use iris_worker::lower_final_sandbox_privileges_asap;
use log::info;

#[cfg_attr(not(windows), link(name = "dummy_library"))]
#[cfg_attr(windows, link(name = "dummy_library.dll"))]
extern "C" {
    fn dynamically_loaded_library_function() -> i32;
}

fn main() {
    lower_final_sandbox_privileges_asap();
    common_test_setup();
    info!("Worker main reached");
    let res = unsafe { dynamically_loaded_library_function() };
    std::process::exit(res);
}
