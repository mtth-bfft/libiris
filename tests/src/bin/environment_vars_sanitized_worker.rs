use common::common_test_setup;
use iris_worker::lower_final_sandbox_privileges_asap;

const FORBIDDEN_VARS: &[&str] = &["path", "home", "homepath", "onedrive"];

fn main() {
    lower_final_sandbox_privileges_asap();
    common_test_setup();
    for (var, val) in std::env::vars() {
        if FORBIDDEN_VARS.contains(&var.as_str().to_lowercase().as_str()) {
            panic!("{var} leaked in environment: {val}");
        }
    }
}
