use common::common_test_setup;

const FORBIDDEN_VARS: &[&str] = &["path", "home", "homepath", "onedrive"];

fn main() {
    common_test_setup();
    for (var, val) in std::env::vars() {
        if FORBIDDEN_VARS.contains(&var.as_str().to_lowercase().as_str()) {
            panic!("{var} leaked in environment: {val}");
        }
    }
}
