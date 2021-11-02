use iris_worker::initialize_sandbox_as_soon_as_possible;

const FORBIDDEN_VARS: &[&str] = &["path", "home", "homepath", "onedrive"];

fn main() {
    initialize_sandbox_as_soon_as_possible();
    for (var, val) in std::env::vars() {
        if FORBIDDEN_VARS.contains(&var.as_str().to_lowercase().as_str()) {
            panic!("{} leaked in environment: {}", var, val);
        }
    }
}
