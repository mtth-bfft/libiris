use common::common_test_setup;
use iris_worker::lower_final_sandbox_privileges_asap;

fn main() {
    lower_final_sandbox_privileges_asap();
    common_test_setup();
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 2);
    let path = &args[1];
    std::fs::read_to_string(path).unwrap(); // should not generate a callback call
    assert!(std::fs::write(path, "NOPE").is_err()); // should generate a callback call
}
