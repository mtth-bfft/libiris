#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
use common::common_test_setup;
use iris_worker::lower_final_sandbox_privileges_asap;
use std::io::{self, Read};

fn main() {
    lower_final_sandbox_privileges_asap();
    common_test_setup();

    println!("OK_STDOUT");
    eprintln!("OK_STDERR");

    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .expect("Unable to read from stdin");
    assert_eq!(buffer, "OK_STDIN")
}
