#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
use std::io::{self, Read};

fn main() {
    println!("OK_STDOUT");
    eprintln!("OK_STDERR");

    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .expect("Unable to read from stdin");
    assert_eq!(buffer, "OK_STDIN")
}
