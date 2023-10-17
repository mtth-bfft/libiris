use std::env;
use cmake;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    cmake::build(".");
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=dylib=libdummy");
    println!("cargo:rerun-if-changed=src/libdummy.c");
    println!("cargo:rustc-env=DLL_DIR={}", out_dir)
}
