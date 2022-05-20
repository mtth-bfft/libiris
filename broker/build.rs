
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if let Ok(_) = std::env::var("DEP_SECCOMP_VERSION") {
        println!("cargo:rustc-cfg=seccomp");
        if std::env::var("DEP_SECCOMP_NOTIFY") == Ok("true".to_owned()) {
            println!("cargo:rustc-cfg=seccomp_notify");
        }
    }
}
