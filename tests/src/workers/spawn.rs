use iris_worker::lower_final_sandbox_privileges_asap;

fn main() {
    lower_final_sandbox_privileges_asap();
    println!(" [+] Worker main reached");
    std::process::exit(42);
}
