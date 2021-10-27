use iris_worker::initialize_sandbox_as_soon_as_possible;

fn main() {
    initialize_sandbox_as_soon_as_possible();
    println!(" [+] Worker main reached");
    std::process::exit(42);
}
