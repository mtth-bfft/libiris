use iris_worker::initialize_sandbox_as_soon_as_possible;

fn main() {
    initialize_sandbox_as_soon_as_possible();
    std::thread::sleep(std::time::Duration::new(2, 0));
}
