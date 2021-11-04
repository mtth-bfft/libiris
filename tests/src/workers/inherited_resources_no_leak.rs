use iris_worker::initialize_sandbox_as_soon_as_possible;

fn main() {
    initialize_sandbox_as_soon_as_possible();
    // FIXME: replace with an infinite loop when a worker.terminate()
    // feature is ready
    std::thread::sleep(std::time::Duration::new(2, 0));
}
