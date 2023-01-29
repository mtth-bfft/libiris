use iris_worker::lower_final_sandbox_privileges_asap;

/// Apply the final sandboxing restrictions, making the process ready to handle
/// untrusted data.
/// # Safety
/// This function is always safe to call, but may make your program crash if its
/// policy restricts resources or system calls needed by your program or one of
/// its dependencies, or if your program is otherwise not designed to run in a
/// sandbox.
#[no_mangle]
pub unsafe extern "C" fn iris_lower_final_sandbox_privileges_asap() {
    lower_final_sandbox_privileges_asap();
}
