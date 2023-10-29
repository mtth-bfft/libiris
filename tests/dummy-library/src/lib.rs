// Exported function to have a .dll/.so to test whether our workers can
// successfully load a dynamic library during their initialization (e.g.
// does their IPC initialize early enough) and after (e.g. does their
// policy apply correctly when loading libraries)
#[no_mangle]
pub extern "C" fn dynamically_loaded_library_function() -> i32 {
    42
}
