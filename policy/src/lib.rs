// Common modules
mod error;
mod handle;
mod policy;

pub use error::PolicyError;
pub use handle::{CrossPlatformHandle, Handle};
pub use policy::{Policy, PolicyVerdict};

// OS-specific modules

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
mod os;

pub use os::handle::{downcast_to_handle, set_unmanaged_handle_inheritable};
pub use os::policy::PolicyRequest;

// Common utils

// Examples:
// /a/b/c -> /a/b
// /a/b -> /a
// /a -> /
// / -> None
fn strip_one_component(path: &str, separator: char) -> Option<&str> {
    let path = match path.strip_suffix(separator) {
        Some(s) => s,
        None => path,
    };
    match path.rsplit_once(separator) {
        Some((rest, _)) => {
            if rest.is_empty() {
                None
            } else {
                Some(rest)
            }
        }
        None => None,
    }
}
