pub(crate) mod handle;
pub(crate) mod path;

pub(crate) const ALWAYS_ALLOWED_PATHS: [(&str, bool, bool, bool); 4] = [
    ("/lib/*", true, false, false),
    ("/usr/lib/*", true, false, false),
    ("/etc/ld.so.cache", true, false, false),
    ("/dev/null", true, true, false),
];
