use crate::os::path::path_is_sane;
use crate::policy::{Policy, PolicyVerdict};
use libc::{
    c_int, O_APPEND, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_PATH, O_RDONLY, O_RDWR,
    O_TRUNC, O_WRONLY,
};

const SUPPORTED_FILE_OPEN_FLAGS: c_int = O_RDONLY
    | O_WRONLY
    | O_RDWR
    | O_TRUNC
    | O_CREAT
    | O_EXCL
    | O_DIRECTORY
    | O_APPEND
    | O_PATH
    | O_CLOEXEC;

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyRequest<'a> {
    FileOpen { path: &'a str, flags: c_int },
}

impl Policy<'_> {
    pub fn evaluate_request(&self, req: &PolicyRequest) -> PolicyVerdict {
        let res = match req {
            PolicyRequest::FileOpen { path, flags } => self.check_file_open(path, *flags),
        };
        self.log_verdict(req, &res);
        res
    }

    fn check_file_open(&self, path: &str, flags: c_int) -> PolicyVerdict {
        if (flags & !SUPPORTED_FILE_OPEN_FLAGS) != 0 {
            return PolicyVerdict::DelegationToSandboxNotSupported {
                why: format!(
                    "open flag {:#X} not supported",
                    flags & !SUPPORTED_FILE_OPEN_FLAGS
                ),
            };
        }
        if !path_is_sane(path) {
            return PolicyVerdict::InvalidRequestParameters {
                argument_name: "path".to_owned(),
                why: format!("path to open \"{path}\" is not in canonical form"),
            };
        }
        // When O_PATH is set, other flags than O_CLOEXEC, O_DIRECTORY, and O_NOFOLLOW are supposed to be ignored by the kernel
        // Enforce this by clearing other bits. Also enforce O_CLOEXEC for good measure.
        let flags = if (flags & O_PATH) != 0 {
            flags & (O_PATH | O_DIRECTORY | O_NOFOLLOW)
        } else {
            flags
        } | O_CLOEXEC;
        // Ensure the access requested matches the worker's policy
        let requests_read = (flags & (O_WRONLY | O_PATH)) == 0;
        let requests_write = (flags & (O_WRONLY | O_RDWR | O_TRUNC | O_CREAT | O_EXCL | O_APPEND))
            != 0
            && (flags & O_PATH) == 0;
        let (can_read, can_write, _, _, _) = self.get_filepath_allowed_access(path);
        if !(can_read || can_write)
            || (requests_read && !can_read)
            || (requests_write && !can_write)
        {
            let why = format!(
                "requests {} access, but {}",
                if requests_read && requests_write {
                    "read-write"
                } else if requests_read {
                    "read-only"
                } else if requests_write {
                    "write-only"
                } else {
                    "read or write"
                },
                if can_read {
                    "can only read"
                } else if can_write {
                    "can only write"
                } else {
                    "has no access to that path"
                }
            );
            PolicyVerdict::DeniedByPolicy { why }
        } else {
            PolicyVerdict::Granted
        }
    }
}

impl<'a> core::fmt::Display for PolicyRequest<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            PolicyRequest::FileOpen { path, flags } => {
                write!(f, "file {path} with flags {flags:#X}")
            }
        }
    }
}
