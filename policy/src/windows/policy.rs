use crate::os::path::{path_is_sane, derive_all_reg_key_paths_from_path, OS_PATH_SEPARATOR};
use crate::policy::{Policy, PolicyVerdict};
use crate::{PolicyError, strip_one_component};
use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE, GENERIC_ALL, READ_CONTROL, SYNCHRONIZE, FILE_READ_DATA, FILE_READ_ATTRIBUTES, FILE_READ_EA, FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES, DELETE, WRITE_DAC, WRITE_OWNER, ACCESS_MASK, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE, REG_OPTION_VOLATILE, REG_OPTION_NON_VOLATILE, KEY_NOTIFY, KEY_WOW64_32KEY, KEY_WOW64_64KEY, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_CREATE_SUB_KEY, KEY_SET_VALUE, FILE_ATTRIBUTE_NORMAL};
use winapi::um::winbase::{FILE_FLAG_WRITE_THROUGH, FILE_FLAG_SEQUENTIAL_SCAN, FILE_FLAG_RANDOM_ACCESS, FILE_FLAG_OPEN_NO_RECALL, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_DELETE_ON_CLOSE, FILE_FLAG_NO_BUFFERING, FILE_FLAG_OPEN_REPARSE_POINT};
use winapi::shared::ntdef::ULONG;

const FILE_ALWAYS_GRANTED_RIGHTS: u32 = READ_CONTROL | SYNCHRONIZE;
const FILE_READ_RIGHTS: u32 = GENERIC_READ | GENERIC_ALL | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA;
const FILE_WRITE_RIGHTS: u32 = GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER;

const KEY_ALWAYS_GRANTED_RIGHTS: u32 =
    READ_CONTROL | SYNCHRONIZE | KEY_NOTIFY | KEY_WOW64_32KEY | KEY_WOW64_64KEY;
const KEY_READ_RIGHTS: u32 = KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_ALWAYS_GRANTED_RIGHTS;
const KEY_WRITE_RIGHTS: u32 = KEY_CREATE_SUB_KEY | KEY_SET_VALUE | DELETE | WRITE_DAC | WRITE_OWNER | KEY_ALWAYS_GRANTED_RIGHTS;

// Constants from winternl.h not yet exported by winapi
const FILE_DELETE_ON_CLOSE: u32 = 0x00001000;
const FILE_SUPERSEDE: u32 = 0x00000000;
const FILE_OPEN: u32 = 0x00000001;
const FILE_CREATE: u32 = 0x00000002;
const FILE_OPEN_IF: u32 = 0x00000003;
const FILE_OVERWRITE: u32 = 0x00000004;
const FILE_OVERWRITE_IF: u32 = 0x00000005;

const SUPPORTED_FILE_CREATE_DISPOSITIONS: [ULONG; 6] = [FILE_SUPERSEDE, FILE_CREATE, FILE_OPEN, FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF];
const SUPPORTED_FILE_ATTRIBUTES: ULONG = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_NO_BUFFERING | FILE_FLAG_OPEN_NO_RECALL | FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_WRITE_THROUGH;

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyRequest<'a> {
    FileOpen {
        path: &'a str,
        desired_access: ACCESS_MASK,
        file_attributes: ULONG,
        share_access: ULONG,
        create_disposition: ULONG,
        create_options: ULONG,
        ea: &'a [u8],
    },
    RegKeyOpen {
        path: &'a str,
        desired_access: ACCESS_MASK,
        create_options: ULONG,
        do_create: bool,
    },
}

impl Policy<'_> {
    pub fn evaluate_request(&self, req: &PolicyRequest) -> PolicyVerdict {
        let res = match req {
            PolicyRequest::FileOpen { path, desired_access, file_attributes, share_access, create_disposition, create_options, ea } => self.check_file_open(path, *desired_access, *file_attributes, *share_access, *create_disposition, *create_options, ea),
            PolicyRequest::RegKeyOpen { path, desired_access, create_options, do_create } => self.check_reg_key_open(path, *desired_access, *create_options, *do_create),
        };
        self.log_verdict(req, &res);
        res
    }

    fn check_file_open(&self,
                       path: &str,
                       desired_access: ACCESS_MASK,
                       file_attributes: ULONG,
                       share_access: ULONG,
                       create_disposition: ULONG,
                       create_options: ULONG,
                       ea: &[u8]) -> PolicyVerdict {
        let unsupported_access_rights = desired_access & !(FILE_ALWAYS_GRANTED_RIGHTS | FILE_READ_RIGHTS | FILE_WRITE_RIGHTS);
        if unsupported_access_rights != 0 {
            return PolicyVerdict::DelegationToSandboxNotSupported {
                why: format!("access right {:#X} not supported", unsupported_access_rights),
            };
        }
        let unsupported_attributes = file_attributes & !SUPPORTED_FILE_ATTRIBUTES;
        if unsupported_attributes != 0 {
            return PolicyVerdict::DelegationToSandboxNotSupported {
                why: format!("file attribute {:#X} not supported", unsupported_attributes),
            };
        }
        if (create_options & FILE_FLAG_OPEN_REPARSE_POINT) == 0 {
            return PolicyVerdict::DelegationToSandboxNotSupported {
                why: format!("opening files with reparse points enabled is not supported"),
            };
        }
        if !SUPPORTED_FILE_CREATE_DISPOSITIONS.contains(&create_disposition) {
            return PolicyVerdict::DelegationToSandboxNotSupported {
                why: format!("file creation disposition {:#X} not supported", create_disposition),
            };
        }
        if !path_is_sane(path) {
            return PolicyVerdict::InvalidRequestParameters {
                argument_name: "path".to_owned(),
                reason: format!("path to open \"{}\" is not in canonical form", path),
            };
        }
        // Ensure the access requested matches the worker's policy
        let requests_read = (desired_access & FILE_READ_RIGHTS) != 0 && ![FILE_SUPERSEDE, FILE_CREATE, FILE_OVERWRITE, FILE_OVERWRITE_IF].contains(&create_disposition);
        let requests_write = ((desired_access & FILE_WRITE_RIGHTS) != 0) || (create_disposition != FILE_OPEN) || ((create_options & FILE_DELETE_ON_CLOSE) != 0) || !ea.is_empty();
        let requests_block_readers = (share_access & FILE_SHARE_READ) == 0;
        let requests_block_writers = (share_access & FILE_SHARE_WRITE) == 0;
        let requests_block_deleters = (share_access & FILE_SHARE_DELETE) == 0;
        let (can_read, can_write, can_block_readers, can_block_writers, can_block_deleters) = self.get_filepath_allowed_access(path);
        if !(can_read || can_write || can_block_readers || can_block_writers || can_block_deleters)
        {
            PolicyVerdict::DeniedByPolicy { why: "has no access to that path".to_owned() }
        }
        else if (requests_read && !can_read) || (requests_write && !can_write)
        {
            PolicyVerdict::DeniedByPolicy { why: format!("requests {}, but {}",
                if requests_read && requests_write {
                    "read and write"
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
            )}
        } else if (requests_block_readers && !can_block_readers)
            || (requests_block_writers && !can_block_writers)
            || (requests_block_deleters && !can_block_deleters)
        {
            let mut why = format!("requests to block other");
            if requests_block_readers {
                why.push_str(" readers");
            }
            if requests_block_writers {
                why.push_str(" writers");
            }
            if requests_block_deleters {
                why.push_str(" deleters");
            }
            why.push_str(" but ");
            if can_block_readers || can_block_writers || can_block_deleters {
                why.push_str("can only block");
                if can_block_readers {
                    why.push_str(" readers");
                }
                if can_block_writers {
                    why.push_str(" writers");
                }
                if can_block_deleters {
                    why.push_str(" deleters");
                }
            } else {
                why.push_str("has no lock right");
            }
            PolicyVerdict::DeniedByPolicy { why }
        } else {
            PolicyVerdict::Granted
        }
    }

    pub fn allow_regkey_read(&mut self, path: &str) -> Result<(), PolicyError> {
        self.allow_regkey_access(path, (true, false))
    }

    pub fn allow_regkey_write(&mut self, path: &str) -> Result<(), PolicyError> {
        self.allow_regkey_access(path, (false, true))
    }

    fn allow_regkey_access(&mut self, path: &str, access: (bool, bool)) -> Result<(), PolicyError> {
        let (new_read, new_write) = access;
        for path in derive_all_reg_key_paths_from_path(path)? {
            let path = match path.strip_suffix(OS_PATH_SEPARATOR) {
                Some(rest) => rest,
                None => &path,
            };
            let (prev_read, prev_write) = self.regkey_access.get(path)
                .copied()
                .unwrap_or((false, false));
            self.regkey_access.insert(
                path.to_owned(),
                (
                    prev_read | new_read,
                    prev_write | new_write,
                )
            );
        }
        Ok(())
    }

    fn get_regkey_allowed_access(&self, path: &str) -> (bool, bool) {
        let mut verdict_read = false;
        let mut verdict_write = false;
        let mut current_path = match path.strip_suffix(OS_PATH_SEPARATOR) {
            Some(s) => s,
            None => path,
        };
        while !verdict_read || !verdict_write {
            if let Some((read, write)) = self.regkey_access.get(current_path) {
                verdict_read |= read;
                verdict_write |= write;
            }
            match strip_one_component(current_path, OS_PATH_SEPARATOR) {
                Some(parent_path) => current_path = parent_path,
                None => break,
            }
        }
        (
            verdict_read,
            verdict_write,
        )
    }

    fn check_reg_key_open(&self, path: &str, desired_access: ACCESS_MASK, create_options: ULONG, do_create: bool) -> PolicyVerdict {
        let unsupported_access_rights = desired_access & !(KEY_READ_RIGHTS | KEY_WRITE_RIGHTS | KEY_ALWAYS_GRANTED_RIGHTS);
        if unsupported_access_rights != 0 {
            return PolicyVerdict::DelegationToSandboxNotSupported {
                why: format!("access right {:#X} not supported", unsupported_access_rights),
            };
        }
        let unsupported_create_options = create_options & !(REG_OPTION_VOLATILE | REG_OPTION_NON_VOLATILE);
        if unsupported_create_options != 0 {
            return PolicyVerdict::DelegationToSandboxNotSupported {
                why: format!("creation option {:#X} not supported", unsupported_create_options),
            };
        }
        let requests_read = (desired_access & KEY_READ_RIGHTS) != 0;
        let requests_write = (desired_access & KEY_WRITE_RIGHTS) != 0 || do_create;
        let (can_read, can_write) = self.get_regkey_allowed_access(&path);
        if !(can_read || can_write)
            || (requests_read && !can_read)
            || (requests_write && !can_write)
        {
            let why = format!("requests {} access, but {}",
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
            PolicyRequest::FileOpen { path, desired_access, file_attributes, share_access, create_disposition, create_options, ea } => {
                write!(f, "file {} with access_mask {:#X} (sharing {:#X}) (attributes {:#X}) (create_disposition {:#X} and create_options {:#X})",
                    path, desired_access, share_access, file_attributes, create_disposition, create_options)?;
                if !ea.is_empty() {
                    write!(f, "with {} bytes of extended attributes", ea.len())?;
                }
                Ok(())
            },
            PolicyRequest::RegKeyOpen { path, desired_access, create_options, do_create } => {
                write!(f, "registry key {} with access_mask {:#X}", path, desired_access)?;
                if *do_create {
                    write!(f, ", creating it with options {:#X} if it does not exist", create_options)?;
                }
                Ok(())
            },
        }
    }
}
