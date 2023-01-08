#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use common::common_test_setup;
use iris_worker::lower_final_sandbox_privileges_asap;
use log::info;
use std::convert::TryInto;
use std::ffi::CString;

#[cfg(unix)]
fn run_checks(path: &str, policy_readable: bool, policy_writable: bool) {
    use libc::{c_int, c_void, O_RDONLY, O_WRONLY, O_RDWR, O_PATH, O_APPEND, O_EXCL, O_CREAT, O_TRUNC, O_CLOEXEC};

    fn check_path(path: &str, flags: c_int, should_work: bool) {
        let path_nul = CString::new(path).unwrap();
        // Try to open a file descriptor using open()
        unsafe { *(libc::__errno_location()) = 0 };
        let res = unsafe { libc::syscall(libc::SYS_open, path_nul.as_ptr(), flags, 0, 0, 0, 0) };
        let err = unsafe { *(libc::__errno_location()) };
        if should_work {
            assert!(res >= 0, "open({}, flags={}) should have worked, failed with errno {}",
                path,
                flags,
                err
            );
            let res = unsafe { libc::close(res.try_into().expect("invalid file descriptor")) };
            assert_eq!(res, 0, "unable to close file descriptor");
        } else {
            assert!(res < 0, "open({}, flags={}) should have failed, succeeded",
                path,
                flags
            );
            assert_eq!(err, libc::EACCES, "open({}, flags={}) should have failed with errno EACCES, failed with errno {}",
                path,
                flags,
                err
            );
        }
        // Perform the same test using openat()
        unsafe { *(libc::__errno_location()) = 0 };
        let res = unsafe {
            libc::syscall(
                libc::SYS_openat,
                libc::STDERR_FILENO,
                path_nul.as_ptr(),
                flags,
                0,
                0,
                0,
            )
        };
        let err = unsafe { *(libc::__errno_location()) };
        if should_work {
            assert!(res >= 0, "openat({}, flags={}) should have worked, failed with errno {}",
                path,
                flags,
                err
            );
        } else {
            assert!(res < 0, "openat({}, flags={}) should have failed, succeeded",
                path,
                flags
            );
            assert_eq!(err, libc::EACCES, "openat({}, flags={}) should have failed with errno EACCES, failed with errno {}",
                path,
                flags,
                err
            );
        }
        if res >= 0 {
            let fd: c_int = res.try_into().expect("invalid file descriptor returned");
            check_fd(fd, flags);
            let res = unsafe { libc::close(fd) };
            assert_eq!(res, 0, "unable to close file descriptor");
        }
    }

    fn check_fd(fd: c_int, flags: c_int) {
        let mut buf = [0u8; 3];
        // Try to read (set up by the broker to contain "OK")
        unsafe { *(libc::__errno_location()) = 0 };
        let res = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, 3) };
        let err = unsafe { *(libc::__errno_location()) };
        if (flags & (O_WRONLY | O_PATH)) == 0 {
            if (flags & O_TRUNC) == 0 {
                assert!(res >= 0, "read() failed on fd flags={:#X} with errno {}", flags, err);
                assert_eq!(res, 2, "wrong number of bytes read from test file");
                assert_eq!(b"OK", &buf[..2], "unexpected content read from test file");
            } else {
                assert_eq!(res, 0, "file was supposed to be empty after truncation");
            }
        } else {
            assert_eq!(res, -1, "read() should have failed");
            assert_eq!(err, libc::EBADF, "read() failed with the wrong errno");
        }
        // Try to write
        // If the write is supposed to succeed, seek to a deterministic index so that this part
        // does not depend on whether read() was allowed by policy
        if (flags & (O_WRONLY | O_RDWR)) != 0 && (flags & O_PATH) == 0 {
            unsafe { *(libc::__errno_location()) = 0 };
            let res = unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
            assert_eq!(res, 0, "lseek() failed with errno {}", unsafe { *(libc::__errno_location()) });
        }
        // Do the write
        unsafe { *(libc::__errno_location()) = 0 };
        let res = unsafe { libc::write(fd, b"KO?".as_ptr() as *const c_void, 3) };
        let err = unsafe { *(libc::__errno_location()) };
        if (flags & (O_WRONLY | O_RDWR)) != 0 && (flags & O_PATH) == 0 {
            assert_eq!(res, 3, "write() failed with error {}", err);
            // Check the result using fstat() which requires no permission
            // on the file (reading would fail when write-only)
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            let res = unsafe { libc::fstat(fd, &mut stat as *mut _) };
            assert_eq!(res, 0, "unable to fstat()");
            let expected_size = if (flags & O_APPEND) == 0 { 3 } else { 5 };
            assert_eq!(stat.st_size, expected_size, "unexpected file size after write with flags={:#X}", flags);
            // Reset the file as we found it
            let res = unsafe { libc::ftruncate(fd, 0) };
            assert_eq!(res, 0, "unable to truncate test file");
            let res = unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
            assert_eq!(res, 0);
            let res = unsafe { libc::write(fd, b"OK".as_ptr() as *const c_void, 2) };
            assert_eq!(res, 2, "unable to reset test file contents");
        } else {
            assert_eq!(res, -1, "write() should have failed due to flags={:#X}", flags);
            assert_eq!(err, libc::EBADF, "write() failed with the wrong errno");
        }
    }

    check_path(path, O_RDONLY, policy_readable);
    check_path(path, O_RDONLY | O_CLOEXEC, policy_readable);
    check_path(path, O_WRONLY, policy_writable);
    check_path(path, O_RDWR, policy_readable && policy_writable);
    check_path(path, O_WRONLY | O_APPEND, policy_writable);
    check_path(path, O_RDWR | O_APPEND, policy_readable && policy_writable);
    check_path(path, O_PATH, policy_readable || policy_writable);
    check_path(path, O_RDONLY | O_CREAT, policy_readable && policy_writable);
    check_path(path, O_RDONLY | O_EXCL, policy_readable && policy_writable);
    // Last test, messes up the test file with no way to reset it
    check_path(path, O_RDONLY | O_TRUNC, policy_readable && policy_writable);
}

#[cfg(windows)]
fn run_checks(path: &str, policy_readable: bool, policy_writable: bool) {
    use core::ptr::null_mut;
    use winapi::shared::basetsd::ULONG_PTR;
    use winapi::shared::minwindef::{DWORD, FARPROC};
    use winapi::shared::ntdef::{
        InitializeObjectAttributes, NTSTATUS, NT_SUCCESS, OBJECT_ATTRIBUTES, PLARGE_INTEGER,
        POBJECT_ATTRIBUTES, ULONG, UNICODE_STRING,
    };
    use winapi::shared::ntstatus::STATUS_ACCESS_DENIED;
    use winapi::shared::winerror::ERROR_ACCESS_DENIED;
    use winapi::um::errhandlingapi::{GetLastError, SetLastError};
    use winapi::um::fileapi::{
        GetFileSize, ReadFile, SetFilePointer, SetEndOfFile, WriteFile, INVALID_SET_FILE_POINTER,
    };
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
    use winapi::um::winbase::FILE_BEGIN;
    use winapi::um::winnt::{
        ACCESS_MASK, FILE_APPEND_DATA, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_WRITE_DATA, HANDLE, LARGE_INTEGER, PHANDLE,
        PVOID, SYNCHRONIZE, WCHAR, GENERIC_READ, GENERIC_WRITE, GENERIC_ALL
    };
    const FILE_SHARE_ALL: ULONG = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    const FILE_OPEN: DWORD = 0x00000001;
    const FILE_OPENED: ULONG_PTR = 0x00000001;
    const FILE_NON_DIRECTORY_FILE: DWORD = 0x00000040;
    const FILE_SYNCHRONOUS_IO_NONALERT: DWORD = 0x00000020;
    #[allow(non_camel_case_types)]
    struct IO_STATUS_BLOCK {
        _pointer: PVOID,
        information: ULONG_PTR,
    }
    #[allow(non_camel_case_types)]
    type PIO_STATUS_BLOCK = *mut IO_STATUS_BLOCK;
    #[allow(non_camel_case_types)]
    type pntcreatefile = unsafe extern "system" fn(
        file_handle: PHANDLE,
        desired_access: ACCESS_MASK,
        object_attributes: POBJECT_ATTRIBUTES,
        io_status_block: PIO_STATUS_BLOCK,
        allocation_size: PLARGE_INTEGER,
        file_attributes: ULONG,
        share_access: ULONG,
        create_disposition: ULONG,
        create_options: ULONG,
        ea_buffer: PVOID,
        ea_length: ULONG,
    ) -> NTSTATUS;

    fn check_handle(handle: HANDLE, access_rights: ACCESS_MASK) {
        let mut buf = [0u8; 3];
        let mut bytes_read: DWORD = 0;
        // Try to read (set up by the broker to contain "OK")
        unsafe {
            SetLastError(0);
        }
        let res = unsafe {
            ReadFile(
                handle,
                buf.as_mut_ptr() as *mut _,
                buf.len().try_into().unwrap(),
                &mut bytes_read as *mut _,
                null_mut(),
            )
        };
        let err = unsafe { GetLastError() };
        if (access_rights & (GENERIC_READ | GENERIC_ALL | FILE_READ_DATA)) == 0 {
            assert_eq!(res, 0, "ReadFile should not have succeeded");
            assert_eq!(err, ERROR_ACCESS_DENIED, "unexpected ReadFile error code");
        } else {
            assert_ne!(res, 0, "ReadFile failed with error code {}", err);
            assert_eq!(err, 0, "ReadFile set error code {} unexpectedly", err);
            assert_eq!(bytes_read, 2, "wrong number of bytes read");
            assert_eq!(
                b"OK",
                &buf[..bytes_read as usize],
                "read unexpected contents from file"
            );
        }
        // Try to write at the beginning
        let res = unsafe { SetFilePointer(handle, 0, null_mut(), FILE_BEGIN) };
        assert_ne!(res, INVALID_SET_FILE_POINTER, "unable to seek to beginning");
        let buf = b"KO?";
        let mut bytes_written: DWORD = 0;
        unsafe { SetLastError(0) };
        let res = unsafe {
            WriteFile(
                handle,
                buf.as_ptr() as *const _,
                3,
                &mut bytes_written as *mut _,
                null_mut(),
            )
        };
        let err = unsafe { GetLastError() };
        if (access_rights & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA)) == 0 {
            assert_eq!(res, 0, "WriteFile should have failed");
            assert_eq!(err, ERROR_ACCESS_DENIED, "unexpected WriteFile error code");
        } else {
            assert_ne!(res, 0, "WriteFile failed (error {})", err);
            assert_eq!(bytes_written, 3, "unexpected number of bytes written");
            assert_eq!(err, 0, "WriteFile set error to {} unexpectedly", err);
            // Check the result: should be "OKKO?" if append-only, "KO?" otherwise
            // Do this check using GetFileSize() which requires no permission on the file (reading would fail
            // when not readable by policy)
            let size = unsafe { GetFileSize(handle, null_mut()) };
            assert_eq!(
                size,
                if (access_rights & FILE_APPEND_DATA) == 0 {
                    3
                } else {
                    5
                },
                "unexpected result file size"
            );
            // Reset file as we found it
            let res = unsafe { SetFilePointer(handle, 0, null_mut(), FILE_BEGIN) };
            assert_ne!(res, INVALID_SET_FILE_POINTER, "unable to seek to beginning");
            let res = unsafe { SetEndOfFile(handle) };
            assert_ne!(res, 0, "unable to truncate file");
        }
    }

    fn check_path(path: &str, desired_access: ACCESS_MASK, create_disposition: ULONG, create_options: ULONG, attributes: ULONG, share_access: ULONG, should_work: bool) {
        let dllname = CString::new("ntdll.dll").unwrap();
        let hntdll = unsafe { LoadLibraryA(dllname.as_ptr()) };
        assert_ne!(hntdll, null_mut());
        let funcname = CString::new("NtCreateFile").unwrap();
        let ntcreatefile = unsafe { GetProcAddress(hntdll, funcname.as_ptr()) };
        assert_ne!(ntcreatefile, null_mut());
        let ntcreatefile = unsafe { std::mem::transmute::<FARPROC, pntcreatefile>(ntcreatefile) };
        // TODO: same with NtOpenFile

        let mut obj_attr: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
        let mut us_obj_name: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        let buffer_len: u16 = ((us_obj_name.len() - 1) * std::mem::size_of::<WCHAR>())
            .try_into()
            .unwrap();
        let mut us_obj_name = UNICODE_STRING {
            Buffer: us_obj_name.as_mut_ptr(),
            Length: buffer_len,
            MaximumLength: buffer_len,
        };
        let h_directory: HANDLE = null_mut();
        unsafe {
            InitializeObjectAttributes(
                &mut obj_attr as *mut _,
                &mut us_obj_name as *mut _,
                0,
                h_directory,
                null_mut(),
            )
        };
        let mut allocation_size: LARGE_INTEGER = unsafe { std::mem::zeroed() };
        let mut io_status_block = IO_STATUS_BLOCK {
            _pointer: null_mut(),
            information: 0,
        };

        let mut hfile: HANDLE = null_mut();
        let res = unsafe {
            ntcreatefile(
                &mut hfile as *mut _,
                desired_access,
                &mut obj_attr as *mut _,
                &mut io_status_block as *mut _,
                &mut allocation_size as *mut _,
                attributes,
                share_access,
                create_disposition,
                create_options,
                null_mut(),
                0,
            )
        };
        if should_work {
            assert!(NT_SUCCESS(res), "NtCreateFile({}, access_mask={:#X}, share={:#X}, create_disposition={:#X}, create_options={:#X}) should have succeeded", path, desired_access, share_access, create_disposition, create_options);
            assert_ne!(hfile, null_mut(), "NtCreateFile() succeeded but did not return a handle");
            assert_eq!(io_status_block.information, FILE_OPENED);
            info!("Opened handle with access rights 0x{:X}", desired_access);
            check_handle(hfile, desired_access);
            assert_ne!(unsafe { CloseHandle(hfile) }, 0, "NtCreateFile() returned an invalid handle");
        } else {
            assert_eq!(res, STATUS_ACCESS_DENIED, "NtCreateFile returned unexpected status");
            assert_eq!(hfile, null_mut(), "NtCreateFile failed but still returned a handle");
        }
    }

    let res = std::fs::read_to_string(path);
    if policy_readable {
        assert!(res.is_ok(), "reading using stdlib APIs should have worked");
        assert_eq!(res.unwrap(), "OK", "unexpected contents read from file");
    } else {
        assert!(res.is_err(), "reading using stdlib APIs should have failed");
    }

    check_path(path, FILE_READ_DATA | SYNCHRONIZE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, FILE_SHARE_ALL, policy_readable);
    check_path(path, GENERIC_READ | SYNCHRONIZE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, FILE_SHARE_ALL, policy_readable);
    check_path(path, FILE_WRITE_DATA | SYNCHRONIZE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, FILE_SHARE_ALL, policy_writable);
    check_path(path, GENERIC_WRITE | SYNCHRONIZE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, FILE_SHARE_ALL, policy_writable);
    //check_path(path, GENERIC_ALL | SYNCHRONIZE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, FILE_SHARE_ALL, policy_readable && policy_writable);
}

fn main() {
    lower_final_sandbox_privileges_asap();
    common_test_setup();

    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 4);
    let path = &args[1];
    let policy_readable = args[2] == "1";
    let policy_writable = args[3] == "1";

    info!(
        "{} should be {}readable {}writable",
        path,
        if policy_readable { "" } else { "non-" },
        if policy_writable { "" } else { "non-" },
    );
    run_checks(path, policy_readable, policy_writable)
}
