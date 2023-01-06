#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use common::common_test_setup;
use iris_worker::lower_final_sandbox_privileges_asap;
use log::info;
use std::convert::TryInto;
use std::ffi::{CStr, CString};

#[cfg(unix)]
fn run_checks(path: &CStr, policy_readable: bool, policy_writable: bool) {
    use libc::{c_int, c_void, O_RDONLY, O_WRONLY, O_RDWR, O_PATH, O_APPEND, O_EXCL, O_CREAT, O_TRUNC, O_CLOEXEC};

    fn check_path(path: &CStr, flags: c_int, should_work: bool) {
        // Try to open a file descriptor using open()
        unsafe { *(libc::__errno_location()) = 0 };
        let res = unsafe { libc::syscall(libc::SYS_open, path.as_ptr(), flags, 0, 0, 0, 0) };
        let err = unsafe { *(libc::__errno_location()) };
        if should_work {
            assert!(res >= 0, "open({}, flags={}) should have worked, failed with errno {}",
                path.to_string_lossy(),
                flags,
                err
            );
            let res = unsafe { libc::close(res.try_into().expect("invalid file descriptor")) };
            assert_eq!(res, 0, "unable to close file descriptor");
        } else {
            assert!(res < 0, "open({}, flags={}) should have failed, succeeded",
                path.to_string_lossy(),
                flags
            );
            assert_eq!(err, libc::EACCES, "open({}, flags={}) should have failed with errno EACCES, failed with errno {}",
                path.to_string_lossy(),
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
                path.as_ptr(),
                flags,
                0,
                0,
                0,
            )
        };
        let err = unsafe { *(libc::__errno_location()) };
        if should_work {
            assert!(res >= 0, "openat({}, flags={}) should have worked, failed with errno {}",
                path.to_string_lossy(),
                flags,
                err
            );
        } else {
            assert!(res < 0, "openat({}, flags={}) should have failed, succeeded",
                path.to_string_lossy(),
                flags
            );
            assert_eq!(err, libc::EACCES, "openat({}, flags={}) should have failed with errno EACCES, failed with errno {}",
                path.to_string_lossy(),
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
fn run_checks(test_function: u8, path: &CStr, granted_by_policy: u8, access_to_request: u8) {
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
        GetFileSize, ReadFile, SetFilePointer, WriteFile, INVALID_SET_FILE_POINTER,
    };
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
    use winapi::um::winbase::FILE_BEGIN;
    use winapi::um::winnt::{
        ACCESS_MASK, DELETE, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_READ_ATTRIBUTES,
        FILE_READ_DATA, FILE_READ_EA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, HANDLE, LARGE_INTEGER, PHANDLE,
        PVOID, READ_CONTROL, SYNCHRONIZE, WCHAR,
    };
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
    #[allow(non_camel_case_types)]
    type pntopenfile = unsafe extern "system" fn(
        file_handle: PHANDLE,
        desired_access: ACCESS_MASK,
        object_attributes: POBJECT_ATTRIBUTES,
        io_status_block: PIO_STATUS_BLOCK,
        share_access: ULONG,
        open_options: ULONG,
    ) -> NTSTATUS;

    fn check_handle(handle: HANDLE, should_be_granted: u8) {
        let mut buf = vec![0u8; 1024];
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
        if (should_be_granted & FILE_READ) == 0 {
            assert_eq!(res, 0, "ReadFile succeeded");
            assert_eq!(err, ERROR_ACCESS_DENIED, "unexpected ReadFile error code");
        } else {
            assert_ne!(res, 0, "ReadFile failed (error code {})", err);
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
        let buf = b"KO";
        let mut bytes_written: DWORD = 0;
        unsafe { SetLastError(0) };
        let res = unsafe {
            WriteFile(
                handle,
                buf.as_ptr() as *const _,
                2,
                &mut bytes_written as *mut _,
                null_mut(),
            )
        };
        let err = unsafe { GetLastError() };
        if (should_be_granted & (FILE_WRITE_ANYWHERE | FILE_WRITE_APPEND_ONLY)) == 0 {
            assert_eq!(res, 0, "WriteFile should have failed");
            assert_eq!(err, ERROR_ACCESS_DENIED, "unexpected WriteFile error code");
        } else {
            assert_ne!(res, 0, "WriteFile failed (error {})", err);
            assert_eq!(bytes_written, 2, "unexpected number of bytes written");
            assert_eq!(err, 0, "WriteFile set error to {} unexpectedly", err);
            // Check the result: should be "KO" if writable anywhere, "OKKO" if writable only in APPEND mode
            // Do this check using GetFileSize() which requires no permission on the file (reading would fail
            // when not readable by policy)
            let size = unsafe { GetFileSize(handle, null_mut()) };
            assert_eq!(
                size,
                if (should_be_granted & FILE_WRITE_APPEND_ONLY) == 0 {
                    2
                } else {
                    4
                },
                "unexpected result file size"
            );
        }
    }

    let dllname = CString::new("ntdll.dll").unwrap();
    let hntdll = unsafe { LoadLibraryA(dllname.as_ptr()) };
    assert_ne!(hntdll, null_mut());
    let funcname = CString::new("NtCreateFile").unwrap();
    let ntcreatefile = unsafe { GetProcAddress(hntdll, funcname.as_ptr()) };
    assert_ne!(ntcreatefile, null_mut());
    let ntcreatefile = unsafe { std::mem::transmute::<FARPROC, pntcreatefile>(ntcreatefile) };
    let funcname = CString::new("NtOpenFile").unwrap();
    let ntopenfile = unsafe { GetProcAddress(hntdll, funcname.as_ptr()) };
    assert_ne!(ntopenfile, null_mut());
    let ntopenfile = unsafe { std::mem::transmute::<FARPROC, pntopenfile>(ntopenfile) };

    let path = path.to_string_lossy();
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

    let requested_rights = SYNCHRONIZE
        | READ_CONTROL
        | if (access_to_request & FILE_READ) != 0 {
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA
        } else {
            0
        }
        | if (access_to_request & FILE_WRITE_ANYWHERE) != 0 {
            FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE
        } else {
            0
        }
        | if (access_to_request & FILE_WRITE_APPEND_ONLY) != 0 {
            FILE_APPEND_DATA
        } else {
            0
        };

    let should_work = ((access_to_request & FILE_READ) == 0
        || (granted_by_policy & FILE_READ) != 0)
        && ((access_to_request & FILE_WRITE_ANYWHERE) == 0
            || (granted_by_policy & FILE_WRITE_ANYWHERE) != 0)
        && ((access_to_request & FILE_WRITE_APPEND_ONLY) == 0
            || (granted_by_policy & (FILE_WRITE_APPEND_ONLY | FILE_WRITE_ANYWHERE)) != 0)
        && access_to_request != 0
        && granted_by_policy != 0;

    let mut hfile: HANDLE = null_mut();
    let file_sharing = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    if test_function == 1 {
        let res = unsafe {
            ntcreatefile(
                &mut hfile as *mut _,
                requested_rights,
                &mut obj_attr as *mut _,
                &mut io_status_block as *mut _,
                &mut allocation_size as *mut _,
                FILE_ATTRIBUTE_NORMAL,
                file_sharing,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                null_mut(),
                0,
            )
        };
        assert!(
            (should_work
                && NT_SUCCESS(res)
                && hfile != null_mut()
                && io_status_block.information == FILE_OPENED)
                || (!should_work && res == STATUS_ACCESS_DENIED && hfile == null_mut()),
            "NtCreateFile({}, 0x{:X}) = 0x{:X}",
            path,
            requested_rights,
            res
        );
    } else if test_function == 2 {
        let res = unsafe {
            ntopenfile(
                &mut hfile as *mut _,
                requested_rights,
                &mut obj_attr as *mut _,
                &mut io_status_block as *mut _,
                file_sharing,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            )
        };
        assert!(
            (should_work
                && NT_SUCCESS(res)
                && hfile != null_mut()
                && io_status_block.information == FILE_OPENED)
                || (!should_work && res == STATUS_ACCESS_DENIED && hfile == null_mut()),
            "NtOpenFile({}, 0x{:X}) = 0x{:X}",
            path,
            requested_rights,
            res
        );
    } else {
        panic!("Unknown function {}", test_function);
    }
    info!("Opened handle with access rights 0x{:X}", requested_rights);
    if hfile != null_mut() {
        check_handle(hfile, access_to_request);
        assert_ne!(unsafe { CloseHandle(hfile) }, 0);
    }
}

fn main() {
    lower_final_sandbox_privileges_asap();
    common_test_setup();

    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 4);
    let path = CString::new(args[1].as_str()).unwrap();
    let policy_readable = args[2] == "1";
    let policy_writable = args[3] == "1";

    info!(
        "{} should be {}readable {}writable",
        args[1],
        if policy_readable { "" } else { "non-" },
        if policy_writable { "" } else { "non-" },
    );
    run_checks(&path, policy_readable, policy_writable)
}
