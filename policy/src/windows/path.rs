use core::ptr::null_mut;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::GetFullPathNameW;

pub(crate) fn canonicalize_path(path: &str) -> Vec<String> {
    let relative: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let str_len = unsafe { GetFullPathNameW(relative.as_ptr(), 0, null_mut(), null_mut()) };
    let absolute = if str_len == 0 {
        println!(
            " [!] GetFullPathNameW({}) failed with error {}",
            path,
            unsafe { GetLastError() }
        );
        path.to_owned()
    } else {
        let mut buf = vec![0u16; str_len as usize];
        let res =
            unsafe { GetFullPathNameW(relative.as_ptr(), str_len, buf.as_mut_ptr(), null_mut()) };
        if res == 0 || res > str_len {
            println!(
                " [!] GetFullPathNameW({}) failed with error {}",
                path,
                unsafe { GetLastError() }
            );
            path.to_owned()
        } else {
            match String::from_utf16(&buf[..str_len as usize - 1]) {
                Ok(s) => s,
                Err(e) => {
                    println!(
                        " [!] GetFullPathNameW({}) returned a non-unicode result, {}: {:?}",
                        path, e, buf
                    );
                    path.to_owned()
                }
            }
        }
    };
    let mut res = vec![];
    // Drive-absolute path type
    if absolute.get(1..3) == Some(":\\") {
        res.push(format!("\\??\\{}", absolute)); // \??\C:\Windows\Temp\a.txt
    }
    res
}
