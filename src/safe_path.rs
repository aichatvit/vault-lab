use std::os::unix::ffi::OsStrExt;
use std::{
    ffi::{CStr, CString},
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, RawFd},
    path::Path,
};
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
pub fn open_at(fd: RawFd, name: &CStr, flags: i32, mode: u32, resolve: u64) -> io::Result<File> {
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: mode as u64,
        resolve,
    };
    // SAFETY: pointers reference initialized values of the correct syscall layout.
    let result = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            fd,
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(result as RawFd) })
    }
}
pub fn directory(path: &Path) -> io::Result<File> {
    let name = CString::new(path.as_os_str().as_bytes())?;
    open_at(
        libc::AT_FDCWD,
        &name,
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
        0x04,
    )
}
pub fn beneath(dir: &File, path: &str, flags: i32, mode: u32) -> io::Result<File> {
    let name = CString::new(path)?;
    // BENEATH | NO_SYMLINKS | NO_XDEV (also forbids magic links).
    open_at(dir.as_raw_fd(), &name, flags, mode, 0x08 | 0x04 | 0x01)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn descriptor_survives_path_substitution_and_rejects_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        std::fs::create_dir(&a).unwrap();
        std::fs::write(a.join("value"), b"original").unwrap();
        let dir = directory(&a).unwrap();
        std::fs::rename(&a, tmp.path().join("old")).unwrap();
        std::fs::create_dir(&a).unwrap();
        std::fs::write(a.join("value"), b"fake").unwrap();
        use std::io::Read;
        let mut value = String::new();
        beneath(&dir, "value", libc::O_RDONLY, 0)
            .unwrap()
            .read_to_string(&mut value)
            .unwrap();
        assert_eq!(value, "original");
        assert!(beneath(&dir, "../a/value", libc::O_RDONLY, 0).is_err());
        std::os::unix::fs::symlink("/etc/passwd", tmp.path().join("old/link")).unwrap();
        assert!(beneath(&dir, "link", libc::O_RDONLY, 0).is_err());
    }
}
