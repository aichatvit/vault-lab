//! This client uses only the verified root descriptor, never a mountpoint pathname.
use crate::safe_path;
use anyhow::{Result, bail, ensure};
use std::{
    ffi::CString,
    fs::File,
    io::{self, BufRead, Read, Write},
    os::fd::{AsRawFd, FromRawFd},
};
fn get(root: &File, path: &str) -> Result<Vec<u8>> {
    let mut f = safe_path::beneath(root, path, libc::O_RDONLY, 0)?;
    let mut v = vec![];
    f.read_to_end(&mut v)?;
    Ok(v)
}
fn print_file(root: &File, path: &str) -> Result<()> {
    let mut file = safe_path::beneath(root, path, libc::O_RDONLY, 0)?;
    let mut output = io::stdout().lock();
    let mut buffer = zeroize::Zeroizing::new(vec![0; 64_000]);
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        output.write_all(&buffer[..n])?;
    }
    writeln!(output)?;
    Ok(())
}

fn put(root: &File, path: &str, data: &[u8]) -> Result<()> {
    let mut f = safe_path::beneath(
        root,
        path,
        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
        0o600,
    )?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}
fn parent(root: &File, path: &str) -> Result<(File, CString)> {
    let (p, n) = path.rsplit_once('/').unwrap_or((".", path));
    ensure!(crate::store::valid_name(n), "Invalid final component");
    Ok((
        safe_path::beneath(root, p, libc::O_RDONLY | libc::O_DIRECTORY, 0)?,
        CString::new(n)?,
    ))
}
fn mkdir(root: &File, path: &str) -> Result<()> {
    let (p, n) = parent(root, path)?;
    ensure!(
        unsafe { libc::mkdirat(p.as_raw_fd(), n.as_ptr(), 0o700) } == 0,
        "mkdir: {}",
        io::Error::last_os_error()
    );
    Ok(())
}
fn remove(root: &File, path: &str, dir: bool) -> Result<()> {
    let (p, n) = parent(root, path)?;
    ensure!(
        unsafe {
            libc::unlinkat(
                p.as_raw_fd(),
                n.as_ptr(),
                if dir { libc::AT_REMOVEDIR } else { 0 },
            )
        } == 0,
        "remove: {}",
        io::Error::last_os_error()
    );
    Ok(())
}
fn move_file(root: &File, source: &str, target: &str) -> Result<()> {
    let (from, name) = parent(root, source)?;
    let (to, target) = parent(root, target)?;
    ensure!(
        unsafe {
            libc::renameat(
                from.as_raw_fd(),
                name.as_ptr(),
                to.as_raw_fd(),
                target.as_ptr(),
            )
        } == 0,
        "rename: {}",
        io::Error::last_os_error()
    );
    Ok(())
}
fn list(root: &File, path: &str) -> Result<()> {
    let dir = safe_path::beneath(root, path, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    // proc magic link refers to an already opened, constrained directory, not external input.
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
        println!("{}", entry?.file_name().to_string_lossy());
    }
    Ok(())
}
pub fn run(fd: i32, test: bool) -> Result<()> {
    ensure!(fd >= 3, "Invalid root descriptor");
    let root = unsafe { File::from_raw_fd(fd) };
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstatfs(root.as_raw_fd(), &mut stat) } == 0 && stat.f_type == 0x65735546,
        "Descriptor is not FUSE; refusing access"
    );
    if test {
        let prefix = format!("probe-{}", hex::encode(crate::cipher::random::<8>()?));
        mkdir(&root, &prefix)?;
        let name = format!("{prefix}/data");
        put(&root, &name, b"vault-probe confidential payload")?;
        ensure!(
            get(&root, &name)? == b"vault-probe confidential payload",
            "Readback differs"
        );
        put(&root, &name, b"short")?;
        ensure!(get(&root, &name)? == b"short", "Truncate failed");
        ensure!(
            safe_path::beneath(&root, "../outside", libc::O_WRONLY | libc::O_CREAT, 0o600).is_err(),
            "Escape allowed"
        );
        let renamed = format!("{prefix}/renamed");
        move_file(&root, &name, &renamed)?;
        ensure!(get(&root, &renamed)? == b"short", "Rename failed");
        remove(&root, &renamed, false)?;
        remove(&root, &prefix, true)?;
        put(&root, "probe-persistent", b"vault-probe persisted")?;
        println!(
            "PASS: FUSE create/write/read/truncate/rename/mkdir/unlink/rmdir/fsync and path lookup; persisted probe-persistent"
        );
        return Ok(());
    }
    println!(
        "Commands: put PATH TEXT | get PATH | ls [PATH] | mkdir PATH | mv PATH NEWPATH | rm PATH | rmdir PATH | exit"
    );
    let stdin = io::stdin();
    let mut input = stdin.lock();
    loop {
        print!("vault> ");
        io::stdout().flush()?;
        let mut line = zeroize::Zeroizing::new(String::new());
        if input.read_line(&mut line)? == 0 {
            break;
        }
        let mut parts = line.trim_end_matches(['\r', '\n']).splitn(3, ' ');
        let command = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or(".");
        let text = parts.next().unwrap_or("");
        if command == "exit" {
            break;
        }
        let result: Result<()> = match command {
            "put" => put(&root, path, text.as_bytes()),
            "get" => print_file(&root, path),
            "ls" => list(&root, path),
            "mkdir" => mkdir(&root, path),
            "mv" => move_file(&root, path, text),
            "rm" => remove(&root, path, false),
            "rmdir" => remove(&root, path, true),
            "" => Ok(()),
            _ => {
                eprintln!("Unknown command");
                Ok(())
            }
        };
        if let Err(e) = result {
            eprintln!("Operation failed: {e:#}");
        }
    }
    Ok(())
}
pub fn verify_persistent(fd: i32) -> Result<()> {
    let root = unsafe { File::from_raw_fd(fd) };
    if get(&root, "probe-persistent")? != b"vault-probe persisted" {
        bail!("Persistent file mismatch");
    }
    println!("PASS: persisted FUSE data survived remount");
    Ok(())
}
