use crate::{cipher::Cipher, fs::VaultFs, safe_path, store::Store};
use anyhow::{Context, Result, ensure};
use std::{
    ffi::CString,
    io,
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, process::CommandExt},
    },
    path::Path,
    process::Command,
};
use zeroize::Zeroizing;
static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn stop_mount(_: libc::c_int) {
    STOP.store(true, std::sync::atomic::Ordering::Relaxed);
}

pub fn mount_visible(
    path: &Path,
    cipher: Cipher,
    key: Zeroizing<Vec<u8>>,
    point: &Path,
) -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "mount requires sudo");
    ensure!(Path::new("/dev/fuse").exists(), "/dev/fuse is unavailable");
    let (uid, gid) = mount_owner()?;
    let directory = safe_path::directory(point)
        .context("Mountpoint must be an existing directory without symlinks")?;
    ensure!(
        std::fs::read_dir(point)?.next().is_none(),
        "Mountpoint must be empty"
    );
    let options = [
        fuser::MountOption::FSName("vault-lab".into()),
        fuser::MountOption::DefaultPermissions,
        // Kernel permissions (0700/0600) restrict access to the selected owner.
        fuser::MountOption::AllowOther,
        fuser::MountOption::NoDev,
        fuser::MountOption::NoSuid,
        fuser::MountOption::NoExec,
    ];
    let mut store = Store::open(path, cipher, key)?;
    // Keep the checked directory alive and mount through its descriptor.
    let target = std::path::PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let mut session =
        fuser::Session::new(VaultFs::with_owner(&mut store, uid, gid), &target, &options)
            .context("FUSE mount failed")?;
    let mut unmounter = session.unmount_callable();
    STOP.store(false, std::sync::atomic::Ordering::Relaxed);
    let old_int =
        unsafe { libc::signal(libc::SIGINT, stop_mount as *const () as libc::sighandler_t) };
    let old_term =
        unsafe { libc::signal(libc::SIGTERM, stop_mount as *const () as libc::sighandler_t) };
    println!(
        "Mounted at {}; Ctrl-C to unmount (owner UID {uid}, GID {gid})",
        point.display()
    );
    let (done, receiver) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        loop {
            match receiver.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
            if STOP.swap(false, std::sync::atomic::Ordering::Relaxed) {
                if let Err(error) = unmounter.unmount() {
                    eprintln!("Unmount failed: {error}; close open files and retry Ctrl-C");
                }
            }
        }
    });
    let result = session.run();
    let _ = done.send(());
    let joined = worker.join();
    unsafe {
        libc::signal(libc::SIGINT, old_int);
        libc::signal(libc::SIGTERM, old_term);
    }
    joined.map_err(|_| anyhow::anyhow!("Unmount worker panicked"))?;
    result?;
    drop(session);
    store.close().context("Container packing failed")
}

fn mount_owner() -> Result<(u32, u32)> {
    match (std::env::var_os("SUDO_UID"), std::env::var_os("SUDO_GID")) {
        (None, None) => Ok((unsafe { libc::geteuid() }, unsafe { libc::getegid() })),
        (Some(uid), Some(gid)) => {
            let parse = |value: std::ffi::OsString| -> Result<u32> {
                let value = value.to_str().context("Invalid sudo owner ID")?;
                ensure!(
                    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                    "Invalid sudo owner ID"
                );
                let id: u32 = value.parse().context("Invalid sudo owner ID")?;
                ensure!(id != u32::MAX, "Invalid sudo owner ID");
                Ok(id)
            };
            Ok((parse(uid)?, parse(gid)?))
        }
        _ => anyhow::bail!("SUDO_UID and SUDO_GID must both be set"),
    }
}
fn mount(
    source: Option<&Path>,
    target: &Path,
    kind: Option<&str>,
    flags: libc::c_ulong,
) -> Result<()> {
    let source = source
        .map(|p| CString::new(p.as_os_str().as_bytes()))
        .transpose()?;
    let target = CString::new(target.as_os_str().as_bytes())?;
    let kind = kind.map(CString::new).transpose()?;
    let rc = unsafe {
        libc::mount(
            source.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            target.as_ptr(),
            kind.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            flags,
            std::ptr::null(),
        )
    };
    ensure!(rc == 0, "mount: {}", io::Error::last_os_error());
    Ok(())
}
fn unmount(path: &Path) -> Result<()> {
    let p = CString::new(path.as_os_str().as_bytes())?;
    ensure!(
        unsafe { libc::umount2(p.as_ptr(), 0) } == 0,
        "unmount: {}",
        io::Error::last_os_error()
    );
    Ok(())
}
pub fn open(
    path: &Path,
    cipher: Cipher,
    key: Zeroizing<Vec<u8>>,
    test: bool,
    attack: bool,
    verify: bool,
) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "open requires sudo for mount namespace; do not run cargo as root"
    );
    ensure!(Path::new("/dev/fuse").exists(), "/dev/fuse is unavailable");
    ensure!(
        unsafe { libc::unshare(libc::CLONE_NEWNS) } == 0,
        "unshare: {}",
        io::Error::last_os_error()
    );
    mount(None, Path::new("/"), None, libc::MS_REC | libc::MS_PRIVATE)?;
    let temp = tempfile::Builder::new()
        .prefix("vault-lab-")
        .tempdir_in("/tmp")?;
    mount(
        None,
        temp.path(),
        Some("tmpfs"),
        libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC,
    )?;
    let result = (|| -> Result<Store> {
        let point = temp.path().join("view");
        std::fs::create_dir(&point)?;
        let decoy = temp.path().join("decoy");
        std::fs::create_dir(&decoy)?;
        let options = [
            fuser::MountOption::FSName("vault-lab".into()),
            fuser::MountOption::DefaultPermissions,
            fuser::MountOption::NoDev,
            fuser::MountOption::NoSuid,
            fuser::MountOption::NoExec,
        ];
        let mut store = Store::open(path, cipher, key)?;
        let mut session = fuser::Session::new(VaultFs::new(&mut store), &point, &options)
            .context("FUSE mount failed")?;
        let mut unmounter = session.unmount_callable();
        // Parent survives Ctrl-C; child gets default SIGINT and triggers orderly cleanup on exit.
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_IGN);
        }
        let worker = std::thread::spawn(move || -> Result<()> {
            let mut overlay = false;
            let result = (|| -> Result<()> {
                // This is our fresh mount in our fresh private tmpfs. Never accept a caller-supplied view path.
                let root = safe_path::directory(&point)?;
                let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
                ensure!(
                    unsafe { libc::fstatfs(root.as_raw_fd(), &mut stat) } == 0
                        && stat.f_type == 0x65735546,
                    "Unexpected filesystem at view"
                );
                if attack {
                    mount(Some(&decoy), &point, None, libc::MS_BIND)?;
                    overlay = true;
                    println!("TEST: bind-mounted decoy over view after capturing root descriptor");
                }
                let fd = root.as_raw_fd();
                let mut cmd = Command::new(std::env::current_exe()?);
                cmd.arg("probe").arg("--fd").arg("3");
                if test {
                    cmd.arg("--test");
                }
                if verify {
                    cmd.arg("--verify");
                }
                // Only async-signal-safe libc operations in the fork child before exec.
                unsafe {
                    cmd.pre_exec(move || {
                        if libc::dup2(fd, 3) < 0 {
                            return Err(io::Error::last_os_error());
                        }
                        if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                            return Err(io::Error::last_os_error());
                        }
                        libc::signal(libc::SIGINT, libc::SIG_DFL);
                        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
                            return Err(io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                let status = cmd.status()?;
                drop(root);
                ensure!(status.success(), "Probe exited with {status}");
                if attack {
                    ensure!(
                        std::fs::read_dir(&decoy)?.next().is_none(),
                        "Plaintext was written into decoy"
                    );
                    println!("PASS: decoy remained empty; descriptor kept original FUSE mount");
                }
                Ok(())
            })();
            let overlay_result = if overlay { unmount(&point) } else { Ok(()) };
            let cleanup = unmounter.unmount();
            result?;
            overlay_result?;
            cleanup?;
            Ok(())
        });
        let run = session.run();
        let worker_result = worker
            .join()
            .map_err(|_| anyhow::anyhow!("Probe manager panicked"))?;
        drop(session);
        run?;
        worker_result?;
        Ok(store)
    })();
    let cleanup = unmount(temp.path());
    let mut store = result?;
    cleanup?;
    store.close().context("Container packing failed")
}
