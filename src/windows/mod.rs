mod archive;
mod cloud;
mod pack;
mod sidebar;
mod staging;

use self::{archive::Archive, pack::Snapshot};
use crate::{
    cipher::{Cipher, random},
    format::Container,
};
use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, Write},
    net::{Ipv4Addr, Shutdown, TcpListener, TcpStream},
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
    process::Command,
    ptr,
    time::Duration,
};
use tempfile::NamedTempFile;
use windows_sys::Win32::{
    Storage::FileSystem::*,
    UI::WindowsAndMessaging::{MB_ICONERROR, MB_ICONINFORMATION, MB_OK, MessageBoxW},
};

#[derive(Parser)]
#[command(version, about = "S-Box Cloud Files provider")]
struct Args {
    #[arg(long, global = true)]
    plugin: Option<PathBuf>,
    /// Show failures in Explorer even after the console window closes.
    #[arg(long, global = true)]
    explorer: bool,
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Create an encrypted S-Box and show its new master key.
    Create {
        #[arg(required_unless_present = "in_folder", conflicts_with = "in_folder")]
        storage: Option<PathBuf>,
        /// Ask for the file name in this folder (Explorer action).
        #[arg(long)]
        in_folder: Option<PathBuf>,
        #[arg(long, default_value_t = 1)]
        quota_gb: u64,
    },
    Mount {
        storage: PathBuf,
    },
    Unmount {
        storage: PathBuf,
    },
}

fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

fn write_state(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut tmp = NamedTempFile::new_in(path.parent().context("Missing parent")?)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)?;
    Ok(())
}

fn file_id(f: &File) -> Result<(u32, u32, u32)> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    ))
}

fn endpoint(state: &Path) -> Result<(u16, String)> {
    let data = fs::read_to_string(state.join("endpoint")).context("No active S-Box session")?;
    let (port, token) = data.split_once(' ').context("Invalid session endpoint")?;
    ensure!(token.len() == 64, "Invalid session token");
    Ok((port.parse()?, token.to_owned()))
}

fn unmount(state: &Path) -> Result<()> {
    let (port, token) = endpoint(state)?;
    let mut socket = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .context("Provider is offline. Mount again to recover the session")?;
    println!("Сохраняю изменения и закрываю рабочую папку…");
    socket.write_all(token.as_bytes())?;
    socket.shutdown(Shutdown::Write)?;
    let mut reply = String::new();
    socket.take(64 * 1024).read_to_string(&mut reply)?;
    ensure!(
        reply == "OK",
        "{}",
        if reply.is_empty() {
            "Provider stopped before confirming the save"
        } else {
            &reply
        }
    );
    println!("Контейнер сохранён и размонтирован.");
    Ok(())
}

fn finish_cleanup(state: &Path, view: &Path) -> Result<()> {
    sidebar::remove(state)?;
    if view.try_exists()? {
        ensure!(
            fs::read_dir(view)?.next().is_none(),
            "Working folder contains unsaved entries: {}",
            view.display()
        );
        cloud::unregister(view)?;
        fs::remove_dir(view)?;
    }
    // Remove the phase marker last so an interrupted cleanup remains repeatable.
    for name in [
        "sidebar-name",
        "sidebar.lnk",
        "endpoint",
        "ready",
        "closing",
        "base.sbox",
        "retiring",
    ] {
        match fs::remove_file(state.join(name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            result => result?,
        }
    }
    Ok(())
}

fn mount(
    storage: &Path,
    state: &Path,
    plugin: PathBuf,
    explorer: bool,
    key: zeroize::Zeroizing<Vec<u8>>,
) -> Result<()> {
    let mut original = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .open(storage)
        .context("Cannot open container for editing. Check permissions and existing sessions")?;
    let cipher = Cipher::load(&plugin)?;
    let (current, _) = Container::read_index(&mut original, &cipher, &key)?;
    fs::create_dir_all(state)?;
    let session_lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .share_mode(0)
        .open(state.join("lock"))
        .context("Session already active")?;
    let view = state.join("opened");
    let base = state.join("base.sbox");
    let ready = state.join("ready");
    let closing = state.join("closing");
    let retiring = state.join("retiring");
    if retiring.try_exists()? {
        ensure!(
            fs::read(&retiring)? == current.revision,
            "Container changed during cleanup"
        );
        finish_cleanup(state, &view)?;
    }
    let fresh = !base.try_exists()?;
    if fresh {
        ensure!(
            !view.try_exists()? && !ready.try_exists()? && !closing.try_exists()?,
            "Incomplete session in {}",
            state.display()
        );
        original.rewind()?;
        let mut tmp = NamedTempFile::new_in(state)?;
        std::io::copy(&mut original, &mut tmp)?;
        tmp.as_file().sync_all()?;
        tmp.persist_noclobber(&base)?;
    }
    let archive = Archive::open(base.clone(), plugin, key, &cipher)?;
    let mut committed = closing.try_exists()? && fs::read(&closing)? == current.revision;
    ensure!(
        current.id == archive.container.id
            && (current.revision == archive.container.revision || committed),
        "Container changed outside this session. Working files retained in {}",
        state.display()
    );
    let publish = !ready.try_exists()?;
    if publish {
        // A failed first population has never been published. Keep any partial tree for inspection.
        ensure!(
            !view.try_exists()?,
            "Previous setup incomplete in {}. Move the session directory aside before retrying",
            state.display()
        );
        archive.validate_names()?;
        fs::create_dir(&view)?;
        if let Err(e) = cloud::register(&view, &current.id) {
            let _ = fs::remove_dir(&view);
            return Err(e);
        }
    }
    let connection = cloud::Connection::open(&view, &archive)?;
    if publish {
        if let Err(e) = archive.populate(&view) {
            drop(connection);
            cloud::unregister(&view)?;
            // Empty directories can be retried immediately. Preserve any local files.
            let _ = fs::remove_dir(&view);
            return Err(e);
        }
        write_state(&ready, &archive.container.revision)?;
    }
    if !committed {
        sidebar::publish(storage, state, &view)
            .context("Не удалось создать ярлык контейнера в панели S-Box")?;
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let token = hex::encode(random::<32>()?);
    write_state(
        &state.join("endpoint"),
        format!("{} {token}", listener.local_addr()?.port()).as_bytes(),
    )?;
    println!(
        "S-Box: {}\nKeep this window open. Use Unmount on the container to save.",
        view.display()
    );
    println!(
        "Snapshot: {:.3} MB",
        archive.tree.used() as f64 / 1_000_000.0
    );
    if explorer && !committed {
        let shell = PathBuf::from(std::env::var_os("SystemRoot").context("Missing SystemRoot")?)
            .join("explorer.exe");
        if let Err(e) = Command::new(shell).arg(&view).spawn() {
            eprintln!("Explorer: {e}");
        }
    }
    let mut original_id = file_id(&original)?;
    let mut staging = staging::Staging::new(state, archive.tree.next);
    let mut changes = (!committed).then(|| staging::Changes::new(&view));
    listener.set_nonblocking(true)?;
    loop {
        let mut client = match listener.accept() {
            Ok((client, _)) => client,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if let Some(watch) = changes.as_mut() {
                    if watch.due() {
                        watch.scanned(staging.scan(&view, &archive, &cipher));
                    }
                }
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
            Err(err) => return Err(err.into()),
        };
        client.set_nonblocking(false)?;
        client.set_read_timeout(Some(Duration::from_secs(3)))?;
        let mut provided = [0; 64];
        if client.read_exact(&mut provided).is_err() || provided != token.as_bytes() {
            continue;
        }
        drop(changes.take());
        let close = (|| -> Result<()> {
            let at_path = File::open(storage)?;
            ensure!(
                file_id(&at_path)? == original_id,
                "Container replaced by another application"
            );
            let snapshot = Snapshot::capture(&view, archive.tree.quota)?;
            if committed {
                let saved = Archive::open(
                    storage.to_owned(),
                    archive.plugin.clone(),
                    archive.key.clone(),
                    &cipher,
                )?;
                snapshot.verify_remaining(&view, &saved)?;
            } else {
                let (temp, new) = snapshot.pack(&archive, &cipher, storage, &mut staging)?;
                let temp = temp.into_temp_path();
                write_state(&closing, &new.revision)?;
                ensure!(
                    file_id(&File::open(storage)?)? == original_id,
                    "Container changed during packing"
                );
                if unsafe {
                    ReplaceFileW(
                        wide(storage).as_ptr(),
                        wide(&*temp).as_ptr(),
                        ptr::null(),
                        0,
                        ptr::null(),
                        ptr::null_mut(),
                    )
                } == 0
                {
                    return Err(std::io::Error::last_os_error())
                        .context("Replacing the S-Box container");
                }
                committed = true;
                original = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
                    .open(storage)?;
                original_id = file_id(&original)?;
            }
            snapshot.clean()?;
            ensure!(
                fs::read_dir(&view)?.next().is_none(),
                "New files appeared during unmount. Work folder retained"
            );
            write_state(&retiring, &fs::read(&closing)?)
        })();
        if let Err(e) = close {
            changes = (!committed).then(|| staging::Changes::new(&view));
            let msg = format!("{e:#}\nWorking directory: {}", view.display());
            eprintln!("{msg}");
            let _ = client.write_all(msg.as_bytes());
            continue;
        }
        drop(connection);
        let finish = finish_cleanup(state, &view);
        if let Err(e) = finish {
            let _ = client.write_all(
                format!(
                    "Container saved. Session cleanup failed in {}: {e:#}",
                    state.display()
                )
                .as_bytes(),
            );
            return Err(e);
        }
        drop(session_lock);
        let _ = client.write_all(b"OK");
        return Ok(());
    }
}

fn plugin_path(plugin: Option<PathBuf>) -> Result<PathBuf> {
    let path = match plugin {
        Some(path) => path,
        None => std::env::current_exe()?.with_file_name("aldcrypto.dll"),
    };
    fs::canonicalize(path).context("Cannot locate the Windows crypto DLL")
}

fn session_location(path: &Path) -> Result<(PathBuf, PathBuf)> {
    let storage = fs::canonicalize(path)?;
    let mut hash = Sha256::new();
    for ch in storage.as_os_str().encode_wide() {
        hash.update(ch.to_le_bytes());
    }
    let state = PathBuf::from(std::env::var_os("LOCALAPPDATA").context("Missing LOCALAPPDATA")?)
        .join("VaultLab")
        .join("sessions")
        .join(hex::encode(hash.finalize()));
    Ok((storage, state))
}

fn create(
    storage: Option<PathBuf>,
    folder: Option<PathBuf>,
    quota_gb: u64,
    plugin: PathBuf,
) -> Result<()> {
    let quota = quota_gb
        .checked_mul(1_000_000_000)
        .filter(|q| *q > 0)
        .context("Недопустимая квота")?;
    let mut path = if let Some(folder) = folder {
        print!("Имя нового контейнера (например, Работа): ");
        std::io::stdout().flush()?;
        let mut name = String::new();
        std::io::stdin().read_line(&mut name)?;
        let name = name.trim_end_matches(['\r', '\n']);
        archive::validate_name(name)?;
        folder.join(name)
    } else {
        storage.context("Укажите путь к контейнеру")?
    };
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .context("Недопустимое имя файла")?;
    archive::validate_name(name)?;
    if !name.to_ascii_lowercase().ends_with(".sbox") {
        let name = format!("{name}.sbox");
        archive::validate_name(&name)?;
        path.set_file_name(name);
    }
    ensure!(
        !path.try_exists()?,
        "Файл уже существует: {}",
        path.display()
    );
    let cipher = Cipher::load(&plugin)?;
    let key = zeroize::Zeroizing::new(random::<32>()?);
    let text = zeroize::Zeroizing::new(hex::encode(key.as_slice()));
    println!(
        "Сохраните ключ отдельно от контейнера. Вставьте его ещё раз для подтверждения.\n{}",
        text.as_str()
    );
    let confirm = crate::key()?;
    ensure!(
        confirm.as_slice() == key.as_slice(),
        "Ключи не совпали. Файл не создан."
    );
    Container::create_empty(&path, &cipher, key.as_slice(), quota)?;
    println!("Создан контейнер {}. Квота {quota_gb} ГБ.", path.display());
    Ok(())
}

pub fn run() -> Result<()> {
    let args = Args::parse();
    let closing = matches!(args.action, Action::Unmount { .. });
    let creating = matches!(args.action, Action::Create { .. });
    let result = (|| -> Result<()> {
        match args.action {
            Action::Create {
                storage,
                in_folder,
                quota_gb,
            } => create(storage, in_folder, quota_gb, plugin_path(args.plugin)?),
            Action::Mount { storage } => {
                let (storage, state) = session_location(&storage)?;
                mount(
                    &storage,
                    &state,
                    plugin_path(args.plugin)?,
                    args.explorer,
                    crate::key()?,
                )
            }
            Action::Unmount { storage } => unmount(&session_location(&storage)?.1),
        }
    })();
    if args.explorer {
        let notice = match &result {
            Err(e) => Some((format!("{e:#}"), MB_ICONERROR)),
            Ok(()) if creating => Some((
                "Контейнер создан. Выберите «Монтировать S-Box» в меню файла.".into(),
                MB_ICONINFORMATION,
            )),
            Ok(()) if closing => Some((
                "Контейнер сохранён и размонтирован.".into(),
                MB_ICONINFORMATION,
            )),
            Ok(()) => None,
        };
        if let Some((message, icon)) = notice {
            unsafe {
                MessageBoxW(
                    ptr::null_mut(),
                    wide(message).as_ptr(),
                    wide("S-Box").as_ptr(),
                    MB_OK | icon,
                );
            }
        }
    }
    result
}

#[cfg(test)]
mod tests;
