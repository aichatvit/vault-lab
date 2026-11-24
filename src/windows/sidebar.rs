//! Explorer shows shortcuts in a dedicated directory, separate from encrypted session state.
use super::{file_id, wide, write_state};
use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File, OpenOptions},
    io::ErrorKind,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Component, Path, PathBuf},
    ptr,
};
use windows::{
    Win32::{
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
            CoUninitialize, IPersistFile,
        },
        UI::Shell::{IShellLinkW, ShellLink},
    },
    core::{Interface, PCWSTR},
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_DISPOSITION_INFO, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileDispositionInfo, SetFileInformationByHandle,
};

fn directory(state: &Path) -> Result<PathBuf> {
    Ok(state
        .parent()
        .and_then(Path::parent)
        .context("Invalid S-Box session directory")?
        .join("Containers"))
}

fn recorded_name(state: &Path) -> Result<Option<String>> {
    let name = match fs::read_to_string(state.join("sidebar-name")) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        other => other?,
    };
    let mut parts = Path::new(&name).components();
    ensure!(
        matches!(parts.next(), Some(Component::Normal(_)))
            && parts.next().is_none()
            && name.ends_with(".lnk")
            && !name.contains([':', '/', '\\']),
        "Invalid sidebar shortcut name"
    );
    Ok(Some(name))
}

fn save_shortcut(path: &Path, view: &Path) -> Result<()> {
    // The CLI session thread is not otherwise using COM. Release interfaces before uninitializing it.
    unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok()? };
    let result = (|| -> Result<()> {
        let link: IShellLinkW =
            unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)? };
        unsafe {
            link.SetPath(PCWSTR(wide(view).as_ptr()))?;
        }
        let persist: IPersistFile = link.cast()?;
        unsafe {
            persist.Save(PCWSTR(wide(path).as_ptr()), true)?;
        }
        Ok(())
    })();
    unsafe { CoUninitialize() };
    result
}

pub fn publish(storage: &Path, state: &Path, view: &Path) -> Result<()> {
    let folder = directory(state)?;
    fs::create_dir_all(&folder)?;
    // Keep a private hard link so recovery and cleanup can identify our exact
    // shortcut, even if another container or a user file has the same name.
    let backing = state.join("sidebar.lnk");
    if !backing.try_exists()? {
        let temp = tempfile::tempdir_in(state)?;
        let link = temp.path().join("new.lnk");
        save_shortcut(&link, view)?;
        fs::rename(link, &backing)?;
    }
    let identity = file_id(&File::open(&backing)?)?;
    let previous = recorded_name(state)?;
    let label: String = storage
        .file_name()
        .context("Missing container name")?
        .to_string_lossy()
        .chars()
        .scan(0, |len, ch| {
            *len += ch.len_utf16();
            (*len <= 228).then_some(ch)
        })
        .collect();
    let names = (1u64..).map(|n| {
        if n == 1 {
            format!("{label}.lnk")
        } else {
            format!("{label} ({n}).lnk")
        }
    });
    for name in previous.into_iter().chain(names) {
        let path = folder.join(&name);
        write_state(&state.join("sidebar-name"), name.as_bytes())?;
        match fs::hard_link(&backing, &path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                let existing = OpenOptions::new()
                    .read(true)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(&path);
                if existing.ok().as_ref().and_then(|f| file_id(f).ok()) == Some(identity) {
                    return Ok(());
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    anyhow::bail!("No available shortcut name")
}

pub fn remove(state: &Path) -> Result<()> {
    let Some(name) = recorded_name(state)? else {
        return Ok(());
    };
    let path = directory(state)?.join(name);
    let file = match OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path)
    {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        result => result?,
    };
    if file_id(&file)? == file_id(&File::open(state.join("sidebar.lnk"))?)? {
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileDispositionInfo,
                ptr::from_ref(&disposition).cast(),
                size_of_val(&disposition) as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}
