//! Prepare complete encrypted files while the CFAPI view is open.
use super::{Archive, file_id, wide};
use crate::{
    cipher::Cipher,
    format::{BLOCK, Tag, block_len},
};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, Write},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    },
    Storage::{CloudFilters::*, FileSystem::*},
    System::Threading::WaitForSingleObject,
};
use zeroize::Zeroizing;

pub(super) fn attributes(handle: &File, root: bool) -> Result<(bool, bool)> {
    let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle(),
            FileAttributeTagInfo,
            (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of_val(&tag) as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let state =
        unsafe { CfGetPlaceholderStateFromAttributeTag(tag.FileAttributes, tag.ReparseTag) };
    let placeholder =
        state != CF_PLACEHOLDER_STATE_INVALID && state & CF_PLACEHOLDER_STATE_PLACEHOLDER != 0;
    let sync_root =
        state != CF_PLACEHOLDER_STATE_INVALID && state & CF_PLACEHOLDER_STATE_SYNC_ROOT != 0;
    ensure!(
        tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            || (if sync_root { root } else { placeholder }),
        "Unsupported reparse point"
    );
    Ok((
        tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        placeholder,
    ))
}

pub(super) fn clean_id(handle: &File) -> Option<u64> {
    // BASIC_INFO has a variable-length identity. Use aligned storage and
    // check the returned length before reading our eight identity bytes.
    let mut storage = [0u64; 8];
    let mut len = 0;
    let result = unsafe {
        CfGetPlaceholderInfo(
            handle.as_raw_handle(),
            CF_PLACEHOLDER_INFO_BASIC,
            storage.as_mut_ptr().cast(),
            size_of_val(&storage) as u32,
            &mut len,
        )
    };
    let offset = std::mem::offset_of!(CF_PLACEHOLDER_BASIC_INFO, FileIdentity);
    if result < 0 || (len as usize) < offset + 8 {
        return None;
    }
    let info = unsafe { &*storage.as_ptr().cast::<CF_PLACEHOLDER_BASIC_INFO>() };
    if info.InSyncState != CF_IN_SYNC_STATE_IN_SYNC || info.FileIdentityLength != 8 {
        return None;
    }
    Some(unsafe {
        storage
            .as_ptr()
            .cast::<u8>()
            .add(offset)
            .cast::<u64>()
            .read_unaligned()
    })
}

#[derive(PartialEq, Eq)]
struct Stamp {
    id: (u32, u32, u32),
    size: u64,
    changed: i64,
    written: i64,
}

impl Stamp {
    fn read(handle: &File) -> Result<Self> {
        let mut basic = FILE_BASIC_INFO::default();
        if unsafe {
            GetFileInformationByHandleEx(
                handle.as_raw_handle(),
                FileBasicInfo,
                (&mut basic as *mut FILE_BASIC_INFO).cast(),
                size_of_val(&basic) as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self {
            id: file_id(handle)?,
            size: handle.metadata()?.len(),
            changed: basic.ChangeTime,
            written: basic.LastWriteTime,
        })
    }
}

pub(super) struct Sealed {
    pub id: u64,
    pub tags: Vec<Tag>,
    stamp: Stamp,
    plain_hash: [u8; 32],
    record_hash: [u8; 32],
    records: File,
}

impl Sealed {
    fn copy_to(&mut self, output: &mut File, buf: &mut [u8]) -> Result<()> {
        self.records.rewind()?;
        let mut hash = Sha256::new();
        loop {
            let n = self.records.read(buf)?;
            if n == 0 {
                break;
            }
            hash.update(&buf[..n]);
            output.write_all(&buf[..n])?;
        }
        ensure!(
            <[u8; 32]>::from(hash.finalize()) == self.record_hash,
            "Damaged staged ciphertext"
        );
        Ok(())
    }
}

pub(super) struct Staging {
    state: PathBuf,
    pub next: u64,
    pub files: HashMap<PathBuf, Sealed>,
    last_error: Option<String>,
}

impl Staging {
    pub fn new(state: &Path, next: u64) -> Self {
        Self {
            state: state.into(),
            next,
            files: HashMap::new(),
            last_error: None,
        }
    }

    pub fn allocate(&mut self) -> Result<u64> {
        let id = self.next;
        self.next = id.checked_add(1).context("File ID overflow")?;
        Ok(id)
    }

    fn seal(
        &mut self,
        path: &Path,
        mut input: File,
        stamp: Stamp,
        archive: &Archive,
        cipher: &Cipher,
    ) -> Result<()> {
        let id = match self.files.get(path) {
            Some(file) => file.id,
            None => self.allocate()?,
        };
        let keys = archive.container.file_keys(cipher, &archive.key, id)?;
        let mut records = tempfile::tempfile_in(&self.state)?;
        let mut plain_hash = Sha256::new();
        let mut record_hash = Sha256::new();
        let mut tags = Vec::new();
        let mut buf = Zeroizing::new(vec![0; stamp.size.min(BLOCK) as usize]);
        for block in 0..stamp.size.div_ceil(BLOCK) {
            let n = block_len(stamp.size, block);
            input.read_exact(&mut buf[..n])?;
            plain_hash.update(&buf[..n]);
            let record = cipher.seal(
                &keys,
                &archive.container.block_context(id, block, n),
                &buf[..n],
            )?;
            tags.push(record[record.len() - 32..].try_into()?);
            record_hash.update(&record);
            records.write_all(&record)?;
        }
        ensure!(
            Stamp::read(&input)? == stamp,
            "File changed while encrypting"
        );
        self.files.insert(
            path.to_owned(),
            Sealed {
                id,
                tags,
                records,
                stamp,
                plain_hash: plain_hash.finalize().into(),
                record_hash: record_hash.finalize().into(),
            },
        );
        Ok(())
    }

    // The caller holds the snapshot guard against writes and renames. Verify
    // bytes even if a producer restored the original size and time stamps.
    pub fn verified(
        &mut self,
        path: &Path,
        archive: &Archive,
        cipher: &Cipher,
        buf: &mut [u8],
    ) -> Result<&Sealed> {
        let mut input = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .open(path)?;
        let stamp = Stamp::read(&input)?;
        if let Some(file) = self.files.get(path).filter(|f| f.stamp.size == stamp.size) {
            let mut hash = Sha256::new();
            loop {
                let n = input.read(buf)?;
                if n == 0 {
                    break;
                }
                hash.update(&buf[..n]);
            }
            if <[u8; 32]>::from(hash.finalize()) == file.plain_hash {
                return Ok(&self.files[path]);
            }
            input.rewind()?;
        }
        self.seal(path, input, stamp, archive, cipher)?;
        Ok(&self.files[path])
    }

    pub fn copy_to(&mut self, path: &Path, output: &mut File, buf: &mut [u8]) -> Result<()> {
        let result = self
            .files
            .get_mut(path)
            .context("Missing staged file")?
            .copy_to(output, buf);
        if result.is_err() {
            self.files.remove(path);
        }
        result
    }

    fn visit(
        &mut self,
        path: &Path,
        root: bool,
        archive: &Archive,
        cipher: &Cipher,
        seen: &mut HashSet<PathBuf>,
    ) -> Result<Option<(File, fs::ReadDir)>> {
        let guard = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let (dir, placeholder) = attributes(&guard, root)?;
        if dir {
            return Ok(Some((guard, fs::read_dir(path)?)));
        }
        let stamp = Stamp::read(&guard)?;
        if placeholder
            && clean_id(&guard)
                .and_then(|id| archive.tree.nodes.get(&id))
                .is_some_and(|node| !node.dir && node.size == stamp.size)
        {
            return Ok(None);
        }
        if stamp.size > archive.tree.quota {
            return Ok(None);
        }
        seen.insert(path.to_owned());
        if self.files.get(path).is_some_and(|file| file.stamp == stamp) {
            return Ok(None);
        }
        // Defer an active writer. Release the probe once the ordinary reader
        // is open so long encryption jobs allow subsequent edits.
        let probe = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .open(path)?;
        let input = File::open(path)?;
        drop(probe);
        drop(guard);
        self.seal(path, input, stamp, archive, cipher)?;
        Ok(None)
    }

    pub fn scan(&mut self, root: &Path, archive: &Archive, cipher: &Cipher) -> bool {
        let mut seen = HashSet::new();
        // Keep ancestor directories pinned while resolving children by path.
        let mut parents = Vec::new();
        let mut path = root.to_owned();
        let mut retry = false;
        let mut first_error = None;
        loop {
            match self.visit(&path, parents.is_empty(), archive, cipher, &mut seen) {
                Ok(Some(dir)) => parents.push(dir),
                Ok(None) => (),
                Err(err) => {
                    retry = true;
                    let busy = err.downcast_ref::<std::io::Error>().is_some_and(|e| {
                        e.kind() == std::io::ErrorKind::NotFound
                            || matches!(
                                e.raw_os_error().map(|code| code as u32),
                                Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
                            )
                    });
                    if !busy && first_error.is_none() {
                        first_error = Some(format!("{}: {err:#}", path.display()));
                    }
                }
            }
            loop {
                let Some((_, entries)) = parents.last_mut() else {
                    break;
                };
                match entries.next() {
                    Some(Ok(entry)) => {
                        path = entry.path();
                        break;
                    }
                    Some(Err(err)) => {
                        retry = true;
                        first_error.get_or_insert_with(|| err.to_string());
                    }
                    None => {
                        parents.pop();
                    }
                }
            }
            if parents.is_empty() {
                break;
            }
        }
        if first_error != self.last_error {
            if let Some(message) = &first_error {
                eprintln!("Отложена подготовка файла: {message}");
            }
            self.last_error = first_error;
        }
        self.files.retain(|path, _| seen.contains(path));
        retry
    }
}

// A subtree notification coalesces bursts of writes. A periodic pass also
// covers lost notifications, open writers and failed staging attempts.
pub(super) struct Changes {
    handle: HANDLE,
    next_scan: Instant,
}

impl Changes {
    pub fn new(root: &Path) -> Self {
        let flags = FILE_NOTIFY_CHANGE_FILE_NAME
            | FILE_NOTIFY_CHANGE_DIR_NAME
            | FILE_NOTIFY_CHANGE_SIZE
            | FILE_NOTIFY_CHANGE_LAST_WRITE;
        let handle = unsafe { FindFirstChangeNotificationW(wide(root).as_ptr(), 1, flags) };
        Self {
            handle,
            next_scan: Instant::now(),
        }
    }

    pub fn due(&mut self) -> bool {
        if self.handle != INVALID_HANDLE_VALUE {
            match unsafe { WaitForSingleObject(self.handle, 0) } {
                WAIT_OBJECT_0 => {
                    if unsafe { FindNextChangeNotification(self.handle) } == 0 {
                        self.close();
                    }
                    return true;
                }
                WAIT_TIMEOUT => (),
                _ => self.close(),
            }
        }
        Instant::now() >= self.next_scan
    }

    pub fn scanned(&mut self, retry: bool) {
        let seconds = if retry || self.handle == INVALID_HANDLE_VALUE {
            1
        } else {
            30
        };
        self.next_scan = Instant::now() + Duration::from_secs(seconds);
    }

    fn close(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            unsafe {
                FindCloseChangeNotification(self.handle);
            }
            self.handle = INVALID_HANDLE_VALUE;
        }
    }
}
impl Drop for Changes {
    fn drop(&mut self) {
        self.close();
    }
}
