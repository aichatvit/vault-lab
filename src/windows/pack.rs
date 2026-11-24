//! Hold each object against writes and renames until the replacement is durable.
use super::{Archive, wide};
use crate::{
    cipher::{Cipher, random},
    format::{BLOCK, Container, Node, Tree},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, Write},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
    ptr,
};
use tempfile::NamedTempFile;
use windows_sys::Win32::{
    Foundation::{ERROR_HANDLE_EOF, INVALID_HANDLE_VALUE},
    Storage::{CloudFilters::*, FileSystem::*},
};
use zeroize::Zeroizing;

struct Entry {
    path: PathBuf,
    guard: File,
    dir: bool,
    children: BTreeSet<std::ffi::OsString>,
}

pub struct Snapshot {
    entries: Vec<Entry>,
    tree: Tree,
}

fn checked_streams(path: &Path) -> Result<()> {
    let mut data = WIN32_FIND_STREAM_DATA::default();
    let h = unsafe {
        FindFirstStreamW(
            wide(path).as_ptr(),
            FindStreamInfoStandard,
            (&mut data as *mut WIN32_FIND_STREAM_DATA).cast(),
            0,
        )
    };
    if h == INVALID_HANDLE_VALUE {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) {
            return Ok(());
        }
        return Err(err.into());
    }
    let result = (|| -> Result<()> {
        loop {
            let name = &data.cStreamName[..data
                .cStreamName
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(data.cStreamName.len())];
            ensure!(
                name.iter().copied().eq("::$DATA".encode_utf16()),
                "Named NTFS stream on {}",
                path.display()
            );
            if unsafe { FindNextStreamW(h, (&mut data as *mut WIN32_FIND_STREAM_DATA).cast()) } == 0
            {
                let err = std::io::Error::last_os_error();
                ensure!(
                    err.raw_os_error() == Some(ERROR_HANDLE_EOF as i32),
                    "Enumerating NTFS streams: {err}"
                );
                return Ok(());
            }
        }
    })();
    unsafe {
        FindClose(h);
    }
    result
}

impl Snapshot {
    pub fn capture(root: &Path, quota: u64) -> Result<Self> {
        let mut tree = Tree::empty(quota);
        let mut entries = Vec::new();
        let mut pending = vec![(root.to_owned(), 1)];
        let mut used = 0u64;
        while let Some((path, id)) = pending.pop() {
            let guard = OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES | DELETE)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&path)
                .with_context(|| format!("Close applications using {}", path.display()))?;
            let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
            if unsafe {
                GetFileInformationByHandleEx(
                    guard.as_raw_handle(),
                    FileAttributeTagInfo,
                    (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                    size_of_val(&tag) as u32,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let state = unsafe {
                CfGetPlaceholderStateFromAttributeTag(tag.FileAttributes, tag.ReparseTag)
            };
            ensure!(
                tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                    || (state != CF_PLACEHOLDER_STATE_INVALID
                        && (state & CF_PLACEHOLDER_STATE_PLACEHOLDER != 0
                            || (id == 1 && state & CF_PLACEHOLDER_STATE_SYNC_ROOT != 0))),
                "Unsupported reparse point {}",
                path.display()
            );
            let dir = tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
            let meta = guard.metadata()?;
            let node = tree.nodes.get_mut(&id).unwrap();
            node.dir = dir;
            let mut children = BTreeSet::new();
            if dir {
                for item in fs::read_dir(&path)? {
                    let item = item?;
                    let name = item.file_name();
                    let text = name.to_str().context("Invalid Unicode file name")?;
                    super::archive::validate_name(text)?;
                    let child = tree.next;
                    tree.next += 1;
                    tree.nodes
                        .insert(child, Node::new(id, text.to_owned(), false));
                    children.insert(name);
                    pending.push((item.path(), child));
                }
            } else {
                node.size = meta.len();
                used = used
                    .checked_add(meta.len())
                    .context("File sizes overflow")?;
                ensure!(used <= quota, "S-Box quota exceeded");
            }
            checked_streams(&path)?;
            entries.push((
                id,
                Entry {
                    path,
                    guard,
                    dir,
                    children,
                },
            ));
        }
        // IDs are assigned with parents first, as required for reverse cleanup.
        entries.sort_by_key(|(id, _)| *id);
        Ok(Self {
            entries: entries.into_iter().map(|(_, e)| e).collect(),
            tree,
        })
    }

    pub fn check_directories(&self) -> Result<()> {
        for entry in self.entries.iter().filter(|e| e.dir) {
            let current = fs::read_dir(&entry.path)?
                .map(|e| e.map(|i| i.file_name()))
                .collect::<std::io::Result<BTreeSet<_>>>()?;
            ensure!(
                current == entry.children,
                "Directory changed during packing: {}",
                entry.path.display()
            );
        }
        Ok(())
    }

    pub fn pack(
        &mut self,
        archive: &Archive,
        cipher: &Cipher,
        destination: &Path,
    ) -> Result<(NamedTempFile, Container)> {
        let parent = destination.parent().context("Invalid container location")?;
        let mut payload = tempfile::tempfile_in(parent)?;
        let container = Container {
            revision: random()?,
            ..archive.container
        };
        let mut buf = Zeroizing::new(vec![0; BLOCK as usize]);
        for ((&id, node), entry) in self.tree.nodes.iter_mut().zip(&self.entries) {
            if node.dir {
                continue;
            }
            let mut input = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
                .open(&entry.path)?;
            let keys = container.file_keys(cipher, &archive.key, id)?;
            for block in 0..node.size.div_ceil(BLOCK) {
                let n = crate::format::block_len(node.size, block);
                input.read_exact(&mut buf[..n])?;
                let record =
                    cipher.seal(&keys, &container.block_context(id, block, n), &buf[..n])?;
                node.tags.push(record[record.len() - 32..].try_into()?);
                payload.write_all(&record)?;
            }
        }
        let mut out = NamedTempFile::new_in(parent)?;
        container.write_index(out.as_file_mut(), cipher, &archive.key, &self.tree)?;
        payload.rewind()?;
        std::io::copy(&mut payload, &mut out)?;
        out.as_file().sync_all()?;
        self.check_directories()?;
        Ok((out, container))
    }

    // After a crash the committed snapshot is authoritative. Only remove a leftover
    // entry after verifying that its current bytes have already been saved.
    pub fn verify_remaining(&self, root: &Path, saved: &Archive) -> Result<()> {
        let mut names = std::collections::BTreeMap::new();
        for (&id, node) in &saved.tree.nodes {
            names.insert((node.parent, node.name.as_str()), id);
        }
        let mut ids = std::collections::BTreeMap::from([(root.to_owned(), 1)]);
        for entry in self.entries.iter().skip(1) {
            let parent = ids[entry.path.parent().unwrap()];
            let name = entry
                .path
                .file_name()
                .and_then(|s| s.to_str())
                .context("Invalid file name")?;
            let id = *names
                .get(&(parent, name))
                .with_context(|| format!("Unsaved entry: {}", entry.path.display()))?;
            let node = &saved.tree.nodes[&id];
            ensure!(entry.dir == node.dir, "Entry changed after commit");
            if entry.dir {
                ids.insert(entry.path.clone(), id);
            } else {
                let mut f = OpenOptions::new()
                    .read(true)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
                    .open(&entry.path)?;
                ensure!(
                    f.metadata()?.len() == node.size,
                    "File size changed after commit"
                );
                if node.size != 0 {
                    saved.read_range(id, 0, node.size, |_, expected| {
                        let mut actual = Zeroizing::new(vec![0; expected.len()]);
                        f.read_exact(&mut actual)?;
                        ensure!(
                            actual.as_slice() == expected,
                            "Unsaved changes: {}",
                            entry.path.display()
                        );
                        Ok(())
                    })?;
                }
            }
        }
        self.check_directories()
    }

    pub fn clean(self) -> Result<()> {
        // Delete only entries actually packed, through the same locked handles.
        // A concurrent new child makes directory removal fail and is preserved.
        for entry in self.entries.into_iter().skip(1).rev() {
            let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
            if unsafe {
                SetFileInformationByHandle(
                    entry.guard.as_raw_handle(),
                    FileDispositionInfo,
                    ptr::from_ref(&disposition).cast(),
                    size_of_val(&disposition) as u32,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("Cleaning {}", entry.path.display()));
            }
        }
        Ok(())
    }
}
