//! Hold each object against writes and renames until the replacement is durable.
use super::{
    Archive,
    staging::{Staging, attributes, clean_id},
    wide,
};
use crate::{
    cipher::{Cipher, random},
    format::{BLOCK, Container, Node, Tree},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Read,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
    ptr,
};
use tempfile::NamedTempFile;
use windows_sys::Win32::{
    Foundation::{ERROR_HANDLE_EOF, INVALID_HANDLE_VALUE},
    Storage::FileSystem::*,
};
use zeroize::Zeroizing;

struct Entry {
    path: PathBuf,
    guard: File,
    baseline: Option<u64>,
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
            let (dir, placeholder) = attributes(&guard, id == 1)
                .with_context(|| format!("Checking {}", path.display()))?;
            let baseline = if placeholder && !dir {
                clean_id(&guard)
            } else {
                None
            };
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
                    baseline,
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
        &self,
        archive: &Archive,
        cipher: &Cipher,
        destination: &Path,
        staging: &mut Staging,
    ) -> Result<(NamedTempFile, Container)> {
        let parent = destination.parent().context("Invalid container location")?;
        let container = Container {
            revision: random()?,
            ..archive.container
        };
        let mut tree = Tree::empty(self.tree.quota);
        let mut directories = BTreeMap::from([(1, 1)]);
        // None selects the authenticated baseline. Other payloads are complete staged files.
        let mut sources = BTreeMap::new();
        let mut buf = Zeroizing::new(vec![0; BLOCK as usize]);
        for ((&temporary_id, template), entry) in self.tree.nodes.iter().zip(&self.entries).skip(1)
        {
            let mut node = template.clone();
            node.parent = directories[&node.parent];
            let id = if node.dir {
                let id = staging.allocate()?;
                directories.insert(temporary_id, id);
                id
            } else if let Some(id) = entry.baseline.filter(|id| {
                !sources.contains_key(id)
                    && archive
                        .tree
                        .nodes
                        .get(id)
                        .is_some_and(|old| !old.dir && old.size == node.size)
            }) {
                node.tags.clone_from(&archive.tree.nodes[&id].tags);
                sources.insert(id, None);
                id
            } else {
                let file = staging
                    .verified(&entry.path, archive, cipher, &mut buf)
                    .with_context(|| format!("Preparing {}", entry.path.display()))?;
                node.tags.clone_from(&file.tags);
                sources.insert(file.id, Some(&entry.path));
                file.id
            };
            tree.nodes.insert(id, node);
        }
        tree.next = staging.next;
        let mut out = NamedTempFile::new_in(parent)?;
        container.write_index(out.as_file_mut(), cipher, &archive.key, &tree)?;
        let mut base = File::open(&archive.baseline)?;
        let mut record = Vec::new();
        for (id, source) in sources {
            if let Some(path) = source {
                staging.copy_to(path, out.as_file_mut(), &mut buf)?;
            } else {
                archive.copy_records(id, &mut base, out.as_file_mut(), cipher, &mut record)?;
            }
        }
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
