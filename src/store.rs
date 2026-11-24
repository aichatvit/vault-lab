mod journal;
pub use crate::format::{Node, Tree, valid_name};
use crate::{
    cipher::{Cipher, random},
    format::{BLOCK, Container, Id, MAX_INDEX, block_len, check_tag},
    safe_path,
};
use anyhow::{Context, Result, ensure};
use journal::{Edit, Journal, PATCH_LIMIT, PATCH_SIZE, Patch};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashSet, VecDeque},
    ffi::CString,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
};
use zeroize::Zeroizing;

const WORK_HEADER: usize = 40;
const WORK_FIELDS: usize = 37;
const MAX_WORK: usize =
    MAX_INDEX + MAX_INDEX / 27 * 16 + MAX_INDEX / 32 * 8 + WORK_FIELDS + PATCH_LIMIT;
const ALIGNMENT: u64 = 4096;
const CACHE_BLOCKS: usize = 8;
const COMPACT_SLACK: u64 = 8_000_000;

#[derive(Clone)]
struct WorkFile {
    generation: Id,
    offsets: Vec<u64>,
}

impl WorkFile {
    fn contiguous(generation: Id, blocks: usize, container: Container) -> Self {
        let stride = container.record_len(BLOCK as usize) as u64;
        Self {
            generation,
            offsets: (0..blocks as u64).map(|i| i * stride).collect(),
        }
    }
}

struct Location {
    dir: File,
    name: String,
    work_name: String,
    _lock: File,
}

impl Location {
    fn lock(path: &Path) -> Result<Self> {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("Container path needs a UTF-8 file name")?
            .to_owned();
        // Sidecar names must fit within Linux NAME_MAX.
        ensure!(
            !name.starts_with('.') && name.len() <= 249,
            "Container name must not begin with a dot or exceed 249 bytes"
        );
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let dir = safe_path::directory(parent)?;
        let lock = safe_path::beneath(
            &dir,
            &format!(".{name}.lock"),
            libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
            0o600,
        )?;
        ensure!(lock.metadata()?.is_file(), "Invalid lock file");
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "Vault is busy"
        );
        let work_name = format!(".{name}.work");
        Ok(Self {
            dir,
            name,
            work_name,
            _lock: lock,
        })
    }

    fn read(&self, cipher: &Cipher, key: &[u8]) -> Result<(File, Container, Tree)> {
        let mut file = read_file(&self.dir, &self.name)?;
        let (header, tree) = Container::read_index(&mut file, cipher, key)?;
        Ok((file, header, tree))
    }

    fn work_dir(&self) -> Result<File> {
        let name = CString::new(self.work_name.as_str())?;
        let status = unsafe { libc::mkdirat(self.dir.as_raw_fd(), name.as_ptr(), 0o700) };
        if status != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error.into());
            }
        }
        let work = safe_path::beneath(
            &self.dir,
            &self.work_name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        let meta = work.metadata()?;
        ensure!(
            meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o777 == 0o700,
            "Work directory must be owned by this user with mode 0700"
        );
        self.dir.sync_all()?;
        Ok(work)
    }

    fn clean_work(&self, dir: &File) -> Result<()> {
        clean_files(dir, &HashSet::from(["state".to_owned()]))?;
        unlink_if_present(dir, "state")?;
        dir.sync_all()?;
        unlink(&self.dir, &self.work_name, libc::AT_REMOVEDIR)?;
        self.dir.sync_all()?;
        Ok(())
    }
}

struct Workspace {
    dir: File,
    session: Id,
    base: Id,
    target: Option<Id>,
    dirty: bool,
    files: BTreeMap<u64, WorkFile>,
    journal: Option<Journal>,
    patches: Vec<Patch>,
}

impl Workspace {
    fn load(
        dir: &File,
        container: Container,
        cipher: &Cipher,
        key: &[u8],
    ) -> Result<Option<(Self, Tree)>> {
        let mut state = match read_file(dir, "state") {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let (header, plain) = Self::read_state(&mut state, container, cipher, key, None)?;
        let session = header[24..].try_into()?;
        if plain[16] == 4 {
            return Ok(Some(Self::load_head(
                dir, container, cipher, key, session, &plain,
            )?));
        }
        Ok(Some(Self::decode_snapshot(
            dir, container, session, &plain,
        )?))
    }

    fn read_state(
        state: &mut File,
        container: Container,
        cipher: &Cipher,
        key: &[u8],
        expected: Option<&crate::format::Tag>,
    ) -> Result<([u8; WORK_HEADER], Zeroizing<Vec<u8>>)> {
        let len = usize::try_from(state.metadata()?.len())?;
        ensure!(
            (WORK_HEADER + container.record_len(WORK_FIELDS)
                ..=WORK_HEADER + container.record_len(MAX_WORK))
                .contains(&len),
            "Invalid workspace length"
        );
        let mut header = [0; WORK_HEADER];
        state.read_exact(&mut header)?;
        ensure!(
            &header[..8] == cipher.workspace_magic() && header[8..24] == container.id,
            "Foreign workspace"
        );
        let session = header[24..40].try_into()?;
        let keys = work_keys(cipher, key, container.id, session)?;
        let mut body = vec![0; len - WORK_HEADER];
        state.read_exact(&mut body)?;
        ensure!(state.read(&mut [0])? == 0, "Trailing workspace bytes");
        if let Some(tag) = expected {
            check_tag(&body, tag)?;
        }
        let plain = cipher.unseal(&keys, &header, container.iv, &body)?;
        ensure!(plain.len() >= WORK_FIELDS, "Invalid workspace");
        Ok((header, plain))
    }

    fn decode_snapshot(
        dir: &File,
        container: Container,
        session: Id,
        plain: &[u8],
    ) -> Result<(Self, Tree)> {
        let base = plain[..16].try_into()?;
        let flags = plain[16];
        ensure!(flags & !11 == 0, "Invalid workspace flags");
        let target = match flags & 1 {
            0 if plain[17..33] == [0; 16] => None,
            1 => Some(plain[17..33].try_into()?),
            _ => anyhow::bail!("Invalid workspace revision"),
        };
        let index_len = u32::from_le_bytes(plain[33..37].try_into()?) as usize;
        ensure!(
            index_len <= plain.len() - WORK_FIELDS,
            "Invalid work index length"
        );
        let index_end = WORK_FIELDS + index_len;
        let tree = Tree::decode(&plain[WORK_FIELDS..index_end])?;
        let files = tree.nodes.iter().filter(|(_, node)| !node.dir);
        let generation_bytes = files.clone().count() * 16;
        let block_count: usize = files.clone().map(|(_, node)| node.tags.len()).sum();
        let rest = &plain[index_end..];
        let (rest, patches) = if flags & 8 != 0 {
            let count = generation_bytes + block_count * 8;
            ensure!(rest.len() > count, "Missing small writes");
            let (locations, extra) = rest.split_at(count);
            (locations, Patch::restore(&tree, extra)?)
        } else {
            (rest, Vec::new())
        };
        ensure!(
            rest.len() == generation_bytes || rest.len() == generation_bytes + block_count * 8,
            "Invalid workspace layout"
        );
        let (generations, mut offsets) = rest.split_at(generation_bytes);
        let files = files
            .zip(generations.chunks_exact(16))
            .map(|((&id, node), generation)| {
                let mut file = WorkFile::contiguous(
                    generation.try_into().unwrap(),
                    node.tags.len(),
                    container,
                );
                if !offsets.is_empty() {
                    for offset in &mut file.offsets {
                        let (encoded, rest) = offsets.split_at(8);
                        *offset = u64::from_le_bytes(encoded.try_into().unwrap());
                        offsets = rest;
                    }
                }
                (id, file)
            })
            .collect();
        Ok((
            Self {
                dir: dir.try_clone()?,
                session,
                base,
                target,
                dirty: flags & 2 != 0,
                files,
                journal: None,
                patches,
            },
            tree,
        ))
    }

    fn save(
        &mut self,
        container: Container,
        cipher: &Cipher,
        key: &[u8],
        tree: &Tree,
    ) -> Result<()> {
        let encoded = tree.encode()?;
        let mut plain = Zeroizing::new(Vec::with_capacity(
            WORK_FIELDS
                + encoded.len()
                + self.files.len() * 16
                + self
                    .files
                    .values()
                    .map(|file| file.offsets.len() * 8)
                    .sum::<usize>(),
        ));
        plain.extend_from_slice(&self.base);
        plain.push(
            u8::from(self.target.is_some())
                | (u8::from(self.dirty) << 1)
                | (u8::from(!self.patches.is_empty()) << 3),
        );
        plain.extend_from_slice(&self.target.unwrap_or([0; 16]));
        plain.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        plain.extend_from_slice(&encoded);
        for file in self.files.values() {
            plain.extend_from_slice(&file.generation);
        }
        for file in self.files.values() {
            for offset in &file.offsets {
                plain.extend_from_slice(&offset.to_le_bytes());
            }
        }
        for patch in &self.patches {
            plain.extend(patch.id.to_le_bytes());
            patch.encode(&mut plain);
        }
        self.write_state(container, cipher, key, &plain)?;
        self.forget_checkpoint();
        Ok(())
    }

    fn write_state(
        &self,
        container: Container,
        cipher: &Cipher,
        key: &[u8],
        plain: &[u8],
    ) -> Result<()> {
        let mut header = [0; WORK_HEADER];
        header[..8].copy_from_slice(cipher.workspace_magic());
        header[8..24].copy_from_slice(&container.id);
        header[24..].copy_from_slice(&self.session);
        let keys = work_keys(cipher, key, container.id, self.session)?;
        let body = cipher.seal(&keys, &header, plain)?;
        atomic_write(&self.dir, "state", false, |file| {
            file.write_all(&header)?;
            file.write_all(&body)?;
            Ok(())
        })
    }

    fn prune(&self) -> Result<()> {
        let mut keep = HashSet::from(["state".to_owned()]);
        keep.extend(
            self.files
                .iter()
                .map(|(&id, file)| work_file(id, file.generation)),
        );
        self.keep_checkpoint(&mut keep);
        clean_files(&self.dir, &keep)
    }

    fn open_file(&self, id: u64, flags: i32) -> Result<File> {
        let file = self.files.get(&id).context("Missing working file")?;
        let name = work_file(id, file.generation);
        let file = safe_path::beneath(&self.dir, &name, flags | libc::O_NONBLOCK, 0)?;
        ensure!(file.metadata()?.is_file(), "Invalid work file");
        Ok(file)
    }

    fn transfer(
        &self,
        dest: Option<&mut File>,
        container: Container,
        cipher: &Cipher,
        key: &[u8],
        id: u64,
        node: &Node,
    ) -> Result<()> {
        if node.tags.is_empty() {
            return Ok(());
        }
        let mut source = self.open_file(id, libc::O_RDONLY)?;
        transfer(
            &mut source,
            dest,
            container,
            cipher,
            key,
            (id, node),
            Some(&self.files[&id].offsets),
        )
    }

    fn create(&self, id: u64, generation: Id) -> Result<File> {
        create_file(&self.dir, &work_file(id, generation))
    }
}

struct CachedBlock {
    id: u64,
    block: u64,
    record: Vec<u8>,
    plain: Zeroizing<Vec<u8>>,
}

struct DirtyBlock {
    data: Zeroizing<Vec<u8>>,
    changed: std::ops::Range<usize>,
}
struct Totals {
    used: u64,
    index: usize,
}
impl Totals {
    fn from_tree(tree: &Tree) -> Self {
        Self {
            used: tree.used(),
            index: tree.encoded_len(),
        }
    }
}

pub struct Store {
    pub tree: Tree,
    pub poisoned: bool,
    cipher: Cipher,
    key: Zeroizing<Vec<u8>>,
    container: Container,
    location: Location,
    work: Workspace,
    cache: RefCell<VecDeque<CachedBlock>>,
    pending: BTreeMap<(u64, u64), DirtyBlock>,
    totals: Totals,
}

impl Store {
    pub fn init(path: &Path, cipher: &Cipher, key: &[u8], quota: u64) -> Result<()> {
        let location = Location::lock(path)?;
        let container = Container::new(cipher, key)?;
        atomic_write(&location.dir, &location.name, true, |file| {
            container.write_index(file, cipher, key, &Tree::empty(quota))
        })
    }

    pub fn check(path: &Path, cipher: &Cipher, key: &[u8]) -> Result<(usize, u64, u64)> {
        let location = Location::lock(path)?;
        let (mut file, container, tree) = location.read(cipher, key)?;
        verify(&mut file, container, cipher, key, &tree)?;
        Ok((tree.nodes.len(), tree.used(), tree.quota))
    }

    pub fn open(path: &Path, cipher: Cipher, key: Zeroizing<Vec<u8>>) -> Result<Self> {
        let location = Location::lock(path)?;
        let (mut file, container, sealed_tree) = location.read(&cipher, &key)?;
        let mut dir = location.work_dir()?;
        if let Some((mut work, tree)) = Workspace::load(&dir, container, &cipher, &key)? {
            if work.target == Some(container.revision) {
                verify(&mut file, container, &cipher, &key, &sealed_tree)?;
                location.clean_work(&dir)?;
                dir = location.work_dir()?;
                file.rewind()?;
                Container::read_index(&mut file, &cipher, &key)?;
            } else {
                ensure!(
                    work.base == container.revision,
                    "Container revision conflicts with workspace"
                );
                verify(&mut file, container, &cipher, &key, &sealed_tree)?;
                for (&id, node) in tree.nodes.iter().filter(|(_, node)| !node.dir) {
                    work.transfer(None, container, &cipher, &key, id, node)?;
                }
                work.dirty |= tree != sealed_tree;
                if work.target.take().is_some() {
                    work.save(container, &cipher, &key, &tree)?;
                }
                work.prune()?;
                return Ok(Self {
                    totals: Totals::from_tree(&tree),
                    tree,
                    poisoned: false,
                    cipher,
                    key,
                    container,
                    location,
                    work,
                    cache: RefCell::default(),
                    pending: BTreeMap::new(),
                });
            }
        }

        clean_files(&dir, &HashSet::new())?;
        let mut work = Workspace {
            dir,
            session: random()?,
            base: container.revision,
            target: None,
            dirty: false,
            files: BTreeMap::new(),
            patches: Vec::new(),
            journal: None,
        };
        let unpack = (|| -> Result<()> {
            for (&id, node) in sealed_tree.nodes.iter().filter(|(_, node)| !node.dir) {
                let generation = random()?;
                if node.size == 0 {
                    work.files
                        .insert(id, WorkFile::contiguous(generation, 0, container));
                    continue;
                }
                let mut output = work.create(id, generation)?;
                transfer(
                    &mut file,
                    Some(&mut output),
                    container,
                    &cipher,
                    &key,
                    (id, node),
                    None,
                )?;
                output.sync_all()?;
                work.files.insert(
                    id,
                    WorkFile::contiguous(generation, node.tags.len(), container),
                );
            }
            work.dir.sync_all()?;
            work.save(container, &cipher, &key, &sealed_tree)
        })();
        if let Err(error) = unpack {
            let _ = location.clean_work(&work.dir);
            return Err(error);
        }
        Ok(Self {
            totals: Totals::from_tree(&sealed_tree),
            tree: sealed_tree,
            poisoned: false,
            cipher,
            key,
            container,
            location,
            work,
            cache: RefCell::default(),
            pending: BTreeMap::new(),
        })
    }

    fn commit_edits(&mut self, changes: Vec<Edit>) -> Result<()> {
        ensure!(!self.poisoned, "Workspace requires recovery");
        let result = (|| -> Result<()> {
            let encoded = self.work.encode_edits(&changes, self.totals.index);
            let count = changes.len();
            for change in changes {
                match &change {
                    Edit::Remove(id) => self.cache.get_mut().retain(|e| e.id != *id),
                    Edit::Blocks {
                        id,
                        size,
                        first,
                        records,
                        ..
                    } => self.cache.get_mut().retain(|e| {
                        e.id != *id
                            || (e.block < size.div_ceil(BLOCK)
                                && !(*first..first + records.len()).contains(&(e.block as usize)))
                    }),
                    _ => {}
                }
                change.apply(
                    &mut self.tree,
                    &mut self.work.files,
                    &mut self.work.patches,
                    &mut self.totals,
                )?;
            }
            self.work.dirty = true;
            if let Some(encoded) = encoded {
                self.work
                    .save_edits(self.container, &self.cipher, &self.key, &encoded, count)?;
            } else {
                self.work
                    .save(self.container, &self.cipher, &self.key, &self.tree)?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub fn add_node(&mut self, parent: u64, name: String, dir: bool) -> Result<u64> {
        let id = self.tree.next;
        let generation = if dir {
            None
        } else {
            let generation = random()?;
            // Publishing the namespace syncs this directory. An empty inode can
            // also be recreated on recovery if a crash interrupted creation.
            self.work.create(id, generation)?;
            Some(generation)
        };
        self.commit_edits(vec![Edit::Create {
            id,
            parent,
            name,
            generation,
        }])?;
        Ok(id)
    }

    pub fn move_or_remove(
        &mut self,
        remove: Option<u64>,
        rename: Option<(u64, u64, String)>,
    ) -> Result<()> {
        let mut changes = Vec::new();
        let obsolete = remove.and_then(|id| {
            self.work
                .files
                .get(&id)
                .map(|f| work_file(id, f.generation))
        });
        if let Some(id) = remove {
            changes.push(Edit::Remove(id));
        }
        if let Some((id, parent, name)) = rename {
            changes.push(Edit::Rename { id, parent, name });
        }
        self.commit_edits(changes)?;
        if let Some(name) = obsolete {
            let _ = unlink_if_present(&self.work.dir, &name);
        }
        Ok(())
    }

    pub fn read(&self, id: u64, offset: u64, requested: u32) -> Result<Zeroizing<Vec<u8>>> {
        let node = &self.tree.nodes[&id];
        let end = offset
            .saturating_add(u64::from(requested))
            .min(self.visible_size(id));
        let mut output = Zeroizing::new(Vec::with_capacity(end.saturating_sub(offset) as usize));
        if offset >= end {
            return Ok(output);
        }
        let mut file = None;
        let mut keys = None;
        let offsets = &self.work.files[&id].offsets;
        let mut position = offset;
        while position < end {
            let block = position / BLOCK;
            let start = (position % BLOCK) as usize;
            if let Some(dirty) = self.pending.get(&(id, block)) {
                let bytes = &dirty.data;
                let take = (end - position).min((bytes.len() - start) as u64) as usize;
                output.extend_from_slice(&bytes[start..start + take]);
                position += take as u64;
                continue;
            }
            let file = match &mut file {
                Some(f) => f,
                None => file.insert(self.work.open_file(id, libc::O_RDONLY)?),
            };
            file.seek(SeekFrom::Start(offsets[block as usize]))?;
            let len = block_len(node.size, block);
            let record = read_record(file, self.container.record_len(len))?;
            let start = (position % BLOCK) as usize;
            let take = (end - position).min((len - start) as u64) as usize;
            self.with_block(id, block, node, &mut keys, record, |plain| {
                output.extend_from_slice(&plain[start..start + take]);
            })?;
            position += take as u64;
        }
        Ok(output)
    }

    pub fn visible_size(&self, id: u64) -> u64 {
        let end = self
            .pending
            .range((id, 0)..=(id, u64::MAX))
            .next_back()
            .map_or(0, |(&(_, block), data)| {
                block * BLOCK + data.data.len() as u64
            });
        self.tree.nodes[&id].size.max(end)
    }

    // The dirty set has at most CACHE_BLOCKS entries, independent of tree size.
    pub fn visible_totals(&self) -> (u64, usize) {
        let mut used = self.totals.used;
        let mut index = self.totals.index;
        let mut previous = None;
        for &(id, _) in self.pending.keys() {
            if previous != Some(id) {
                let size = self.visible_size(id);
                let node = &self.tree.nodes[&id];
                used += size - node.size;
                index += (size.div_ceil(BLOCK) as usize - node.tags.len()) * 32;
                previous = Some(id);
            }
        }
        (used, index)
    }

    pub fn flush_pending(&mut self, id: Option<u64>) -> Result<()> {
        ensure!(!self.poisoned, "Workspace requires recovery");
        loop {
            let first = match id {
                Some(id) => self.pending.range((id, 0)..=(id, u64::MAX)).next(),
                None => self.pending.first_key_value(),
            };
            let Some((&(ino, block), first)) = first else {
                return Ok(());
            };
            let changed = first.changed.clone();
            let offset = block * BLOCK + changed.start as u64;
            let size = self.tree.nodes[&ino].size;
            if changed.len() <= PATCH_SIZE
                && offset + changed.len() as u64 <= size
                && first.data.len() > PATCH_SIZE
            {
                let patch = Patch {
                    id: ino,
                    offset,
                    data: Zeroizing::new(first.data[changed].to_vec()),
                };
                self.persist_patch(patch)?;
                self.pending.remove(&(ino, block));
                continue;
            }
            let mut end = block;
            let mut len = 0;
            for (&(_, n), dirty) in self.pending.range((ino, block)..=(ino, u64::MAX)) {
                if n != end {
                    break;
                }
                end += 1;
                len += dirty.data.len();
            }
            let mut batch = Zeroizing::new(Vec::with_capacity(len));
            for (_, dirty) in self.pending.range((ino, block)..(ino, end)) {
                batch.extend_from_slice(&dirty.data);
            }
            let offset = block * BLOCK;
            let size = self.tree.nodes[&ino].size.max(offset + batch.len() as u64);
            self.update(ino, size, offset, &batch)?;
            for n in block..end {
                self.pending.remove(&(ino, n));
            }
        }
    }

    pub fn write_span(&mut self, id: u64, offset: u64, data: &[u8], sync: bool) -> Result<usize> {
        ensure!(!self.poisoned, "Workspace requires recovery");
        if data.is_empty() {
            return Ok(0);
        }
        if data.len() >= 64_000 {
            self.cipher.prepare_worker();
        }
        let end = offset
            .checked_add(data.len() as u64)
            .context("Write offset overflow")?;
        if sync
            && data.len() <= PATCH_SIZE
            && end <= self.tree.nodes[&id].size
            && offset / BLOCK == (end - 1) / BLOCK
            && block_len(self.tree.nodes[&id].size, offset / BLOCK) > PATCH_SIZE
        {
            self.flush_pending(Some(id))?;
            self.read(id, offset, data.len() as u32)?;
            self.persist_patch(Patch {
                id,
                offset,
                data: Zeroizing::new(data.to_vec()),
            })?;
            return Ok(data.len());
        }
        if sync || offset > self.visible_size(id) {
            self.flush_pending(Some(id))?;
            self.update(id, self.tree.nodes[&id].size.max(end), offset, data)?;
            return Ok(data.len());
        }
        // A large aligned FUSE request already supplies a batch. It can go
        // straight to the writer when this inode has no buffered changes.
        if offset.is_multiple_of(BLOCK)
            && data.len() >= 2 * BLOCK as usize
            && self
                .pending
                .range((id, 0)..=(id, u64::MAX))
                .next()
                .is_none()
        {
            let len = (data.len() / BLOCK as usize).min(CACHE_BLOCKS) * BLOCK as usize;
            self.update(
                id,
                self.tree.nodes[&id].size.max(offset + len as u64),
                offset,
                &data[..len],
            )?;
            return Ok(len);
        }
        let block = offset / BLOCK;
        let start = (offset % BLOCK) as usize;
        let count = data.len().min(BLOCK as usize - start);
        if !self.pending.contains_key(&(id, block)) {
            if self.pending.len() == CACHE_BLOCKS {
                let (&(evict, _), _) = self.pending.first_key_value().unwrap();
                self.flush_pending(Some(evict))?;
            }
            let position = block * BLOCK;
            let old_len = self.tree.nodes[&id]
                .size
                .saturating_sub(position)
                .min(BLOCK) as usize;
            let bytes = if old_len != 0 && (start != 0 || count < old_len) {
                self.read(id, position, old_len as u32)?
            } else {
                Zeroizing::new(Vec::new())
            };

            self.pending.insert(
                (id, block),
                DirtyBlock {
                    data: bytes,
                    changed: start..start + count,
                },
            );
        }
        let dirty = self.pending.get_mut(&(id, block)).unwrap();
        dirty.changed = dirty.changed.start.min(start)..dirty.changed.end.max(start + count);
        let bytes = &mut dirty.data;
        if start + count > bytes.capacity() {
            let capacity = (bytes.capacity() * 2)
                .max(start + count)
                .min(BLOCK as usize);
            let extra = capacity - bytes.len();
            bytes.reserve_exact(extra);
        }
        if start + count > bytes.len() {
            bytes.resize(start + count, 0);
        }
        bytes[start..start + count].copy_from_slice(&data[..count]);
        Ok(count)
    }

    fn persist_patch(&mut self, patch: Patch) -> Result<()> {
        while Patch::usage(&self.work.patches) + 19 + patch.data.len() > PATCH_LIMIT {
            self.materialize_patch()?;
        }
        self.commit_edits(vec![Edit::Patch(patch)])
    }

    fn materialize_patch(&mut self) -> Result<()> {
        let first = &self.work.patches[0];
        let id = first.id;
        let block = first.offset / BLOCK;
        let node = &self.tree.nodes[&id];
        let size = node.size;
        let mut file = self.work.open_file(id, libc::O_RDONLY)?;
        file.seek(SeekFrom::Start(
            self.work.files[&id].offsets[block as usize],
        ))?;
        let record = read_record(&mut file, self.container.record_len(block_len(size, block)))?;
        let plain = self.with_block(id, block, node, &mut None, record, |p| {
            Zeroizing::new(p.to_vec())
        })?;
        self.update(id, size, block * BLOCK, &plain)
    }

    fn with_block<T>(
        &self,
        id: u64,
        block: u64,
        node: &Node,
        keys: &mut Option<Zeroizing<Vec<u8>>>,
        record: Vec<u8>,
        use_plain: impl FnOnce(&[u8]) -> T,
    ) -> Result<T> {
        let len = block_len(node.size, block);
        check_tag(&record, &node.tags[block as usize])?;
        let use_plain = |base: &[u8]| {
            let mut patches = self
                .work
                .patches
                .iter()
                .filter(|p| p.id == id && p.offset / BLOCK == block)
                .peekable();
            if patches.peek().is_none() {
                return use_plain(base);
            }
            let mut bytes = Zeroizing::new(base.to_vec());
            for p in patches {
                let start = (p.offset % BLOCK) as usize;
                bytes[start..start + p.data.len()].copy_from_slice(&p.data);
            }
            use_plain(&bytes)
        };
        // The disk bytes must match the previously authenticated record in full.
        if let Some(cached) = self
            .cache
            .borrow()
            .iter()
            .find(|cached| cached.id == id && cached.block == block && cached.record == record)
        {
            return Ok(use_plain(&cached.plain));
        }
        let context = self.container.block_context(id, block, len);
        let keys = match keys {
            Some(keys) => keys,
            None => keys.insert(self.container.file_keys(&self.cipher, &self.key, id)?),
        };
        let plain = self
            .cipher
            .unseal(keys, &context, self.container.iv, &record)?;
        ensure!(plain.len() == len, "Invalid block plaintext length");
        let result = use_plain(&plain);
        let mut cache = self.cache.borrow_mut();
        cache.retain(|entry| entry.id != id || entry.block != block);
        if cache.len() == CACHE_BLOCKS {
            cache.pop_front();
        }
        cache.push_back(CachedBlock {
            id,
            block,
            record,
            plain,
        });
        Ok(result)
    }

    pub fn update(&mut self, id: u64, size: u64, offset: u64, data: &[u8]) -> Result<()> {
        ensure!(
            !self.poisoned,
            "Workspace is in failed state; reopen the container"
        );
        let old = &self.tree.nodes[&id];
        if data.is_empty() && size == old.size {
            return Ok(());
        }
        let write_end = offset
            .checked_add(data.len() as u64)
            .context("Write offset overflow")?;
        ensure!(
            data.is_empty() || write_end <= size,
            "Write exceeds file size"
        );
        let blocks = size.div_ceil(BLOCK);
        ensure!(
            size <= self.tree.quota - (self.totals.used - old.size)
                && blocks <= ((MAX_INDEX - (self.totals.index - old.tags.len() * 32)) / 32) as u64,
            "Quota or index limit exceeded"
        );
        let current = &self.work.files[&id];
        let old_generation = current.generation;
        let mut created = false;
        let mut src = match self.work.open_file(id, libc::O_RDWR) {
            Ok(file) => file,
            Err(error)
                if old.size == 0
                    && error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
            {
                created = true;
                self.work.create(id, old_generation)?
            }
            Err(error) => return Err(error),
        };
        let physical = src.metadata()?.len();
        let live = self.container.file_len(size);
        let compact = physical > live.saturating_add(live.max(COMPACT_SLACK));
        let (generation, mut dst) = if compact {
            let generation = random()?;
            (generation, self.work.create(id, generation)?)
        } else {
            (old_generation, src.try_clone()?)
        };
        let mut tail = if compact { 0 } else { physical };
        // Growth materializes holes and the old partial tail. Shrinking only
        // rewrites the new final partial block. Compaction copies every live block.
        let (first, end) = if compact {
            (0, blocks)
        } else if size < old.size && data.is_empty() {
            (size / BLOCK, blocks)
        } else if size > old.size {
            (
                (if data.is_empty() {
                    old.size
                } else {
                    offset.min(old.size)
                }) / BLOCK,
                blocks,
            )
        } else {
            (offset / BLOCK, write_end.div_ceil(BLOCK))
        };
        let mut keys = Some(self.container.file_keys(&self.cipher, &self.key, id)?);
        let write_result = (|| -> Result<_> {
            let mut records = Vec::new();
            let mut pending = None;
            let mut write_record = |record: Vec<u8>| -> Result<()> {
                if !compact {
                    tail = tail
                        .checked_add(ALIGNMENT - 1)
                        .context("File offset overflow")?
                        & !(ALIGNMENT - 1);
                }
                dst.seek(SeekFrom::Start(tail))?;
                dst.write_all(&record)?;
                records.push((record[record.len() - 32..].try_into()?, tail));
                tail = tail
                    .checked_add(record.len() as u64)
                    .context("File offset overflow")?;
                Ok(())
            };
            for block in first..end {
                let position = block * BLOCK;
                let len = block_len(size, block);
                let old_len = old.size.saturating_sub(position).min(BLOCK) as usize;
                let begin = offset.max(position);
                let stop = write_end.min(position + len as u64);
                let retained = len == old_len
                    && begin >= stop
                    && !self
                        .work
                        .patches
                        .iter()
                        .any(|p| p.id == id && p.offset / BLOCK == block);
                let preserve =
                    old_len > 0 && (begin != position || stop < position + old_len.min(len) as u64);
                let previous = if retained || preserve {
                    src.seek(SeekFrom::Start(current.offsets[block as usize]))?;
                    Some(read_record(&mut src, self.container.record_len(old_len))?)
                } else {
                    None
                };
                let record = if retained {
                    let record = previous.unwrap();
                    check_tag(&record, &old.tags[block as usize])?;
                    record
                } else {
                    let mut plain = match previous {
                        Some(record) => {
                            self.with_block(id, block, old, &mut keys, record, |p| {
                                Zeroizing::new(p.to_vec())
                            })?
                        }
                        None => Zeroizing::new(Vec::new()),
                    };
                    plain.resize(len, 0);
                    if begin < stop {
                        plain[(begin - position) as usize..(stop - position) as usize]
                            .copy_from_slice(
                                &data[(begin - offset) as usize..(stop - offset) as usize],
                            );
                    }
                    let context = self.container.block_context(id, block, len);
                    if pending.is_none() && block + 1 < end {
                        pending = Some(self.cipher.seal_async(
                            keys.as_ref().unwrap(),
                            context,
                            plain,
                        )?);
                        continue;
                    }
                    self.cipher.seal(keys.as_ref().unwrap(), &context, &plain)?
                };
                if let Some(result) = pending.take() {
                    write_record(result.recv().context("Encryption worker stopped")??)?;
                }
                write_record(record)?;
            }
            if compact || tail != physical {
                dst.sync_all()?;
            }
            if compact || created {
                self.work.dir.sync_all()?;
            }
            Ok(Edit::Blocks {
                id,
                size,
                generation,
                first: first as usize,
                records,
            })
        })();
        let result = write_result.and_then(|change| self.commit_edits(vec![change]));
        if compact {
            if result.is_ok() {
                let _ = unlink_if_present(&self.work.dir, &work_file(id, old_generation));
            } else if !self.poisoned {
                let _ = unlink_if_present(&self.work.dir, &work_file(id, generation));
            }
        }

        result
    }

    pub fn close(&mut self) -> Result<()> {
        self.flush_pending(None)?;
        while !self.work.patches.is_empty() {
            self.materialize_patch()?;
        }
        if self.work.dirty {
            let target = self.work.target.unwrap_or(random()?);
            self.work.target = Some(target);
            self.work
                .save(self.container, &self.cipher, &self.key, &self.tree)?;
            let next = Container {
                revision: target,
                ..self.container
            };
            atomic_write(&self.work.dir, "packed", false, |file| {
                next.write_index(file, &self.cipher, &self.key, &self.tree)?;
                for (&id, node) in self.tree.nodes.iter().filter(|(_, node)| !node.dir) {
                    self.work
                        .transfer(Some(file), next, &self.cipher, &self.key, id, node)?;
                }
                Ok(())
            })?;
            let mut packed = read_file(&self.work.dir, "packed")?;
            let (header, index) = Container::read_index(&mut packed, &self.cipher, &self.key)?;
            ensure!(
                header.id == next.id && header.revision == next.revision && index == self.tree,
                "Unexpected packed container"
            );
            verify(&mut packed, header, &self.cipher, &self.key, &index)?;
            let (_, current, _) = self.location.read(&self.cipher, &self.key)?;
            ensure!(
                current.id == self.container.id && current.revision == self.work.base,
                "Container revision changed during session"
            );
            rename(
                &self.work.dir,
                "packed",
                &self.location.dir,
                &self.location.name,
                false,
            )?;
            self.location.dir.sync_all()?;
            self.work.dir.sync_all()?;
        }
        self.location.clean_work(&self.work.dir)
    }
}

fn verify(
    file: &mut File,
    container: Container,
    cipher: &Cipher,
    key: &[u8],
    tree: &Tree,
) -> Result<()> {
    for (&id, node) in tree.nodes.iter().filter(|(_, node)| !node.dir) {
        transfer(file, None, container, cipher, key, (id, node), None)?;
    }
    Ok(())
}

fn transfer(
    source: &mut File,
    mut dest: Option<&mut File>,
    container: Container,
    cipher: &Cipher,
    key: &[u8],
    (id, node): (u64, &Node),
    offsets: Option<&[u64]>,
) -> Result<()> {
    if node.tags.is_empty() {
        return Ok(());
    }
    // Packing verifies the complete destination before it can replace the container.
    let keys = if offsets.is_some() && dest.is_some() {
        None
    } else {
        Some(container.file_keys(cipher, key, id)?)
    };
    let mut record = Vec::new();
    for (block, tag) in node.tags.iter().enumerate() {
        let len = block_len(node.size, block as u64);
        record.resize(container.record_len(len), 0);
        if let Some(offsets) = offsets {
            source.seek(SeekFrom::Start(offsets[block]))?;
        }
        source.read_exact(&mut record)?;
        check_tag(&record, tag)?;
        if let Some(keys) = &keys {
            cipher.authenticate(
                keys,
                &container.block_context(id, block as u64, len),
                &record,
            )?;
        }
        if let Some(file) = dest.as_deref_mut() {
            file.write_all(&record)?;
        }
    }
    Ok(())
}

fn work_keys(cipher: &Cipher, key: &[u8], id: Id, session: Id) -> Result<Zeroizing<Vec<u8>>> {
    let mut seed = [0; 32];
    seed[..16].copy_from_slice(&id);
    seed[16..].copy_from_slice(&session);
    cipher.derive(key, b"vault-lab/v2/work-index", &seed)
}

fn read_record(file: &mut File, len: usize) -> Result<Vec<u8>> {
    let mut data = vec![0; len];
    file.read_exact(&mut data)?;
    Ok(data)
}

fn work_file(id: u64, generation: Id) -> String {
    format!("{id:016x}-{}", hex::encode(generation))
}

fn read_file(dir: &File, name: &str) -> io::Result<File> {
    let file = safe_path::beneath(dir, name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected regular file",
        ));
    }
    Ok(file)
}

fn create_file(dir: &File, name: &str) -> Result<File> {
    Ok(safe_path::beneath(
        dir,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?)
}

fn rename(source: &File, old: &str, dest: &File, new: &str, no_replace: bool) -> Result<()> {
    let old = CString::new(old)?;
    let new = CString::new(new)?;
    let flags = if no_replace {
        libc::RENAME_NOREPLACE
    } else {
        0
    };
    let result = unsafe {
        libc::renameat2(
            source.as_raw_fd(),
            old.as_ptr(),
            dest.as_raw_fd(),
            new.as_ptr(),
            flags,
        )
    };
    ensure!(
        result == 0,
        "Atomic replacement: {}",
        io::Error::last_os_error()
    );
    Ok(())
}

fn unlink(dir: &File, name: &str, flags: i32) -> io::Result<()> {
    let name = CString::new(name)?;
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn unlink_if_present(dir: &File, name: &str) -> io::Result<()> {
    match unlink(dir, name, 0) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn clean_files(dir: &File, keep: &HashSet<String>) -> Result<()> {
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
        let name = entry?.file_name();
        let name = name.to_str().context("Invalid workspace file name")?;
        if !keep.contains(name) {
            let is_hex = |bytes: &[u8]| bytes.iter().all(u8::is_ascii_hexdigit);
            let bytes = name.as_bytes();
            ensure!(
                name == "packed"
                    || (bytes.len() == 43
                        && name.starts_with("checkpoint-")
                        && is_hex(&bytes[11..]))
                    || (bytes.len() == 49
                        && bytes[16] == b'-'
                        && is_hex(&bytes[..16])
                        && is_hex(&bytes[17..]))
                    || (bytes.len() == 40 && name.starts_with("pending-") && is_hex(&bytes[8..])),
                "Unexpected workspace file {name}"
            );
            unlink_if_present(dir, name)?;
        }
    }
    Ok(())
}

fn atomic_write(
    dir: &File,
    name: &str,
    no_replace: bool,
    write: impl FnOnce(&mut File) -> Result<()>,
) -> Result<()> {
    let temporary = format!("pending-{}", hex::encode(random::<16>()?));
    let mut file = create_file(dir, &temporary)?;
    let result = (|| -> Result<()> {
        write(&mut file)?;
        file.sync_all()?;
        rename(dir, &temporary, dir, name, no_replace)?;
        dir.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = unlink_if_present(dir, &temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];

    fn cipher() -> Cipher {
        Cipher::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("lib/libaldcrypto.so")).unwrap()
    }

    fn open(path: &Path) -> Store {
        Store::open(path, cipher(), Zeroizing::new(KEY.to_vec())).unwrap()
    }

    fn add_file(store: &mut Store) {
        store.add_node(1, "secret.txt".into(), false).unwrap();
    }

    #[test]
    fn workspace_recovery_and_ciphertext_transfer() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.sbox");
        let plugin = cipher();
        Store::init(&path, &plugin, &KEY, 1_000_000_000).unwrap();
        let initial = std::fs::read(&path).unwrap();
        assert!(initial.starts_with(b"VLAGOST2"));
        assert!(Store::init(&path, &plugin, &KEY, 1).is_err());
        let mut store = open(&path);
        assert!(Store::check(&path, &plugin, &KEY).is_err());
        add_file(&mut store);
        let original = b"original confidential payload";
        store.update(2, BLOCK + 2, BLOCK - 2, b"last").unwrap();
        assert_eq!(store.read(2, BLOCK - 3, 5).unwrap().as_slice(), b"\0last");
        let first_name = work_file(2, store.work.files[&2].generation);
        let workspace = tmp.path().join(".vault.sbox.work");
        let first_generation = std::fs::read(workspace.join(first_name)).unwrap();
        store.update(2, BLOCK + 2, 17, original).unwrap();
        let file = &store.work.files[&2];
        let work_path = workspace.join(work_file(2, file.generation));
        let physical = std::fs::read(&work_path).unwrap();
        assert!(physical.starts_with(&first_generation));
        assert!(
            !physical
                .windows(original.len())
                .any(|part| part == original)
        );
        let working: Vec<u8> = file
            .offsets
            .iter()
            .enumerate()
            .flat_map(|(block, &offset)| {
                let len = store
                    .container
                    .record_len(block_len(BLOCK + 2, block as u64));
                physical[offset as usize..offset as usize + len]
                    .iter()
                    .copied()
            })
            .collect();
        // A crash can leave bytes beyond the last indexed record.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&work_path)
            .unwrap()
            .set_len(physical.len() as u64 + COMPACT_SLACK * 2)
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), initial);

        store.work.target = Some(random().unwrap());
        store
            .work
            .save(store.container, &store.cipher, &store.key, &store.tree)
            .unwrap();
        drop(store);

        let mut store = open(&path);
        assert_eq!(
            store.read(2, 17, original.len() as u32).unwrap().as_slice(),
            original
        );
        assert_eq!(store.read(2, BLOCK - 2, 4).unwrap().as_slice(), b"last");
        store.close().unwrap();
        drop(store);
        assert!(!workspace.exists());
        let sealed = std::fs::read(&path).unwrap();
        assert!(sealed.ends_with(&working));
        assert_eq!(
            Store::check(&path, &plugin, &KEY).unwrap(),
            (2, BLOCK + 2, 1_000_000_000)
        );
        assert!(Store::check(&path, &plugin, &[0x43; 32]).is_err());

        let mut substituted = sealed.clone();
        let record_at = sealed.len() - working.len();
        let block_record_len = sealed_cipher_record_len(&sealed, BLOCK as usize);
        substituted[record_at..record_at + block_record_len]
            .copy_from_slice(&first_generation[..block_record_len]);
        std::fs::write(&path, substituted).unwrap();
        assert!(Store::check(&path, &plugin, &KEY).is_err());
        std::fs::write(&path, &sealed).unwrap();

        let mut store = open(&path);
        let generation = store.work.files[&2].generation;
        store
            .work
            .open_file(2, libc::O_WRONLY)
            .unwrap()
            .set_len(COMPACT_SLACK * 2)
            .unwrap();
        store.update(2, 19, 0, &[]).unwrap();
        assert_ne!(store.work.files[&2].generation, generation);
        assert_eq!(&store.read(2, 17, 9).unwrap()[..], &original[..2]);
        store.update(2, 21, 19, b"OK").unwrap();
        assert_eq!(&store.read(2, 17, 4).unwrap()[..], b"orOK");
        store.close().unwrap();
        drop(store);

        let current = std::fs::read(&path).unwrap();
        let mut damaged = current.clone();
        let last_byte = damaged.last_mut().unwrap();
        *last_byte ^= 1;
        std::fs::write(&path, damaged).unwrap();
        assert!(Store::check(&path, &plugin, &KEY).is_err());
        let mut extra = current;
        extra.push(0);
        std::fs::write(&path, extra).unwrap();
        assert!(Store::check(&path, &plugin, &KEY).is_err());
    }

    fn sealed_cipher_record_len(container: &[u8], len: usize) -> usize {
        let iv = u32::from_le_bytes(container[40..44].try_into().unwrap()) as usize;
        iv + crate::format::padded(len) + 32
    }

    #[test]
    fn resumes_cleanup_after_packed_revision_was_installed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.sbox");
        let plugin = cipher();
        Store::init(&path, &plugin, &KEY, 1_000_000).unwrap();
        let mut store = open(&path);
        add_file(&mut store);
        store.update(2, 5, 0, b"saved").unwrap();
        let workspace = tmp.path().join(".vault.sbox.work");
        let blocker = workspace.join("cleanup-blocker");
        std::fs::create_dir(&blocker).unwrap();
        assert!(store.close().is_err());
        drop(store);
        assert_eq!(
            Store::check(&path, &plugin, &KEY).unwrap(),
            (2, 5, 1_000_000)
        );
        std::fs::remove_dir(blocker).unwrap();

        let mut store = open(&path);
        assert_eq!(store.read(2, 0, 5).unwrap().as_slice(), b"saved");
        store.close().unwrap();
        assert!(!workspace.exists());
    }

    #[test]
    fn cached_block_rejects_changed_ciphertext() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.sbox");
        let plugin = cipher();
        Store::init(&path, &plugin, &KEY, 1_000_000).unwrap();
        let mut store = open(&path);
        add_file(&mut store);
        store.update(2, 8, 0, b"original").unwrap();
        assert_eq!(store.read(2, 0, 8).unwrap().as_slice(), b"original");

        let path = tmp
            .path()
            .join(".vault.sbox.work")
            .join(work_file(2, store.work.files[&2].generation));
        let mut damaged = std::fs::read(&path).unwrap();
        damaged[store.container.iv] ^= 1;
        std::fs::write(&path, damaged).unwrap();
        assert!(store.read(2, 0, 8).is_err());

        store.update(2, 8, 0, b"entire!\n").unwrap();
        assert_eq!(store.read(2, 0, 8).unwrap().as_slice(), b"entire!\n");
        store.close().unwrap();
    }

    #[test]
    fn xor_benchmark_roundtrip_is_separate_from_gost() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("benchmark.sbox");
        let xor = Cipher::benchmark_xor();
        Store::init(&path, &xor, &KEY, 1_000_000).unwrap();
        assert_eq!(&std::fs::read(&path).unwrap()[..8], b"VLAXOR01");
        let mut store = Store::open(&path, xor, Zeroizing::new(KEY.to_vec())).unwrap();
        add_file(&mut store);
        store.update(2, 7, 0, b"example").unwrap();
        let state = std::fs::read(tmp.path().join(".benchmark.sbox.work/state")).unwrap();
        assert_eq!(&state[..8], b"VLAXWORK");
        store.close().unwrap();
        drop(store);
        assert!(Store::check(&path, &cipher(), &KEY).is_err());

        let gost_path = tmp.path().join("regular.sbox");
        Store::init(&gost_path, &cipher(), &KEY, 1_000_000).unwrap();
        assert!(Store::check(&gost_path, &Cipher::benchmark_xor(), &KEY).is_err());

        let store =
            Store::open(&path, Cipher::benchmark_xor(), Zeroizing::new(KEY.to_vec())).unwrap();
        assert_eq!(store.read(2, 0, 7).unwrap().as_slice(), b"example");
        // Simulate a workspace saved by the version with contiguous records only.
        let state_path = tmp.path().join(".benchmark.sbox.work/state");
        let state = std::fs::read(&state_path).unwrap();
        let (header, body) = state.split_at(WORK_HEADER);
        let keys = work_keys(&store.cipher, &KEY, store.container.id, store.work.session).unwrap();
        let mut plain = store
            .cipher
            .unseal(&keys, header, store.container.iv, body)
            .unwrap();
        let legacy_len = plain.len() - 8;
        plain.truncate(legacy_len);
        let mut legacy = header.to_vec();
        legacy.extend(store.cipher.seal(&keys, header, &plain).unwrap());
        std::fs::write(&state_path, legacy).unwrap();
        drop(store);

        let mut store =
            Store::open(&path, Cipher::benchmark_xor(), Zeroizing::new(KEY.to_vec())).unwrap();
        assert_eq!(store.read(2, 0, 7).unwrap().as_slice(), b"example");
        // XOR tags are placeholders, so this update leaves the portable tree identical.
        store.update(2, 7, 0, b"updated").unwrap();
        drop(store);
        let mut store =
            Store::open(&path, Cipher::benchmark_xor(), Zeroizing::new(KEY.to_vec())).unwrap();
        store.close().unwrap();
        drop(store);
        let mut store =
            Store::open(&path, Cipher::benchmark_xor(), Zeroizing::new(KEY.to_vec())).unwrap();
        assert_eq!(store.read(2, 0, 7).unwrap().as_slice(), b"updated");
        store.close().unwrap();
    }
}

#[cfg(test)]
mod write_tests;
