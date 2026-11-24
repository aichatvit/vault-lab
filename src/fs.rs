use crate::{
    format::{BLOCK, MAX_INDEX},
    store::{Node, Store, valid_name},
};
use fuser::*;
use std::{
    collections::HashMap,
    ffi::OsStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
const TTL: Duration = Duration::ZERO;
const DIRECT_IO: u32 = 1;
pub struct VaultFs<'a> {
    store: &'a mut Store,
    uid: u32,
    gid: u32,
    opened: HashMap<u64, u32>,
    children: HashMap<u64, HashMap<String, u64>>,
}
impl<'a> VaultFs<'a> {
    pub fn new(store: &'a mut Store) -> Self {
        Self::with_owner(store, unsafe { libc::geteuid() }, unsafe {
            libc::getegid()
        })
    }
    pub fn with_owner(store: &'a mut Store, uid: u32, gid: u32) -> Self {
        let mut children = HashMap::<u64, HashMap<String, u64>>::new();
        for (&id, node) in &store.tree.nodes {
            if id != 1 {
                children
                    .entry(node.parent)
                    .or_default()
                    .insert(node.name.clone(), id);
            }
        }
        Self {
            store,
            uid,
            gid,
            opened: HashMap::new(),
            children,
        }
    }
    fn node(&self, ino: u64) -> Result<&Node, i32> {
        if self.store.poisoned {
            return Err(libc::EIO);
        }
        self.store.tree.nodes.get(&ino).ok_or(libc::ENOENT)
    }
    fn attr(&self, ino: u64) -> Result<FileAttr, i32> {
        let n = self.node(ino)?;
        let size = self.store.visible_size(ino);
        Ok(FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: if n.dir {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
            perm: if n.dir { 0o700 } else { 0o600 },
            nlink: if n.dir { 2 } else { 1 },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        })
    }
    fn find(&self, parent: u64, name: &OsStr) -> Result<u64, i32> {
        if !self.node(parent)?.dir {
            return Err(libc::ENOTDIR);
        }
        self.children
            .get(&parent)
            .and_then(|names| names.get(name.to_str()?))
            .copied()
            .ok_or(libc::ENOENT)
    }
    fn add(&mut self, parent: u64, name: &OsStr, dir: bool) -> Result<u64, i32> {
        if !self.node(parent)?.dir {
            return Err(libc::ENOTDIR);
        }
        let name = name
            .to_str()
            .filter(|s| valid_name(s))
            .ok_or(libc::EINVAL)?;
        if self.find(parent, OsStr::new(name)).is_ok() {
            return Err(libc::EEXIST);
        }
        if self.store.tree.next == u64::MAX
            || self.store.visible_totals().1 + 27 + name.len() > MAX_INDEX
        {
            return Err(libc::ENOSPC);
        }
        let id = self
            .store
            .add_node(parent, name.to_owned(), dir)
            .map_err(write_error)?;
        self.children
            .entry(parent)
            .or_default()
            .insert(name.to_owned(), id);
        Ok(id)
    }
    fn remove(&mut self, parent: u64, name: &OsStr, dir: bool) -> Result<(), i32> {
        let ino = self.find(parent, name)?;
        let n = self.node(ino)?;
        if n.dir != dir {
            return Err(if n.dir { libc::EISDIR } else { libc::ENOTDIR });
        }
        if self.opened.get(&ino).copied().unwrap_or(0) > 0 {
            return Err(libc::EBUSY);
        }
        if dir
            && self
                .children
                .get(&ino)
                .is_some_and(|names| !names.is_empty())
        {
            return Err(libc::ENOTEMPTY);
        }
        self.flush_pending(Some(ino))?;
        self.store
            .move_or_remove(Some(ino), None)
            .map_err(write_error)?;
        self.children
            .get_mut(&parent)
            .unwrap()
            .remove(name.to_str().unwrap());
        self.children.remove(&ino);
        Ok(())
    }
    fn flush_pending(&mut self, id: Option<u64>) -> Result<(), i32> {
        self.store.flush_pending(id).map_err(write_error)
    }

    fn validate_size(&self, ino: u64, size: u64) -> Result<(), i32> {
        let tree = &self.store.tree;
        let node = self.node(ino)?;
        if node.dir {
            return Err(libc::EISDIR);
        }
        let (used, index) = self.store.visible_totals();
        let visible = self.store.visible_size(ino);
        if size > tree.quota - (used - visible) {
            return Err(libc::EFBIG);
        }
        let remaining = MAX_INDEX - (index - visible.div_ceil(BLOCK) as usize * 32);
        if size.div_ceil(BLOCK) > (remaining / 32) as u64 {
            return Err(libc::ENOSPC);
        }
        Ok(())
    }

    fn resize(&mut self, ino: u64, size: u64) -> Result<(), i32> {
        self.flush_pending(Some(ino))?;
        self.validate_size(ino, size)?;
        self.store.update(ino, size, 0, &[]).map_err(write_error)
    }

    fn write_data(&mut self, ino: u64, offset: u64, data: &[u8], sync: bool) -> Result<u32, i32> {
        if data.is_empty() {
            return Ok(0);
        }
        let end = offset.checked_add(data.len() as u64).ok_or(libc::EFBIG)?;
        self.validate_size(ino, self.store.visible_size(ino).max(end))?;
        let mut done = 0;
        while done < data.len() {
            match self
                .store
                .write_span(ino, offset + done as u64, &data[done..], sync)
            {
                Ok(count) => done += count,
                Err(error) => {
                    let errno = write_error(error);
                    return if done == 0 {
                        Err(errno)
                    } else {
                        Ok(done as u32)
                    };
                }
            }
        }
        Ok(done as u32)
    }

    fn move_node(
        &mut self,
        parent: u64,
        name: &OsStr,
        target_parent: u64,
        target: &OsStr,
        flags: u32,
    ) -> Result<(), i32> {
        if flags & !libc::RENAME_NOREPLACE != 0 {
            return Err(libc::EOPNOTSUPP);
        }
        let id = self.find(parent, name)?;
        if !self.node(target_parent)?.dir {
            return Err(libc::ENOTDIR);
        }
        let target_name = target
            .to_str()
            .filter(|name| valid_name(name))
            .ok_or(libc::EINVAL)?;
        let dir = self.node(id)?.dir;
        let mut ancestor = target_parent;
        loop {
            if ancestor == id {
                return Err(libc::EINVAL);
            }
            if ancestor == 1 {
                break;
            }
            ancestor = self.node(ancestor)?.parent;
        }
        let existing = match self.find(target_parent, target) {
            Ok(existing) => {
                if flags & libc::RENAME_NOREPLACE != 0 {
                    return Err(libc::EEXIST);
                }
                if existing == id {
                    return Ok(());
                }
                let node = self.node(existing)?;
                if node.dir != dir {
                    return Err(if node.dir {
                        libc::EISDIR
                    } else {
                        libc::ENOTDIR
                    });
                }
                if self.opened.get(&existing).copied().unwrap_or(0) != 0 {
                    return Err(libc::EBUSY);
                }
                if dir
                    && self
                        .children
                        .get(&existing)
                        .is_some_and(|names| !names.is_empty())
                {
                    return Err(libc::ENOTEMPTY);
                }
                Some(existing)
            }
            Err(libc::ENOENT) => None,
            Err(error) => return Err(error),
        };
        let (used_index, removed) = (
            self.store.visible_totals().1,
            existing.map_or(0, |ino| {
                let node = &self.store.tree.nodes[&ino];
                27 + node.name.len() + self.store.visible_size(ino).div_ceil(BLOCK) as usize * 32
            }),
        );
        if used_index - removed - self.store.tree.nodes[&id].name.len() + target_name.len()
            > MAX_INDEX
        {
            return Err(libc::ENOSPC);
        }
        if let Some(ino) = existing {
            self.flush_pending(Some(ino))?;
        }
        self.store
            .move_or_remove(existing, Some((id, target_parent, target_name.to_owned())))
            .map_err(write_error)?;
        if let Some(existing) = existing {
            self.children.remove(&existing);
        }
        self.children
            .get_mut(&parent)
            .unwrap()
            .remove(name.to_str().unwrap());
        self.children
            .entry(target_parent)
            .or_default()
            .insert(target_name.to_owned(), id);
        Ok(())
    }
}

fn write_error(error: anyhow::Error) -> i32 {
    eprintln!("Work file update failed: {error:#}");
    libc::EIO
}

impl Filesystem for VaultFs<'_> {
    fn lookup(&mut self, _: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        match self.find(parent, name).and_then(|i| self.attr(i)) {
            Ok(a) => reply.entry(&TTL, &a, 0),
            Err(e) => reply.error(e),
        }
    }
    fn getattr(&mut self, _: &Request<'_>, ino: u64, _: Option<u64>, reply: ReplyAttr) {
        match self.attr(ino) {
            Ok(a) => reply.attr(&TTL, &a),
            Err(e) => reply.error(e),
        }
    }
    fn mkdir(
        &mut self,
        _: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _: u32,
        _: u32,
        reply: ReplyEntry,
    ) {
        match self.add(parent, name, true).and_then(|i| self.attr(i)) {
            Ok(a) => reply.entry(&TTL, &a, 0),
            Err(e) => reply.error(e),
        }
    }
    fn create(
        &mut self,
        _: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _: u32,
        _: u32,
        _: i32,
        reply: ReplyCreate,
    ) {
        match self.add(parent, name, false) {
            Ok(i) => {
                self.opened.insert(i, 1);
                reply.created(&TTL, &self.attr(i).unwrap(), 0, i, DIRECT_IO)
            }
            Err(e) => reply.error(e),
        }
    }
    fn open(&mut self, _: &Request<'_>, ino: u64, _: i32, reply: ReplyOpen) {
        match self.node(ino) {
            Ok(n) if !n.dir => {
                *self.opened.entry(ino).or_default() += 1;
                reply.opened(ino, DIRECT_IO)
            }
            Ok(_) => reply.error(libc::EISDIR),
            Err(e) => reply.error(e),
        }
    }
    fn read(
        &mut self,
        _: &Request<'_>,
        ino: u64,
        _: u64,
        offset: i64,
        size: u32,
        _: i32,
        _: Option<u64>,
        reply: ReplyData,
    ) {
        match self.node(ino) {
            Ok(n) if !n.dir && offset >= 0 => match self.store.read(ino, offset as u64, size) {
                Ok(data) => reply.data(&data),
                Err(error) => {
                    eprintln!("Work file read failed: {error:#}");
                    reply.error(libc::EIO);
                }
            },
            Ok(_) => reply.error(libc::EINVAL),
            Err(e) => reply.error(e),
        }
    }
    fn write(
        &mut self,
        _: &Request<'_>,
        ino: u64,
        _: u64,
        offset: i64,
        data: &[u8],
        _: u32,
        flags: i32,
        _: Option<u64>,
        reply: ReplyWrite,
    ) {
        let result = (|| -> Result<u32, i32> {
            let node = self.node(ino)?;
            if node.dir || offset < 0 {
                return Err(libc::EINVAL);
            }
            self.write_data(ino, offset as u64, data, flags & libc::O_DSYNC != 0)
        })();
        match result {
            Ok(written) => reply.written(written),
            Err(e) => reply.error(e),
        }
    }
    fn setattr(
        &mut self,
        _: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        _: Option<TimeOrNow>,
        _: Option<TimeOrNow>,
        _: Option<SystemTime>,
        _: Option<u64>,
        _: Option<SystemTime>,
        _: Option<SystemTime>,
        _: Option<SystemTime>,
        flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        if mode.is_some() || uid.is_some() || gid.is_some() || flags.is_some() {
            reply.error(libc::EOPNOTSUPP);
            return;
        }
        if let Some(size) = size {
            if let Err(error) = self.resize(ino, size) {
                reply.error(error);
                return;
            }
        }
        match self.attr(ino) {
            Ok(a) => reply.attr(&TTL, &a),
            Err(e) => reply.error(e),
        }
    }
    fn readdir(
        &mut self,
        _: &Request<'_>,
        ino: u64,
        _: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let parent = match self.node(ino) {
            Ok(n) if n.dir => n.parent,
            Ok(_) => {
                reply.error(libc::ENOTDIR);
                return;
            }
            Err(e) => {
                reply.error(e);
                return;
            }
        };
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        let mut entries = vec![
            (ino, FileType::Directory, ".".to_string()),
            (parent, FileType::Directory, "..".to_string()),
        ];
        entries.extend(
            self.store
                .tree
                .nodes
                .iter()
                .filter(|(i, n)| **i != 1 && n.parent == ino)
                .map(|(i, n)| {
                    (
                        *i,
                        if n.dir {
                            FileType::Directory
                        } else {
                            FileType::RegularFile
                        },
                        n.name.clone(),
                    )
                }),
        );
        for (idx, (i, k, n)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*i, (idx + 1) as i64, *k, n) {
                break;
            }
        }
        reply.ok()
    }
    fn unlink(&mut self, _: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.remove(parent, name, false) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }
    fn rmdir(&mut self, _: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.remove(parent, name, true) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }
    fn rename(
        &mut self,
        _: &Request<'_>,
        parent: u64,
        name: &OsStr,
        target_parent: u64,
        target: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        match self.move_node(parent, name, target_parent, target, flags) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }
    fn flush(&mut self, _: &Request<'_>, ino: u64, _: u64, _: u64, reply: ReplyEmpty) {
        match self.flush_pending(Some(ino)) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }
    fn fsync(&mut self, _: &Request<'_>, ino: u64, _: u64, _: bool, reply: ReplyEmpty) {
        match self.flush_pending(Some(ino)) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }
    fn release(
        &mut self,
        _: &Request<'_>,
        ino: u64,
        _: u64,
        _: i32,
        _: Option<u64>,
        _: bool,
        reply: ReplyEmpty,
    ) {
        if let Some(n) = self.opened.get_mut(&ino) {
            *n = n.saturating_sub(1);
        }
        match self.flush_pending(Some(ino)) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::Cipher;
    use std::path::Path;
    use zeroize::Zeroizing;
    #[test]
    fn tree_operations_persist_and_enforce_limits() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault");
        let c = Cipher::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("lib/libaldcrypto.so"))
            .unwrap();
        Store::init(&path, &c, &[0x25; 32], 1_000_000).unwrap();
        let mut store = Store::open(&path, c, Zeroizing::new(vec![0x25; 32])).unwrap();
        let mut fs = VaultFs::with_owner(&mut store, 1000, 1001);
        let d = fs.add(1, OsStr::new("docs"), true).unwrap();
        let f = fs.add(d, OsStr::new("file"), false).unwrap();
        for (ino, perm) in [(1, 0o700), (d, 0o700), (f, 0o600)] {
            let attr = fs.attr(ino).unwrap();
            assert_eq!((attr.uid, attr.gid, attr.perm), (1000, 1001, perm));
        }
        assert_eq!(fs.add(d, OsStr::new("file"), false), Err(libc::EEXIST));
        assert_eq!(fs.add(f, OsStr::new("bad"), false), Err(libc::ENOTDIR));
        assert_eq!(fs.add(d, OsStr::new(".."), false), Err(libc::EINVAL));
        fs.resize(f, 17).unwrap();
        assert_eq!(fs.attr(f).unwrap().size, 17);
        assert_eq!(fs.resize(f, 1_000_001), Err(libc::EFBIG));
        assert_eq!(fs.remove(1, OsStr::new("docs"), true), Err(libc::ENOTEMPTY));
        fs.opened.insert(f, 1);
        assert_eq!(fs.remove(d, OsStr::new("file"), false), Err(libc::EBUSY));
        fs.opened.clear();
        fs.move_node(d, OsStr::new("file"), 1, OsStr::new("renamed"), 0)
            .unwrap();
        assert_eq!(fs.find(1, OsStr::new("renamed")), Ok(f));
        fs.remove(1, OsStr::new("renamed"), false).unwrap();
        fs.remove(1, OsStr::new("docs"), true).unwrap();
        assert_eq!(fs.store.tree.nodes.len(), 1);
        store.close().unwrap();
    }

    #[test]
    fn overlapping_writers_share_the_reserved_quota() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("quota");
        let key = [3; 32];
        Store::init(&path, &Cipher::benchmark_xor(), &key, 9).unwrap();
        let mut store =
            Store::open(&path, Cipher::benchmark_xor(), Zeroizing::new(key.to_vec())).unwrap();
        let mut fs = VaultFs::new(&mut store);
        let a = fs.add(1, OsStr::new("a"), false).unwrap();
        let b = fs.add(1, OsStr::new("b"), false).unwrap();
        assert_eq!(fs.write_data(a, 0, b"12345", false), Ok(5));
        assert_eq!(fs.write_data(b, 0, b"abcde", false), Err(libc::EFBIG));
        assert_eq!(fs.write_data(b, 0, b"abcd", false), Ok(4));
        fs.flush_pending(Some(b)).unwrap();
        assert_eq!(fs.store.tree.nodes[&a].size, 0);
        fs.resize(a, 2).unwrap();
        assert_eq!(fs.write_data(b, 4, b"xyz", false), Ok(3));
        fs.store.close().unwrap();
    }

    #[test]
    fn sequential_writes_reserve_quota_and_flush_on_sync() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault");
        let cipher = Cipher::benchmark_xor();
        let key = [0x25; 32];
        Store::init(&path, &cipher, &key, BLOCK + 4).unwrap();
        let mut store = Store::open(&path, cipher, Zeroizing::new(key.to_vec())).unwrap();
        {
            let mut fs = VaultFs::with_owner(&mut store, 1000, 1001);
            let id = fs.add(1, OsStr::new("file"), false).unwrap();
            let prefix = vec![0xa5; BLOCK as usize - 2];
            assert_eq!(
                fs.write_data(id, 0, &prefix, false),
                Ok(prefix.len() as u32)
            );
            assert_eq!(fs.store.tree.nodes[&id].size, 0);
            assert_eq!(fs.attr(id).unwrap().size, BLOCK - 2);
            assert_eq!(fs.write_data(id, BLOCK - 2, b"ABCDEF", false), Ok(6));
            assert_eq!(fs.store.tree.nodes[&id].size, 0);
            assert_eq!(fs.attr(id).unwrap().size, BLOCK + 4);
            assert_eq!(fs.write_data(id, BLOCK + 4, b"x", false), Err(libc::EFBIG));
            assert_eq!(fs.store.tree.nodes[&id].size, 0);
            fs.flush_pending(Some(id)).unwrap();
            assert_eq!(fs.store.tree.nodes[&id].size, BLOCK + 4);
            assert_eq!(
                fs.store.read(id, BLOCK - 2, 6).unwrap().as_slice(),
                b"ABCDEF"
            );
            fs.resize(id, BLOCK + 2).unwrap();
            assert_eq!(fs.write_data(id, BLOCK + 2, b"E", true), Ok(1));
            assert_eq!(fs.store.tree.nodes[&id].size, BLOCK + 3);
            assert_eq!(fs.write_data(id, BLOCK + 3, b"F", false), Ok(1));
            assert_eq!(fs.store.tree.nodes[&id].size, BLOCK + 3);
        }
        store.close().unwrap();
        drop(store);
        let mut store =
            Store::open(&path, Cipher::benchmark_xor(), Zeroizing::new(key.to_vec())).unwrap();
        assert_eq!(store.read(2, BLOCK - 2, 6).unwrap().as_slice(), b"ABCDEF");
        store.close().unwrap();
    }
}

#[cfg(test)]
mod write_bench;
