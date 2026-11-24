use crate::cipher::Cipher;
#[cfg(any(target_os = "linux", test))]
use crate::cipher::random;
use anyhow::{Result, ensure};
use std::{
    collections::{BTreeMap, HashSet},
    fs::File,
    io::{Read, Write},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const BLOCK: u64 = 1_000_000;
pub const MAX_INDEX: usize = 64_000_000;
const MAGIC: &[u8; 8] = b"VLAGOST2";
const HEADER: usize = 52;
const INDEX_FIELDS: usize = 20;
const NODE_FIELDS: usize = 27;
pub type Id = [u8; 16];
pub type Tag = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub parent: u64,
    pub name: String,
    pub dir: bool,
    pub size: u64,
    pub tags: Vec<Tag>,
}

impl Node {
    pub fn new(parent: u64, name: String, dir: bool) -> Self {
        Self {
            parent,
            name,
            dir,
            size: 0,
            tags: vec![],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tree {
    pub quota: u64,
    pub next: u64,
    pub nodes: BTreeMap<u64, Node>,
}

impl Tree {
    pub fn empty(quota: u64) -> Self {
        Self {
            quota,
            next: 2,
            nodes: BTreeMap::from([(1, Node::new(1, String::new(), true))]),
        }
    }

    pub fn used(&self) -> u64 {
        self.nodes.values().map(|node| node.size).sum()
    }

    pub fn encoded_len(&self) -> usize {
        INDEX_FIELDS
            + self
                .nodes
                .values()
                .map(|node| NODE_FIELDS + node.name.len() + 32 * node.tags.len())
                .sum::<usize>()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(self.quota > 0, "Invalid quota");
        let root = self
            .nodes
            .get(&1)
            .ok_or_else(|| anyhow::anyhow!("Missing root"))?;
        ensure!(
            root.dir && root.parent == 1 && root.name.is_empty(),
            "Invalid root"
        );
        ensure!(
            self.next > *self.nodes.keys().next_back().unwrap(),
            "Invalid next ID"
        );
        let mut names = HashSet::new();
        let mut total = 0u64;
        for (&id, node) in &self.nodes {
            ensure!(
                (!node.dir || node.size == 0)
                    && node.size.div_ceil(BLOCK) == node.tags.len() as u64,
                "Invalid file size or block count"
            );
            total = total
                .checked_add(node.size)
                .ok_or_else(|| anyhow::anyhow!("Size overflow"))?;
            if id != 1 {
                ensure!(id > 1 && valid_name(&node.name), "Invalid name or ID");
                ensure!(names.insert((node.parent, &node.name)), "Duplicate name");
                ensure!(
                    self.nodes
                        .get(&node.parent)
                        .is_some_and(|parent| parent.dir),
                    "Invalid parent"
                );
            }
        }
        ensure!(total <= self.quota, "Quota exceeded");
        let mut traced = HashSet::from([1]);
        for &id in self.nodes.keys() {
            if traced.contains(&id) {
                continue;
            }
            let mut path = HashSet::new();
            let mut next = id;
            while !traced.contains(&next) {
                ensure!(path.insert(next), "Directory cycle");
                next = self.nodes[&next].parent;
            }
            traced.extend(path);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let len = self.encoded_len();
        ensure!(len <= MAX_INDEX, "Index too large");
        self.validate()?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(len));
        bytes.extend_from_slice(&self.quota.to_le_bytes());
        bytes.extend_from_slice(&self.next.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(self.nodes.len())?.to_le_bytes());
        for (&id, node) in &self.nodes {
            bytes.extend_from_slice(&id.to_le_bytes());
            bytes.extend_from_slice(&node.parent.to_le_bytes());
            bytes.push(u8::from(node.dir));
            bytes.extend_from_slice(&u16::try_from(node.name.len())?.to_le_bytes());
            bytes.extend_from_slice(&node.size.to_le_bytes());
            bytes.extend_from_slice(node.name.as_bytes());
            for tag in &node.tags {
                bytes.extend_from_slice(tag);
            }
        }
        Ok(bytes)
    }

    pub fn decode(mut bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_INDEX, "Index too large");
        let quota = u64::from_le_bytes(take(&mut bytes)?);
        let next = u64::from_le_bytes(take(&mut bytes)?);
        let count = u32::from_le_bytes(take(&mut bytes)?) as usize;
        ensure!(count <= bytes.len() / NODE_FIELDS, "Invalid node count");
        let mut nodes = BTreeMap::new();
        let mut previous = 0;
        for _ in 0..count {
            let id = u64::from_le_bytes(take(&mut bytes)?);
            let parent = u64::from_le_bytes(take(&mut bytes)?);
            let [kind] = take(&mut bytes)?;
            let len = usize::from(u16::from_le_bytes(take(&mut bytes)?));
            let size = u64::from_le_bytes(take(&mut bytes)?);
            ensure!(
                id > previous && kind <= 1 && len <= 255 && len <= bytes.len(),
                "Invalid index entry"
            );
            previous = id;
            let (name, rest) = bytes.split_at(len);
            bytes = rest;
            let name = std::str::from_utf8(name)?.to_owned();
            let blocks = usize::try_from(size.div_ceil(BLOCK))?;
            ensure!(blocks <= bytes.len() / 32, "Invalid block count");
            let mut tags = Vec::with_capacity(blocks);
            for _ in 0..blocks {
                tags.push(take(&mut bytes)?);
            }
            nodes.insert(
                id,
                Node {
                    parent,
                    name,
                    dir: kind == 1,
                    size,
                    tags,
                },
            );
        }
        ensure!(bytes.is_empty(), "Extra bytes in index");
        let tree = Self { quota, next, nodes };
        tree.validate()?;
        Ok(tree)
    }
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N]> {
    let mut value = [0; N];
    bytes.read_exact(&mut value)?;
    Ok(value)
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.contains(['/', '\0'])
}

pub fn padded(len: usize) -> usize {
    (len / 16 + 1) * 16
}

#[derive(Clone, Copy)]
pub struct Container {
    pub id: Id,
    pub revision: Id,
    pub iv: usize,
}

impl Container {
    #[cfg(any(target_os = "linux", test))]
    pub fn new(cipher: &Cipher, key: &[u8]) -> Result<Self> {
        let id = random()?;
        let keys = cipher.derive(key, b"vault-lab/v2/index", &id)?;
        Ok(Self {
            id,
            revision: random()?,
            iv: cipher.iv_size(&keys)?,
        })
    }

    pub fn read_index(file: &mut File, cipher: &Cipher, key: &[u8]) -> Result<(Self, Tree)> {
        let mut header = [0; HEADER];
        file.read_exact(&mut header)?;
        ensure!(
            &header[..8] == cipher.container_magic(),
            "Unsupported container format for this mode; expected {}",
            std::str::from_utf8(cipher.container_magic())?
        );
        let id: Id = header[8..24].try_into()?;
        let revision = header[24..40].try_into()?;
        let iv = u32::from_le_bytes(header[40..44].try_into()?) as usize;
        let len = usize::try_from(u64::from_le_bytes(header[44..52].try_into()?))?;
        ensure!(
            (16..=128).contains(&iv) && (16..=padded(MAX_INDEX)).contains(&len) && len % 16 == 0,
            "Invalid container header"
        );
        let file_size = file.metadata()?.len();
        ensure!(
            file_size >= (HEADER + iv + len + 32) as u64,
            "Truncated index"
        );
        let keys = cipher.derive(key, b"vault-lab/v2/index", &id)?;
        ensure!(cipher.iv_size(&keys)? == iv, "Incompatible plugin IV size");
        let mut record = vec![0; iv + len + 32];
        file.read_exact(&mut record)?;
        let plain = cipher.unseal(&keys, &header, iv, &record)?;
        let tree = Tree::decode(&plain)?;
        let container = Self { id, revision, iv };
        let expected_size = tree
            .nodes
            .values()
            .try_fold((HEADER + record.len()) as u64, |total, node| {
                total.checked_add(container.file_len(node.size))
            })
            .ok_or_else(|| anyhow::anyhow!("Container size overflow"))?;
        ensure!(file_size == expected_size, "Invalid container length");
        Ok((container, tree))
    }

    pub fn write_index(
        &self,
        file: &mut File,
        cipher: &Cipher,
        key: &[u8],
        tree: &Tree,
    ) -> Result<()> {
        let plain = tree.encode()?;
        let mut header = Vec::with_capacity(HEADER);
        header.extend_from_slice(cipher.container_magic());
        header.extend_from_slice(&self.id);
        header.extend_from_slice(&self.revision);
        header.extend_from_slice(&(self.iv as u32).to_le_bytes());
        header.extend_from_slice(&(padded(plain.len()) as u64).to_le_bytes());
        let keys = cipher.derive(key, b"vault-lab/v2/index", &self.id)?;
        file.write_all(&header)?;
        file.write_all(&cipher.seal(&keys, &header, &plain)?)?;
        Ok(())
    }

    pub fn record_len(&self, len: usize) -> usize {
        self.iv + padded(len) + 32
    }

    pub fn file_len(&self, size: u64) -> u64 {
        let full = size / BLOCK;
        let tail = (size % BLOCK) as usize;
        full * self.record_len(BLOCK as usize) as u64
            + if tail == 0 {
                0
            } else {
                self.record_len(tail) as u64
            }
    }

    pub fn block_context(&self, id: u64, block: u64, len: usize) -> [u8; 48] {
        let mut context = [0; 48];
        context[..8].copy_from_slice(MAGIC);
        context[8..24].copy_from_slice(&self.id);
        context[24..32].copy_from_slice(&id.to_le_bytes());
        context[32..40].copy_from_slice(&block.to_le_bytes());
        context[40..44].copy_from_slice(&(len as u32).to_le_bytes());
        context[44..48].copy_from_slice(&(self.iv as u32).to_le_bytes());
        context
    }

    pub fn file_keys(&self, cipher: &Cipher, key: &[u8], id: u64) -> Result<Zeroizing<Vec<u8>>> {
        let mut seed = [0; 24];
        seed[..16].copy_from_slice(&self.id);
        seed[16..].copy_from_slice(&id.to_le_bytes());
        cipher.derive(key, b"vault-lab/v2/file", &seed)
    }
}

pub fn block_len(size: u64, block: u64) -> usize {
    (size - block * BLOCK).min(BLOCK) as usize
}

pub fn check_tag(record: &[u8], expected: &Tag) -> Result<()> {
    ensure!(
        bool::from(record[record.len() - 32..].ct_eq(expected)),
        "Unexpected block tag"
    );
    Ok(())
}
