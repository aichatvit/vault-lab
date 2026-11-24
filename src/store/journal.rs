//! An atomic encrypted head contains bounded edits relative to one immutable checkpoint.
use super::*;
use crate::format::Tag;

const HEAD: u8 = 4;
const LIMIT: usize = 64_000;
const MAX_EDITS: usize = 256;

pub(super) struct Journal {
    epoch: Id,
    tag: Tag,
    edits: Zeroizing<Vec<u8>>,
    count: usize,
}

fn checkpoint(epoch: Id) -> String {
    format!("checkpoint-{}", hex::encode(epoch))
}

pub(super) const PATCH_LIMIT: usize = 512_000;
pub(super) const PATCH_SIZE: usize = 4096;
#[derive(Clone)]
pub(super) struct Patch {
    pub id: u64,
    pub offset: u64,
    pub data: Zeroizing<Vec<u8>>,
}
impl Patch {
    fn cost(&self) -> usize {
        19 + self.data.len()
    }
    pub(super) fn usage(patches: &[Self]) -> usize {
        patches.iter().map(Self::cost).sum()
    }
    fn install(self, tree: &Tree, patches: &mut Vec<Self>) -> Result<()> {
        let size = tree
            .nodes
            .get(&self.id)
            .context("Missing patched file")?
            .size;
        let len = self.data.len();
        let end = self
            .offset
            .checked_add(len as u64)
            .context("Patch overflow")?;
        ensure!(
            len > 0 && len <= PATCH_SIZE && end <= size && self.offset / BLOCK == (end - 1) / BLOCK,
            "Invalid small write"
        );
        patches.retain(|p| {
            p.id != self.id || p.offset < self.offset || p.offset + p.data.len() as u64 > end
        });
        ensure!(
            Self::usage(patches) + self.cost() <= PATCH_LIMIT,
            "Too many small writes"
        );
        patches.push(self);
        Ok(())
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        out.extend(self.offset.to_le_bytes());
        out.extend((self.data.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.data);
    }

    pub(super) fn restore(tree: &Tree, mut bytes: &[u8]) -> Result<Vec<Self>> {
        ensure!(bytes.len() <= PATCH_LIMIT, "Oversized patch snapshot");
        let mut patches = Vec::new();
        while !bytes.is_empty() {
            let id = number(&mut bytes)?;
            Self::decode(id, &mut bytes)?.install(tree, &mut patches)?;
        }
        Ok(patches)
    }
    fn decode(id: u64, input: &mut &[u8]) -> Result<Self> {
        let offset = number(input)?;
        let len = u16::from_le_bytes(take(input)?) as usize;
        ensure!(
            len > 0 && len <= PATCH_SIZE && len <= input.len(),
            "Invalid patch length"
        );
        let (bytes, rest) = input.split_at(len);
        *input = rest;
        Ok(Self {
            id,
            offset,
            data: Zeroizing::new(bytes.to_vec()),
        })
    }
}

#[derive(Clone)]
pub(super) enum Edit {
    Create {
        id: u64,
        parent: u64,
        name: String,
        generation: Option<Id>,
    },
    Remove(u64),
    Patch(Patch),
    Rename {
        id: u64,
        parent: u64,
        name: String,
    },
    Blocks {
        id: u64,
        size: u64,
        generation: Id,
        first: usize,
        records: Vec<(Tag, u64)>,
    },
}

fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn number(input: &mut &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(take(input)?))
}

fn name(input: &mut &[u8]) -> Result<String> {
    let len = usize::from(take::<1>(input)?[0]);
    ensure!(input.len() >= len, "Truncated journal name");
    let (bytes, rest) = input.split_at(len);
    *input = rest;
    let value = std::str::from_utf8(bytes)?;
    ensure!(valid_name(value), "Invalid journal name");
    Ok(value.to_owned())
}

impl Edit {
    fn encode(&self, out: &mut Vec<u8>) {
        let (kind, id) = match self {
            Self::Create { id, generation, .. } => (u8::from(generation.is_some()), id),
            Self::Remove(id) => (2, id),
            Self::Patch(p) => (5, &p.id),
            Self::Rename { id, .. } => (3, id),
            Self::Blocks { id, .. } => (4, id),
        };
        out.push(kind);
        out.extend(id.to_le_bytes());
        match self {
            Self::Create { parent, name, .. } | Self::Rename { parent, name, .. } => {
                out.extend(parent.to_le_bytes());
                out.push(name.len() as u8);
                out.extend(name.as_bytes());
                if let Self::Create {
                    generation: Some(generation),
                    ..
                } = self
                {
                    out.extend(generation);
                }
            }
            Self::Remove(_) => {}
            Self::Patch(p) => p.encode(out),
            Self::Blocks {
                size,
                generation,
                first,
                records,
                ..
            } => {
                out.extend(size.to_le_bytes());
                out.extend(generation);
                out.extend((*first as u32).to_le_bytes());
                out.extend((records.len() as u32).to_le_bytes());
                for (tag, offset) in records {
                    out.extend(tag);
                    out.extend(offset.to_le_bytes());
                }
            }
        }
    }

    fn decode(input: &mut &[u8]) -> Result<Self> {
        let kind = take::<1>(input)?[0];
        let id = number(input)?;
        ensure!(id > 1, "Invalid journal inode");
        Ok(match kind {
            0 | 1 => Self::Create {
                id,
                parent: number(input)?,
                name: name(input)?,
                generation: if kind == 1 { Some(take(input)?) } else { None },
            },
            2 => Self::Remove(id),
            3 => Self::Rename {
                id,
                parent: number(input)?,
                name: name(input)?,
            },
            4 => {
                let size = number(input)?;
                let generation = take(input)?;
                let first = u32::from_le_bytes(take(input)?) as usize;
                let count = u32::from_le_bytes(take(input)?) as usize;
                ensure!(count <= input.len() / 40, "Truncated journal records");
                let records = (0..count)
                    .map(|_| Ok((take(input)?, number(input)?)))
                    .collect::<Result<_>>()?;
                Self::Blocks {
                    id,
                    size,
                    generation,
                    first,
                    records,
                }
            }
            5 => Self::Patch(Patch::decode(id, input)?),
            _ => anyhow::bail!("Unknown journal operation"),
        })
    }

    pub(super) fn apply(
        self,
        tree: &mut Tree,
        files: &mut BTreeMap<u64, WorkFile>,
        patches: &mut Vec<Patch>,
        totals: &mut Totals,
    ) -> Result<()> {
        match self {
            Self::Create {
                id,
                parent,
                name,
                generation,
            } => {
                ensure!(id == tree.next && valid_name(&name), "Invalid new node");
                tree.next = id.checked_add(1).context("Inode overflow")?;
                totals.index += 27 + name.len();
                tree.nodes
                    .insert(id, Node::new(parent, name, generation.is_none()));
                if let Some(generation) = generation {
                    files.insert(
                        id,
                        WorkFile {
                            generation,
                            offsets: Vec::new(),
                        },
                    );
                }
            }
            Self::Patch(p) => p.install(tree, patches)?,
            Self::Remove(id) => {
                patches.retain(|p| p.id != id);
                let node = tree.nodes.remove(&id).context("Missing removed node")?;
                totals.used -= node.size;
                totals.index -= 27 + node.name.len() + node.tags.len() * 32;
                files.remove(&id);
            }
            Self::Rename { id, parent, name } => {
                let node = tree.nodes.get_mut(&id).context("Missing renamed node")?;
                totals.index = totals.index - node.name.len() + name.len();
                node.parent = parent;
                node.name = name;
            }
            Self::Blocks {
                id,
                size,
                generation,
                first,
                records,
            } => {
                let node = tree.nodes.get_mut(&id).context("Missing changed node")?;
                let file = files.get_mut(&id).context("Missing changed file")?;
                let blocks = usize::try_from(size.div_ceil(BLOCK))?;
                let end = first
                    .checked_add(records.len())
                    .context("Invalid journal range")?;
                let old = node.tags.len();
                ensure!(
                    first <= old
                        && end <= blocks
                        && (blocks <= old || end == blocks)
                        && (generation == file.generation || (first == 0 && end == blocks)),
                    "Invalid block change"
                );
                let index = totals.index - old * 32;
                ensure!(
                    blocks <= (MAX_INDEX - index) / 32
                        && size <= tree.quota - (totals.used - node.size),
                    "Journal exceeds limits"
                );
                patches.retain(|p| {
                    let b = (p.offset / BLOCK) as usize;
                    p.id != id || (b < blocks && !(first..end).contains(&b))
                });
                totals.index = index + blocks * 32;
                totals.used = totals.used - node.size + size;
                node.size = size;
                node.tags.resize(blocks, [0; 32]);
                file.generation = generation;
                file.offsets.resize(blocks, 0);
                for (i, (tag, offset)) in (first..end).zip(records) {
                    node.tags[i] = tag;
                    file.offsets[i] = offset;
                }
            }
        }
        ensure!(totals.index <= MAX_INDEX, "Index too large");
        Ok(())
    }
}

impl Workspace {
    pub(super) fn keep_checkpoint(&self, keep: &mut HashSet<String>) {
        if let Some(journal) = &self.journal {
            keep.insert(checkpoint(journal.epoch));
        }
    }

    pub(super) fn forget_checkpoint(&mut self) {
        if let Some(journal) = self.journal.take() {
            let _ = unlink_if_present(&self.dir, &checkpoint(journal.epoch));
        }
    }

    pub(super) fn encode_edits(
        &self,
        changes: &[Edit],
        index_len: usize,
    ) -> Option<Zeroizing<Vec<u8>>> {
        // Small trees are cheaper to checkpoint sooner. Cap recovery work for large ones.
        let limit =
            if self.patches.is_empty() && !changes.iter().any(|c| matches!(c, Edit::Patch(_))) {
                ((index_len + self.files.len() * 16) / 2).clamp(4096, LIMIT)
            } else {
                LIMIT
            };
        let mut encoded = Zeroizing::new(Vec::new());
        for change in changes {
            if matches!(change,Edit::Blocks{records,..} if records.len()>limit/40) {
                return None;
            }
            change.encode(&mut encoded);
        }
        if encoded.len() > limit
            || self.journal.as_ref().is_some_and(|j| {
                j.count + changes.len() > MAX_EDITS || j.edits.len() + encoded.len() > limit
            })
        {
            None
        } else {
            Some(encoded)
        }
    }

    pub(super) fn save_edits(
        &mut self,
        container: Container,
        cipher: &Cipher,
        key: &[u8],
        encoded: &[u8],
        count: usize,
    ) -> Result<()> {
        if self.journal.is_none() {
            let epoch = random()?;
            let mut state = read_file(&self.dir, "state")?;
            state.seek(SeekFrom::End(-32))?;
            let mut tag = [0; 32];
            state.read_exact(&mut tag)?;
            state.rewind()?;
            atomic_write(&self.dir, &checkpoint(epoch), true, |file| {
                io::copy(&mut state, file)?;
                Ok(())
            })?;
            self.journal = Some(Journal {
                epoch,
                tag,
                edits: Zeroizing::new(Vec::new()),
                count: 0,
            });
        }
        let journal = self.journal.as_mut().unwrap();
        journal.edits.extend_from_slice(encoded);
        journal.count += count;
        let mut plain = Zeroizing::new(Vec::with_capacity(65 + journal.edits.len()));
        plain.extend(self.base);
        plain.push(HEAD);
        plain.extend(journal.epoch);
        plain.extend(journal.tag);
        plain.extend_from_slice(&journal.edits);
        self.write_state(container, cipher, key, &plain)
    }

    pub(super) fn load_head(
        dir: &File,
        container: Container,
        cipher: &Cipher,
        key: &[u8],
        session: Id,
        plain: &[u8],
    ) -> Result<(Self, Tree)> {
        ensure!(
            plain.len() > 65 && plain.len() <= 65 + LIMIT,
            "Invalid journal length"
        );
        let epoch = plain[17..33].try_into()?;
        let tag = plain[33..65].try_into()?;
        let (header, snapshot) = Self::read_state(
            &mut read_file(dir, &checkpoint(epoch))?,
            container,
            cipher,
            key,
            Some(&tag),
        )?;
        ensure!(
            header[24..] == session && snapshot[..16] == plain[..16],
            "Unexpected journal checkpoint"
        );
        let (mut work, mut tree) = Self::decode_snapshot(dir, container, session, &snapshot)?;
        ensure!(work.target.is_none(), "Journal after packing");
        let edits = &plain[65..];
        let mut input = edits;
        let mut count = 0;
        let mut totals = Totals::from_tree(&tree);
        while !input.is_empty() {
            ensure!(count < MAX_EDITS, "Too many journal operations");
            Edit::decode(&mut input)?.apply(
                &mut tree,
                &mut work.files,
                &mut work.patches,
                &mut totals,
            )?;
            count += 1;
        }
        tree.validate()?;
        work.dirty = true;
        work.journal = Some(Journal {
            epoch,
            tag,
            edits: Zeroizing::new(edits.to_vec()),
            count,
        });
        Ok((work, tree))
    }
}
