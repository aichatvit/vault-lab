use crate::{
    cipher::Cipher,
    format::{BLOCK, Container, Tree, block_len, check_tag},
};
use anyhow::{Result, ensure};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
};
use zeroize::Zeroizing;

pub struct Archive {
    pub container: Container,
    pub tree: Tree,
    offsets: BTreeMap<u64, u64>,
    pub baseline: PathBuf,
    pub plugin: PathBuf,
    pub key: Zeroizing<Vec<u8>>,
}

impl Archive {
    pub fn open(
        baseline: PathBuf,
        plugin: PathBuf,
        key: Zeroizing<Vec<u8>>,
        cipher: &Cipher,
    ) -> Result<Self> {
        let mut file = File::open(&baseline)?;
        let (container, tree) = Container::read_index(&mut file, cipher, &key)?;
        let mut pos = file.stream_position()?;
        let mut offsets = BTreeMap::new();
        for (&id, node) in &tree.nodes {
            offsets.insert(id, pos);
            pos += container.file_len(node.size);
        }
        Ok(Self {
            container,
            tree,
            offsets,
            baseline,
            plugin,
            key,
        })
    }

    #[cfg(windows)]
    pub fn validate_names(&self) -> Result<()> {
        let mut names = std::collections::HashSet::new();
        for (&id, node) in &self.tree.nodes {
            if id != 1 {
                validate_name(&node.name)?;
                ensure!(
                    names.insert((node.parent, node.name.to_uppercase())),
                    "Case-insensitive name conflict: {:?}",
                    node.name
                );
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    pub fn populate(&self, root: &std::path::Path) -> Result<()> {
        let mut children = BTreeMap::<_, Vec<_>>::new();
        for (&id, node) in self.tree.nodes.iter().filter(|(id, _)| **id != 1) {
            children.entry(node.parent).or_default().push((id, node));
        }
        let mut dirs = vec![(1, root.to_owned())];
        while let Some((parent, path)) = dirs.pop() {
            for &(id, node) in children.get(&parent).into_iter().flatten() {
                super::cloud::placeholder(&path, &node.name, id, node.size, node.dir)?;
                if node.dir {
                    dirs.push((id, path.join(&node.name)));
                }
            }
        }
        Ok(())
    }

    pub fn read_range(
        &self,
        id: u64,
        offset: u64,
        length: u64,
        mut send: impl FnMut(u64, &[u8]) -> Result<()>,
    ) -> Result<()> {
        let node = self
            .tree
            .nodes
            .get(&id)
            .ok_or_else(|| anyhow::anyhow!("Unknown placeholder"))?;
        ensure!(!node.dir && offset < node.size, "Range outside file");
        // Each callback owns its native crypto context and file cursor.
        let cipher = Cipher::load(&self.plugin)?;
        let keys = self.container.file_keys(&cipher, &self.key, id)?;
        let mut file = File::open(&self.baseline)?;
        let mut pos = offset / 4096 * 4096;
        let end = offset
            .saturating_add(length)
            .min(node.size)
            .next_multiple_of(4096)
            .min(node.size);
        let mut block = u64::MAX;
        let mut plain = Zeroizing::new(Vec::new());
        while pos < end {
            // CFAPI requires aligned transfers. VLAGOST2's decimal MB boundaries are unaligned.
            let limit = (pos + 1024 * 1024).min(end);
            let mut out = Zeroizing::new(Vec::with_capacity((limit - pos) as usize));
            let start = pos;
            while pos < limit {
                if pos / BLOCK != block {
                    block = pos / BLOCK;
                    let n = block_len(node.size, block);
                    file.seek(SeekFrom::Start(
                        self.offsets[&id] + self.container.file_len(block * BLOCK),
                    ))?;
                    let mut record = vec![0; self.container.record_len(n)];
                    file.read_exact(&mut record)?;
                    check_tag(&record, &node.tags[block as usize])?;
                    plain = cipher.unseal(
                        &keys,
                        &self.container.block_context(id, block, n),
                        self.container.iv,
                        &record,
                    )?;
                    ensure!(plain.len() == n, "Invalid block length");
                }
                let at = (pos % BLOCK) as usize;
                let n = (plain.len() - at).min((limit - pos) as usize);
                out.extend_from_slice(&plain[at..at + n]);
                pos += n as u64;
            }
            send(start, &out)?;
        }
        Ok(())
    }
}

pub fn validate_name(name: &str) -> Result<()> {
    let stem = name
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    let device = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|n| {
            matches!(
                n,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    });
    ensure!(
        crate::format::valid_name(name)
            && !device
            && !name.ends_with([' ', '.'])
            && !name.chars().any(|c| c < ' ' || "<>:\"\\|?*".contains(c)),
        "Unsupported Windows file name {name:?}"
    );
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::format::Node;
    use std::io::Write;

    #[test]
    fn authenticated_cloud_range_across_decimal_blocks() -> Result<()> {
        let plugin = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("lib/libaldcrypto.so");
        let cipher = Cipher::load(&plugin)?;
        let key = Zeroizing::new(vec![42; 32]);
        let container = Container::new(&cipher, &key)?;
        let mut tree = Tree::empty(BLOCK + 23);
        let data: Vec<_> = (0..tree.quota).map(|i| (i % 251) as u8).collect();
        let mut node = Node::new(1, "report.bin".into(), false);
        node.size = tree.quota;
        let mut payload = Vec::new();
        let keys = container.file_keys(&cipher, &key, 2)?;
        for (i, chunk) in data.chunks(BLOCK as usize).enumerate() {
            let record = cipher.seal(
                &keys,
                &container.block_context(2, i as u64, chunk.len()),
                chunk,
            )?;
            node.tags.push(record[record.len() - 32..].try_into()?);
            payload.extend_from_slice(&record);
        }
        tree.nodes.insert(2, node);
        tree.next = 3;
        let mut file = tempfile::NamedTempFile::new()?;
        container.write_index(file.as_file_mut(), &cipher, &key, &tree)?;
        file.write_all(&payload)?;
        let archive = Archive::open(file.path().to_owned(), plugin, key, &cipher)?;
        let start = BLOCK / 4096 * 4096;
        let mut received = 0;
        archive.read_range(2, start, tree.quota - start, |pos, bytes| {
            assert_eq!(pos, start);
            assert_eq!(bytes, &data[pos as usize..]);
            received += bytes.len();
            Ok(())
        })?;
        assert_eq!(received as u64, tree.quota - start);
        file.seek(SeekFrom::End(-1))?;
        file.write_all(&[payload.last().unwrap() ^ 1])?;
        assert!(
            archive
                .read_range(2, start, 4096, |_, _| panic!("damaged data delivered"))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn rejects_reserved_windows_components() {
        for name in [
            r"a\b", "a:b", "COM1.txt", "NUL", "LPT².x", "tail.", "tail ", "..",
        ] {
            assert!(validate_name(name).is_err(), "{name}");
        }
        assert!(validate_name("Рабочие заметки.txt").is_ok());
    }
}
