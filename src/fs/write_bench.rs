use super::*;
use crate::{
    cipher::Cipher,
    format::{Container, Tree},
};
use anyhow::{Result, ensure};
use std::{fs::File, path::Path, time::Instant};
use zeroize::Zeroizing;

#[test]
#[ignore = "release write benchmark; set VAULT_BENCH_DIR to choose the backing filesystem"]
fn write_profiles() -> Result<()> {
    let directory = std::env::var_os("VAULT_BENCH_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    for scenario in [
        "sequential",
        "8 MB requests",
        "two files",
        "small edits",
        "sync edits",
        "small files",
        "large tree",
    ] {
        measure(&directory, scenario)?;
    }
    Ok(())
}

fn measure(directory: &Path, scenario: &str) -> Result<()> {
    let scratch = tempfile::tempdir_in(directory)?;
    let path = scratch.path().join("bench");
    let plugin = Path::new(env!("CARGO_MANIFEST_DIR")).join("lib/libaldcrypto.so");
    let cipher = Cipher::load(&plugin)?;
    let key = [73; 32];
    let mut tree = Tree::empty(1_000_000_000);
    let count = match scenario {
        "two files" => 2,
        "small files" => 200,
        _ => 1,
    };
    if scenario != "small files" {
        for i in 0..count {
            tree.nodes
                .insert(tree.next, Node::new(1, format!("file{i}"), false));
            tree.next += 1;
        }
    }
    if scenario == "large tree" {
        for i in 0..10_000 {
            tree.nodes
                .insert(tree.next, Node::new(1, format!("dir{i:05}"), true));
            tree.next += 1;
        }
    }
    Container::new(&cipher, &key)?.write_index(&mut File::create(&path)?, &cipher, &key, &tree)?;
    let mut store = Store::open(&path, cipher, Zeroizing::new(key.to_vec()))?;
    let mut fs = VaultFs::new(&mut store);
    let edits = matches!(scenario, "small edits" | "sync edits");
    let size = if edits {
        8_000_000
    } else if scenario == "small files" {
        200 * 4096
    } else {
        24_000_000
    };
    let mut data = vec![0; size];
    getrandom::fill(&mut data).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut expected = vec![Vec::new(); count];
    let mut requests = Vec::new();
    if edits {
        fs.write_data(2, 0, &data, true).unwrap();
        expected[0] = data.clone();
        for i in 0..64 {
            let offset = i % 8 * 1_000_000 + i / 8 * 4096;
            expected[0][offset..offset + 4096].copy_from_slice(&data[i * 4096..(i + 1) * 4096]);
            requests.push((0, offset, i * 4096, 4096));
        }
    } else {
        let chunk = match scenario {
            "small files" => 4096,
            "8 MB requests" => 8_000_000,
            _ => 131072,
        };
        for (i, part) in data.chunks(chunk).enumerate() {
            let f = i % count;
            requests.push((f, expected[f].len(), i * chunk, part.len()));
            expected[f].extend_from_slice(part);
        }
    }
    let start = Instant::now();
    let mut bytes = 0;
    for (f, offset, source, len) in requests {
        let id = f as u64 + 2;
        if scenario == "small files" {
            assert_eq!(fs.add(1, OsStr::new(&format!("file{f}")), false), Ok(id));
        }
        assert_eq!(
            fs.write_data(id, offset as u64, &data[source..source + len], false),
            Ok(len as u32)
        );
        if matches!(scenario, "small files" | "sync edits") {
            fs.flush_pending(Some(id)).unwrap();
        }
        bytes += len;
    }
    fs.flush_pending(None).unwrap();
    let write = start.elapsed();
    let close = Instant::now();
    store.close()?;
    println!(
        "{scenario}: {bytes} bytes, {:.3} s, {:.3} MB/s; pack {:.3} s",
        write.as_secs_f64(),
        bytes as f64 / 1e6 / write.as_secs_f64(),
        close.elapsed().as_secs_f64()
    );
    drop(store);
    let mut reopened = Store::open(&path, Cipher::load(&plugin)?, Zeroizing::new(key.to_vec()))?;
    for (i, file) in expected.iter().enumerate() {
        ensure!(
            reopened
                .read(2 + i as u64, 0, file.len() as u32)?
                .as_slice()
                == file,
            "Copy differs: {scenario}"
        );
    }
    reopened.close()
}
