use super::*;
use crate::cipher::Cipher;
use std::os::unix::fs::FileExt;

const KEY: [u8; 32] = [75; 32];

fn reopen(path: &Path) -> Result<Store> {
    Store::open(
        path,
        Cipher::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("lib/libaldcrypto.so"))?,
        Zeroizing::new(KEY.to_vec()),
    )
}

#[test]
fn synced_patches_survive_checkpoints_truncation_and_packing() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("data");
    let c = Cipher::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("lib/libaldcrypto.so"))?;
    Store::init(&path, &c, &KEY, 3 * BLOCK)?;
    let mut s = Store::open(&path, c, Zeroizing::new(KEY.to_vec()))?;
    let id = s.add_node(1, "file".into(), false)?;
    let mut expected = vec![0x33; 2 * BLOCK as usize];
    s.update(id, 2 * BLOCK, 0, &expected)?;
    for i in 0..35 {
        let offset = (i % 2) * BLOCK as usize + (i / 2) * 4000;
        let bytes = vec![i as u8; 4096];
        s.write_span(id, offset as u64, &bytes, true)?;
        expected[offset..offset + 4096].copy_from_slice(&bytes);
    }
    assert!(!s.work.patches.is_empty());
    assert!(s.work.journal.is_some());
    drop(s);
    let mut s = reopen(&path)?;
    assert_eq!(&s.read(id, 0, 2 * BLOCK as u32)?[..], expected);
    s.update(id, BLOCK + 4100, 0, &[])?;
    expected.truncate(BLOCK as usize + 4100);
    s.close()?;
    drop(s);
    let mut s = reopen(&path)?;
    assert_eq!(&s.read(id, 0, 2 * BLOCK as u32)?[..], expected);
    s.close()
}

#[test]
fn damaged_checkpoint_or_work_file_cannot_replace_container() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("data");
    let cipher = Cipher::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("lib/libaldcrypto.so"))?;
    Store::init(&path, &cipher, &KEY, BLOCK)?;
    let original = std::fs::read(&path)?;
    let mut s = Store::open(&path, cipher, Zeroizing::new(KEY.to_vec()))?;
    let id = s.add_node(1, "file".into(), false)?;
    s.update(id, 6000, 0, &[7; 6000])?;
    let dir = tmp.path().join(".data.work");
    let checkpoint = std::fs::read_dir(&dir)?
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("checkpoint-")
        })
        .unwrap();
    let bytes = std::fs::read(&checkpoint)?;
    drop(s);
    std::fs::write(&checkpoint, &bytes[..bytes.len() - 1])?;
    assert!(reopen(&path).is_err());
    std::fs::write(&checkpoint, bytes)?;
    let mut s = reopen(&path)?;
    let file = s.work.open_file(id, libc::O_RDWR)?;
    let mut byte = [0];
    file.read_exact_at(&mut byte, 37)?;
    byte[0] ^= 1;
    file.write_all_at(&byte, 37)?;
    assert!(s.close().is_err());
    assert_eq!(std::fs::read(&path)?, original);
    Ok(())
}

#[test]
fn fsync_is_per_file_and_eviction_preserves_sparse_writes() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("data");
    let cipher = Cipher::benchmark_xor();
    Store::init(&path, &cipher, &KEY, 20 * BLOCK)?;
    let mut s = Store::open(&path, cipher, Zeroizing::new(KEY.to_vec()))?;
    let a = s.add_node(1, "a".into(), false)?;
    let b = s.add_node(1, "b".into(), false)?;
    s.write_span(a, 0, b"aaa", false)?;
    s.write_span(b, 0, b"bbb", false)?;
    s.flush_pending(Some(a))?;
    assert_eq!(s.tree.nodes[&b].size, 0);
    assert_eq!(&s.read(b, 0, 3)?[..], b"bbb");
    drop(s);
    let mut s = Store::open(&path, Cipher::benchmark_xor(), Zeroizing::new(KEY.to_vec()))?;
    assert_eq!(&s.read(a, 0, 3)?[..], b"aaa");
    assert!(s.read(b, 0, 3)?.is_empty());
    s.write_span(b, 10 * BLOCK, b"end", false)?;
    for i in 0..10 {
        s.write_span(b, i * BLOCK, &[i as u8; 7], false)?;
    }
    s.close()?;
    drop(s);
    let mut s = Store::open(&path, Cipher::benchmark_xor(), Zeroizing::new(KEY.to_vec()))?;
    for i in 0..10 {
        let mut bytes = [i as u8; 8];
        bytes[7] = 0;
        assert_eq!(&s.read(b, i * BLOCK, 8)?[..], bytes);
    }
    assert_eq!(&s.read(b, 10 * BLOCK, 3)?[..], b"end");
    s.close()
}
