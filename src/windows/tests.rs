use super::*;
use crate::format::BLOCK;
use std::{
    io::{SeekFrom, Write},
    thread,
    time::Instant,
};
use zeroize::Zeroizing;

#[test]
#[ignore = "requires NTFS, Windows Cloud Files and VAULT_TEST_WINDOWS_DLL"]
fn explorer_session_roundtrip() -> Result<()> {
    let plugin = fs::canonicalize(
        std::env::var_os("VAULT_TEST_WINDOWS_DLL").context("Set VAULT_TEST_WINDOWS_DLL")?,
    )?;
    let tmp = tempfile::tempdir()?;
    let storage = tmp.path().join("Тестовый архив.sbox");
    let state = tmp.path().join("VaultLab/sessions/test");
    let key = Zeroizing::new(random::<32>()?.to_vec());
    let cipher = Cipher::load(&plugin)?;
    Container::create_empty(&storage, &cipher, &key, 3 * BLOCK)?;
    let view = state.join("opened");
    let mut expected: Vec<_> = (0..2 * BLOCK + 11).map(|i| (i % 251) as u8).collect();
    let mut previous_records = None;
    for pass in 0..3 {
        let (s, d, p, k) = (storage.clone(), state.clone(), plugin.clone(), key.clone());
        let worker = thread::spawn(move || mount(&s, &d, p, false, k));
        let deadline = Instant::now() + Duration::from_secs(30);
        while !state.join("endpoint").is_file() {
            if worker.is_finished() {
                worker.join().expect("provider panicked")?;
                anyhow::bail!("Provider stopped before publishing the session");
            }
            ensure!(Instant::now() < deadline, "Mount timed out");
            thread::sleep(Duration::from_millis(100));
        }
        let shortcut = tmp
            .path()
            .join("VaultLab/Containers/Тестовый архив.sbox.lnk");
        assert!(shortcut.is_file());
        match pass {
            0 => {
                fs::create_dir(view.join("folder"))?;
                fs::write(view.join("folder/данные.bin"), &expected)?;
                fs::write(view.join("remove.txt"), b"delete on second mount")?;
                let writer = OpenOptions::new()
                    .write(true)
                    .open(view.join("folder/данные.bin"))?;
                ensure!(
                    unmount(&state).is_err(),
                    "Open writer was silently accepted"
                );
                drop(writer);
            }
            1 => {
                let path = view.join("folder/данные.bin");
                let mut f = OpenOptions::new().read(true).write(true).open(&path)?;
                f.seek(SeekFrom::Start(BLOCK - 4))?;
                let mut read = [0; 8];
                f.read_exact(&mut read)?;
                assert_eq!(read, expected[BLOCK as usize - 4..BLOCK as usize + 4]);
                f.seek(SeekFrom::Start(BLOCK - 4))?;
                f.write_all(b"modified")?;
                expected[BLOCK as usize - 4..BLOCK as usize + 4].copy_from_slice(b"modified");
                drop(f);
                fs::rename(path, view.join("renamed.bin"))?;
                fs::remove_file(view.join("remove.txt"))?;
            }
            _ => {
                assert_eq!(fs::read(view.join("renamed.bin"))?, expected);
                assert!(!view.join("remove.txt").try_exists()?);
            }
        }
        unmount(&state)?;
        worker.join().expect("provider panicked")?;
        if pass != 0 {
            let saved = Archive::open(storage.clone(), plugin.clone(), key.clone(), &cipher)?;
            let (&id, node) = saved
                .tree
                .nodes
                .iter()
                .find(|(_, n)| n.name == "renamed.bin")
                .unwrap();
            let records = (id, node.tags.clone());
            if let Some(previous) = &previous_records {
                assert_eq!(
                    &records, previous,
                    "Unchanged placeholder was encrypted again"
                );
            }
            previous_records = Some(records);
        }
        assert!(!shortcut.exists());
        ensure!(
            !view.try_exists()?,
            "Working folder survived a successful unmount"
        );
    }
    Ok(())
}

#[test]
fn sidebar_same_name_recovery_and_cleanup() -> Result<()> {
    let profile = tempfile::tempdir()?;
    let a = profile.path().join("sessions/a");
    let b = profile.path().join("sessions/b");
    for state in [&a, &b] {
        fs::create_dir_all(state.join("opened"))?;
        sidebar::publish(Path::new("Работа.sbox"), state, &state.join("opened"))?;
    }
    let list = profile.path().join("Containers");
    let first = list.join("Работа.sbox.lnk");
    let second = list.join("Работа.sbox (2).lnk");
    assert_eq!(
        file_id(&File::open(&first)?)?,
        file_id(&File::open(a.join("sidebar.lnk"))?)?
    );
    assert_eq!(
        file_id(&File::open(&second)?)?,
        file_id(&File::open(b.join("sidebar.lnk"))?)?
    );
    sidebar::remove(&a)?;
    sidebar::publish(Path::new("Работа.sbox"), &b, &b.join("opened"))?;
    assert!(!first.exists());
    assert!(second.exists());
    // An unrelated replacement must survive teardown of the original session.
    fs::remove_file(&second)?;
    fs::write(&second, b"user file")?;
    sidebar::remove(&b)?;
    assert_eq!(fs::read(second)?, b"user file");
    Ok(())
}

#[test]
#[ignore = "requires Windows and VAULT_TEST_WINDOWS_DLL"]
fn whole_file_staging_and_immediate_close() -> Result<()> {
    let plugin = PathBuf::from(
        std::env::var_os("VAULT_TEST_WINDOWS_DLL").context("Set VAULT_TEST_WINDOWS_DLL")?,
    );
    let cipher = Cipher::load(&plugin)?;
    let key = Zeroizing::new(random::<32>()?.to_vec());
    let tmp = tempfile::tempdir()?;
    let base = tmp.path().join("base.sbox");
    Container::create_empty(&base, &cipher, &key, 4 * BLOCK)?;
    let archive = Archive::open(base, plugin.clone(), key.clone(), &cipher)?;
    let view = tmp.path().join("opened");
    fs::create_dir(&view)?;
    let mut cache = staging::Staging::new(tmp.path(), archive.tree.next);
    let path = view.join("ready.bin");
    let data = vec![19; BLOCK as usize + 11];
    let mut writer = File::create(&path)?;
    writer.write_all(&data)?;
    assert!(cache.scan(&view, &archive, &cipher));
    assert!(!cache.files.contains_key(&path));
    drop(writer);
    assert!(!cache.scan(&view, &archive, &cipher));
    let id = cache.files[&path].id;
    let ready_tags = cache.files[&path].tags.clone();
    // Unmount before the next directory notification. One path is new,
    // the other is changed later without changing its length.
    fs::write(view.join("late.txt"), b"late")?;
    for changed in [false, true] {
        let mut expected = data.clone();
        if changed {
            expected[0] ^= 1;
            fs::write(&path, &expected)?;
        }
        let snapshot = Snapshot::capture(&view, archive.tree.quota)?;
        let (packed, _) = snapshot.pack(&archive, &cipher, &archive.baseline, &mut cache)?;
        let saved = Archive::open(packed.path().into(), plugin.clone(), key.clone(), &cipher)?;
        let node = &saved.tree.nodes[&id];
        assert_eq!(node.tags == ready_tags, !changed);
        let mut actual = Vec::new();
        saved.read_range(id, 0, node.size, |_, part| {
            actual.extend_from_slice(part);
            Ok(())
        })?;
        assert_eq!(actual, expected);
        let (&late, _) = saved
            .tree
            .nodes
            .iter()
            .find(|(_, node)| node.name == "late.txt")
            .unwrap();
        saved.read_range(late, 0, 4, |_, part| {
            assert_eq!(part, b"late");
            Ok(())
        })?;
    }
    Ok(())
}
