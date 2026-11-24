use super::*;
use crate::format::{BLOCK, Tree};
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
    let state = tmp.path().join("session");
    let key = Zeroizing::new(random::<32>()?.to_vec());
    let cipher = Cipher::load(&plugin)?;
    let container = Container::new(&cipher, &key)?;
    container.write_index(
        &mut File::create(&storage)?,
        &cipher,
        &key,
        &Tree::empty(3 * BLOCK),
    )?;
    let view = state.join("opened");
    let mut expected: Vec<_> = (0..2 * BLOCK + 11).map(|i| (i % 251) as u8).collect();
    for pass in 0..3 {
        let (s, d, p, k) = (storage.clone(), state.clone(), plugin.clone(), key.clone());
        let worker = thread::spawn(move || mount(&s, &d, p, false, k));
        let deadline = Instant::now() + Duration::from_secs(30);
        while !state.join("endpoint").is_file() {
            if worker.is_finished() {
                worker.join().expect("provider panicked")?;
                bail!("Provider stopped before publishing the session");
            }
            ensure!(Instant::now() < deadline, "Mount timed out");
            thread::sleep(Duration::from_millis(100));
        }
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
        ensure!(
            !view.try_exists()?,
            "Working folder survived a successful unmount"
        );
    }
    Ok(())
}
