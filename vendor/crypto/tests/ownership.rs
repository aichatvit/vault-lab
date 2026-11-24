use crypto::wrappers::{
    asymmetric::Asymmetric, base_crypt::BaseCrypt, bio_rand_kb::BioBuffer, bio_rand_kb::BioRandKb,
    crypto_init_by_seq::CryptoInitBySeq, diffie_hellman::DiffieHellman,
    digest_length::DigestLength, error::Error, hash::Hash, hmac::Hmac, kdf_tree::KdfTree,
    key_container::KeyContainer, library::Library, password::Password, plugin_buffer::PluginBuffer,
    random::Random, sequence_checker::SequenceChecker, signanture::Signature, symmetric::Symmetric,
    symmetric::SymmetricMode,
};
use std::{path::PathBuf, process::Command};

static_assertions::assert_not_impl_any!(Library: Send, Sync);
static_assertions::assert_not_impl_any!(BaseCrypt: Send, Sync);
static_assertions::assert_not_impl_any!(Hash: Send, Sync, Clone);
static_assertions::assert_not_impl_any!(Hmac: Send, Sync, Clone);
static_assertions::assert_not_impl_any!(KdfTree: Send, Sync, Clone);
static_assertions::assert_not_impl_any!(SequenceChecker: Send, Sync, Clone);
static_assertions::assert_not_impl_any!(Random: Send, Sync, Clone);
static_assertions::assert_not_impl_any!(Symmetric: Send, Sync, Clone);
static_assertions::assert_not_impl_any!(Signature: Send, Sync, Clone);
static_assertions::assert_not_impl_any!(Asymmetric: Send, Sync, Clone);
static_assertions::assert_not_impl_any!(DiffieHellman: Send, Sync, Clone);
static_assertions::assert_not_impl_any!(KeyContainer: Send, Sync, Clone);
static_assertions::assert_not_impl_any!(BioRandKb: Send, Sync, Clone);
static_assertions::assert_not_impl_any!(PluginBuffer: Send, Sync, Clone);
static_assertions::assert_not_impl_any!(BioBuffer: Send, Sync, Clone);

struct Fixture {
    directory: PathBuf,
    binary: PathBuf,
}
impl Fixture {
    fn build() -> Self {
        let directory =
            std::env::temp_dir().join(format!("crypto-ownership-fixture-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let binary = directory.join(format!(
            "{}ownership_fixture{}",
            std::env::consts::DLL_PREFIX,
            std::env::consts::DLL_SUFFIX
        ));
        let compiler = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let result = Command::new(compiler)
            .args([
                "--crate-type",
                "cdylib",
                "--edition=2024",
                "--crate-name",
                "ownership_fixture",
            ])
            .arg(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/support/ownership_fixture.rs"),
            )
            .arg("--out-dir")
            .arg(&directory)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "Fixture compilation: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        Self { directory, binary }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Только файлы непосредственно в отдельном каталоге этого теста; без рекурсии.
        if let Ok(files) = std::fs::read_dir(&self.directory) {
            for file in files.flatten() {
                let _ = std::fs::remove_file(file.path());
            }
        }
        let _ = std::fs::remove_dir(&self.directory);
    }
}

#[test]
fn ownership_missing_symbols_and_failure_cleanup() {
    let fixture = Fixture::build();
    // БЕЗОПАСНОСТЬ: библиотека только что собрана из исходников данного теста.
    unsafe {
        let probe = libloading::Library::new(&fixture.binary).unwrap();
        let state = probe
            .get::<unsafe extern "C" fn() -> u32>(b"fixture_state\0")
            .unwrap();
        let failure = probe
            .get::<unsafe extern "C" fn(i32)>(b"fixture_failure\0")
            .unwrap();
        let library = Library::load(&fixture.binary).unwrap();
        let parent = BaseCrypt::new(&library, CryptoInitBySeq::new(vec![1; 64])).unwrap();
        assert_eq!(state(), 1);
        let mut hash = Hash::new(&parent, DigestLength::Bits256).unwrap();
        assert_eq!(state(), 1 | 1 << 8);
        assert!(matches!(
            hash.update(b"test"),
            Err(Error::MissingSymbol("updateHash"))
        ));
        drop(hash);
        assert_eq!(state(), 1);

        failure(77);
        assert!(matches!(
            Hash::new(&parent, DigestLength::Bits256),
            Err(Error::Native { code: 77, .. })
        ));
        assert_eq!(
            state(),
            1,
            "Failed child creation leaked its returned context"
        );
        failure(0);
        {
            let mut agreement = DiffieHellman::new(&parent).unwrap();
            let password = Password::new("test").unwrap();
            assert!(matches!(
                agreement.export_derived_by_password(&password),
                Err(Error::InvalidInput(_))
            ));
            let step = agreement.derive_step(&[1]).unwrap();
            assert!(step.finished);
            assert_eq!(&*step.message.unwrap(), &[11, 22, 33, 44]);
            assert_eq!(
                &*agreement.export_derived_by_password(&password).unwrap(),
                &[11, 22, 33, 44]
            );
            assert!(matches!(
                agreement.derive_step(&[1]),
                Err(Error::InvalidInput(_))
            ));
        }
        assert_eq!(state(), 1);
        let cipher = Symmetric::new(&parent, SymmetricMode::Ecb).unwrap();
        failure(88);
        assert!(matches!(cipher.key(), Err(Error::Native { code: 88, .. })));
        assert_eq!(state(), 1 | 1 << 8, "Error output allocation leaked");
        failure(0);
        let buffer = cipher.key().unwrap();
        assert_eq!(state(), 1 | 1 << 8 | 1 << 16);
        drop(parent);
        drop(library);
        assert_eq!(&*buffer, &[11, 22, 33, 44]);
        drop(cipher);
        assert_eq!(
            state(),
            1 | 1 << 16,
            "Parent died before its output allocation"
        );
        drop(buffer);
        assert_eq!(state(), 0, "Leaked resources or invalid destructor order");
    }
}
