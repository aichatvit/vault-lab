//! Native GOST operations and an isolated XOR backend for benchmarks.
use anyhow::{Result, bail, ensure};
use crypto::wrappers::{
    base_crypt::BaseCrypt,
    crypto_init_by_seq::CryptoInitBySeq,
    digest_length::DigestLength,
    error::Error,
    hmac::Hmac,
    library::Library,
    symmetric::{Symmetric, SymmetricMode},
};
use std::{
    cell::OnceCell,
    fs::File,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("OS RNG: {e}"))?;
    Ok(bytes)
}

pub struct Cipher {
    ctx: Option<BaseCrypt>,
    plugin: Option<Arc<File>>,
    worker: OnceCell<Option<SealWorker>>,
}
impl Cipher {
    pub fn load(path: &Path) -> Result<Self> {
        let module = Arc::new(File::open(path)?);
        // SAFETY: operator explicitly supplies a trusted native plugin with matching ABI.
        let lib = unsafe { Library::load(path) }?;
        for attempt in 1..=16 {
            match BaseCrypt::new(&lib, CryptoInitBySeq::new(random::<64>()?.to_vec())) {
                Ok(ctx) => {
                    return Ok(Self {
                        ctx: Some(ctx),
                        plugin: Some(module),
                        worker: OnceCell::new(),
                    });
                }
                Err(Error::Native {
                    code: 17 | 506 | 507,
                    ..
                }) if attempt < 16 => continue,
                Err(e) => return Err(e.into()),
            }
        }
        bail!("Plugin rejected 16 initialization seeds")
    }
    pub fn benchmark_xor() -> Self {
        Self {
            ctx: None,
            plugin: None,
            worker: OnceCell::new(),
        }
    }

    pub fn prepare_worker(&self) {
        self.worker.get_or_init(|| {
            self.plugin
                .as_ref()
                .and_then(|module| SealWorker::start(module.clone()))
        });
    }

    // Each native context is created, used and destroyed by its own thread.
    pub fn seal_async(
        &self,
        keys: &[u8],
        context: [u8; 48],
        plain: Zeroizing<Vec<u8>>,
    ) -> Result<mpsc::Receiver<Result<Vec<u8>>>> {
        self.prepare_worker();
        let worker = self
            .worker
            .get()
            .and_then(Option::as_ref)
            .filter(|w| w.ready.load(Ordering::Acquire));
        let (reply, result) = mpsc::channel();
        if let Some(worker) = worker {
            let job = SealJob {
                keys: Zeroizing::new(keys.to_vec()),
                context,
                plain,
                reply,
            };
            worker
                .jobs
                .as_ref()
                .unwrap()
                .send(job)
                .map_err(|_| anyhow::anyhow!("Encryption worker stopped"))?;
        } else {
            let _ = reply.send(self.seal(keys, &context, &plain));
        }
        Ok(result)
    }

    pub fn container_magic(&self) -> &'static [u8; 8] {
        if self.ctx.is_some() {
            b"VLAGOST2"
        } else {
            b"VLAXOR01"
        }
    }

    pub fn workspace_magic(&self) -> &'static [u8; 8] {
        if self.ctx.is_some() {
            b"VLAWORK2"
        } else {
            b"VLAXWORK"
        }
    }

    // RFC 7836 KDF_TREE, r=1, L=512 bits. Linux plugin lacks the exported KDF API.
    // Only framing is implemented here: HMAC itself always runs in the supplied plugin.
    pub fn derive(&self, key: &[u8], label: &[u8], seed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(key.len() == 32, "Master key must be 32 bytes");
        let Some(ctx) = &self.ctx else {
            return Ok(Zeroizing::new(key.repeat(2)));
        };
        let mut out = Zeroizing::new(Vec::with_capacity(64));
        for counter in [1, 2] {
            let mut input = vec![counter];
            input.extend_from_slice(label);
            input.push(0);
            input.extend_from_slice(seed);
            input.extend_from_slice(&[2, 0]);
            let mut hmac = Hmac::with_key(ctx, DigestLength::Bits256, key)?;
            let part = Zeroizing::new(hmac.compute(&input)?);
            out.extend_from_slice(&part);
        }
        Ok(out)
    }
    fn sym(ctx: &BaseCrypt, key: &[u8]) -> Result<Symmetric> {
        let mut sym = Symmetric::new(ctx, SymmetricMode::Cbc)?;
        sym.set_key(key)?;
        let meta = sym.data()?;
        ensure!(
            meta.blockSize == 16 && (16..=128).contains(&meta.ivSize),
            "Unexpected CBC parameters: block={}, iv={}",
            meta.blockSize,
            meta.ivSize
        );
        Ok(sym)
    }
    pub fn iv_size(&self, keys: &[u8]) -> Result<usize> {
        match &self.ctx {
            Some(ctx) => Ok(Self::sym(ctx, &keys[..32])?.data()?.ivSize as usize),
            None => Ok(16),
        }
    }

    fn tag(&self, keys: &[u8], context: &[u8], encrypted: &[u8]) -> Result<Vec<u8>> {
        let Some(ctx) = &self.ctx else {
            return Ok(vec![0; 32]);
        };
        let mut hmac = Hmac::with_key(ctx, DigestLength::Bits256, &keys[32..])?;
        hmac.update(context)?;
        hmac.update(encrypted)?;
        Ok(hmac.finalize()?)
    }

    pub fn seal(&self, keys: &[u8], context: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
        let mut sym = self
            .ctx
            .as_ref()
            .map(|ctx| Self::sym(ctx, &keys[..32]))
            .transpose()?;
        let iv_len = match &sym {
            Some(sym) => sym.data()?.ivSize as usize,
            None => 16,
        };
        let mut iv = vec![0; iv_len];
        getrandom::fill(&mut iv).map_err(|e| anyhow::anyhow!("OS RNG: {e}"))?;
        let pad = 16 - plain.len() % 16;
        let mut padded = Zeroizing::new(Vec::with_capacity(plain.len() + pad));
        padded.extend_from_slice(plain);
        padded.resize(plain.len() + pad, pad as u8);
        let mut record = Vec::with_capacity(iv_len + padded.len() + 32);
        record.extend_from_slice(&iv);
        if let Some(sym) = &mut sym {
            record.extend_from_slice(&sym.encrypt(&padded, &record[..iv_len])?);
        } else {
            benchmark_xor(&mut padded, keys, &record);
            record.extend_from_slice(&padded);
        }
        record.extend_from_slice(&self.tag(keys, context, &record)?);
        Ok(record)
    }

    pub fn authenticate(&self, keys: &[u8], context: &[u8], record: &[u8]) -> Result<()> {
        ensure!(record.len() >= 64, "Invalid record length");
        let (encrypted, tag) = record.split_at(record.len() - 32);
        ensure!(
            bool::from(self.tag(keys, context, encrypted)?.as_slice().ct_eq(tag)),
            "Authentication failed (key or data)"
        );
        Ok(())
    }

    pub fn unseal(
        &self,
        keys: &[u8],
        context: &[u8],
        iv_len: usize,
        record: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            (16..=128).contains(&iv_len)
                && record.len() >= iv_len + 16 + 32
                && (record.len() - iv_len - 32).is_multiple_of(16),
            "Invalid framing"
        );
        self.authenticate(keys, context, record)?;
        let end = record.len() - 32;
        let (iv, encrypted) = record[..end].split_at(iv_len);
        let mut plain = if let Some(ctx) = &self.ctx {
            let mut sym = Self::sym(ctx, &keys[..32])?;
            ensure!(
                sym.data()?.ivSize as usize == iv_len,
                "Incompatible plugin IV size"
            );
            Zeroizing::new(sym.decrypt(encrypted, iv)?)
        } else {
            ensure!(iv_len == 16, "Invalid benchmark IV size");
            let mut plain = Zeroizing::new(encrypted.to_vec());
            benchmark_xor(&mut plain, keys, iv);
            plain
        };
        let pad = usize::from(
            *plain
                .last()
                .ok_or_else(|| anyhow::anyhow!("Empty plaintext"))?,
        );
        ensure!(
            (1..=16).contains(&pad)
                && pad <= plain.len()
                && plain[plain.len() - pad..]
                    .iter()
                    .all(|&b| usize::from(b) == pad),
            "Invalid padding"
        );
        let len = plain.len() - pad;
        plain.truncate(len);
        Ok(plain)
    }
}

struct SealJob {
    keys: Zeroizing<Vec<u8>>,
    context: [u8; 48],
    plain: Zeroizing<Vec<u8>>,
    reply: mpsc::Sender<Result<Vec<u8>>>,
}

struct SealWorker {
    ready: Arc<AtomicBool>,
    jobs: Option<mpsc::SyncSender<SealJob>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl SealWorker {
    fn start(module: Arc<File>) -> Option<Self> {
        let (jobs, queue) = mpsc::sync_channel::<SealJob>(1);
        let ready = Arc::new(AtomicBool::new(false));
        let initialized = ready.clone();
        let thread = thread::Builder::new()
            .name("vault-encrypt".into())
            .spawn(move || {
                // Keep the originally selected inode even if the plugin path is
                // replaced between session startup and the first bulk write.
                let path = PathBuf::from(format!("/proc/self/fd/{}", module.as_raw_fd()));
                let cipher = match Cipher::load(&path) {
                    Ok(cipher) => cipher,
                    Err(error) => {
                        eprintln!("Using one encryption thread: {error:#}");
                        return;
                    }
                };
                initialized.store(true, Ordering::Release);
                for job in queue {
                    let _ = job
                        .reply
                        .send(cipher.seal(&job.keys, &job.context, &job.plain));
                }
            })
            .ok()?;
        Some(Self {
            ready,
            jobs: Some(jobs),
            thread: Some(thread),
        })
    }
}

impl Drop for SealWorker {
    fn drop(&mut self) {
        self.jobs.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// Reversible masking with a fixed-size repeating key, solely for benchmarking.
fn benchmark_xor(data: &mut [u8], keys: &[u8], iv: &[u8]) {
    let mask = Zeroizing::new(std::array::from_fn::<_, 32, _>(|i| keys[i] ^ iv[i % 16]));
    for chunk in data.chunks_mut(32) {
        for (byte, mask) in chunk.iter_mut().zip(mask.iter()) {
            *byte ^= mask;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cipher() -> Cipher {
        Cipher::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("lib/libaldcrypto.so")).unwrap()
    }
    #[test]
    fn kuznechik_known_vector() {
        let c = cipher();
        let mut sym = Symmetric::new(c.ctx.as_ref().unwrap(), SymmetricMode::Ecb).unwrap();
        sym.set_key(
            &hex::decode("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
                .unwrap(),
        )
        .unwrap();
        let plain = hex::decode("1122334455667700ffeeddccbbaa9988").unwrap();
        let encrypted = sym.encrypt(&plain, &[]).unwrap();
        assert_eq!(hex::encode(&encrypted), "7f679d90bebc24305a468d42b9d4edcd");
        assert_eq!(sym.decrypt(&encrypted, &[]).unwrap(), plain);
    }
    #[test]
    fn kdf_rfc7836_vector() {
        let c = cipher();
        let actual = c
            .derive(
                &(0..32).collect::<Vec<u8>>(),
                &hex::decode("26bdb878").unwrap(),
                &hex::decode("af21434145656378").unwrap(),
            )
            .unwrap();
        assert_eq!(
            hex::encode(actual.as_slice()),
            "22b6837845c6bef65ea71672b265831086d3c76aebe6dae91cad51d83f79d16b074c9330599d7f8d712fca54392f4ddde93751206b3584c8f43f9e6dc51531f9"
        );
    }
    #[test]
    fn roundtrip_tamper_wrong_key_and_random_iv() {
        let c = cipher();
        let context = b"test context";
        let keys = c.derive(&[0x42; 32], b"test", context).unwrap();
        let wrong = c.derive(&[0x43; 32], b"test", context).unwrap();
        let iv = c.iv_size(&keys).unwrap();
        for n in [0, 1, 15, 16, 17, 1024] {
            let p = vec![0xAC; n];
            let enc = c.seal(&keys, context, &p).unwrap();
            assert_eq!(c.unseal(&keys, context, iv, &enc).unwrap().as_slice(), p);
            assert_ne!(enc, c.seal(&keys, context, &p).unwrap());
            assert!(c.unseal(&wrong, context, iv, &enc).is_err());
            assert!(c.unseal(&keys, b"other", iv, &enc).is_err());
            for i in [0, iv, enc.len() / 2, enc.len() - 1] {
                let mut bad = enc.clone();
                bad[i] ^= 1;
                assert!(c.unseal(&keys, context, iv, &bad).is_err(), "byte {i}");
            }
            assert!(c.unseal(&keys, context, iv, &enc[..enc.len() - 1]).is_err());
        }
    }
}
