mod cipher;
mod format;
mod fs;
mod probe;
mod safe_path;
mod session;
mod store;
use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use zeroize::Zeroizing;
#[derive(Parser)]
#[command(
    version,
    about = "Experimental encrypted FUSE vault using the supplied GOST crypto plugin"
)]
struct Args {
    #[arg(long, global = true, default_value = "lib/libaldcrypto.so")]
    plugin: PathBuf,
    /// Use insecure XOR for benchmarks on synthetic data. Uses a separate container format.
    #[arg(long, global = true)]
    benchmark_xor: bool,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Generate a random 32-byte raw key. Prints the secret once; do not log it.
    Keygen,
    /// Create a new VLAGOST2 container file. Default quota: 1 GB.
    Init {
        storage: PathBuf,
        #[arg(long, conflicts_with = "quota_gb")]
        quota_mb: Option<u64>,
        #[arg(long)]
        quota_gb: Option<u64>,
    },
    /// Mount privately and start the descriptor-based test client. Requires sudo.
    Open {
        storage: PathBuf,
        #[arg(long)]
        test: bool,
        #[arg(long, requires = "test")]
        attack: bool,
        #[arg(long, conflicts_with = "test")]
        verify: bool,
    },
    /// Authenticate a VLAGOST2 container without mounting or printing contents.
    Check { storage: PathBuf },
    /// Mount in a visible directory until Ctrl-C or external unmount. Requires sudo.
    Mount {
        storage: PathBuf,
        mountpoint: PathBuf,
    },
    #[command(hide = true)]
    Probe {
        #[arg(long)]
        fd: i32,
        #[arg(long)]
        test: bool,
        #[arg(long)]
        verify: bool,
    },
}
fn key() -> Result<Zeroizing<Vec<u8>>> {
    let text = Zeroizing::new(rpassword::prompt_password(
        "Key (64 hex characters, hidden): ",
    )?);
    ensure!(
        text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()),
        "Expected exactly 64 hex characters (raw 32-byte key, not password)"
    );
    let mut key = Zeroizing::new(vec![0; 32]);
    hex::decode_to_slice(text.as_bytes(), &mut key[..])?;
    Ok(key)
}
fn harden() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    ensure!(
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0,
        "Cannot disable core dumps"
    );
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } == 0,
        "Cannot disable dumpability"
    );
    Ok(())
}
fn run() -> Result<()> {
    let args = Args::parse();
    harden()?;
    match args.command {
        Action::Keygen => {
            let key = Zeroizing::new(cipher::random::<32>()?);
            let text = Zeroizing::new(hex::encode(key.as_slice()));
            println!("{}", text.as_str());
        }
        Action::Probe { fd, test, verify } => {
            if verify {
                probe::verify_persistent(fd)?;
            } else {
                probe::run(fd, test)?;
            }
        }
        action => {
            let (c, key) = if args.benchmark_xor {
                eprintln!("WARNING: insecure XOR benchmark mode; synthetic data only");
                (
                    cipher::Cipher::benchmark_xor(),
                    Zeroizing::new(vec![0x42; 32]),
                )
            } else {
                let plugin = std::fs::canonicalize(&args.plugin)?;
                (cipher::Cipher::load(&plugin)?, key()?)
            };
            let format = std::str::from_utf8(c.container_magic())?;
            match action {
                Action::Init {
                    storage,
                    quota_mb,
                    quota_gb,
                } => {
                    let quota = match quota_mb {
                        Some(mb) => mb.checked_mul(1_000_000),
                        None => quota_gb.unwrap_or(1).checked_mul(1_000_000_000),
                    }
                    .filter(|&quota| quota > 0)
                    .ok_or_else(|| anyhow::anyhow!("Invalid quota"))?;
                    store::Store::init(&storage, &c, &key, quota)?;
                    println!("Created {format} container; quota {}", display_size(quota));
                }
                Action::Check { storage } => {
                    let (entries, used, quota) = store::Store::check(&storage, &c, &key)?;
                    let status = if args.benchmark_xor {
                        "benchmark structure checked"
                    } else {
                        "authenticated"
                    };
                    println!(
                        "PASS: {format} {status}; {entries} entries; {} / {}",
                        display_size(used),
                        display_size(quota)
                    );
                }
                Action::Open {
                    storage,
                    test,
                    attack,
                    verify,
                } => {
                    session::open(&storage, c, key, test, attack, verify)?;
                    println!("Session closed");
                }
                Action::Mount {
                    storage,
                    mountpoint,
                } => {
                    session::mount_visible(&storage, c, key, &mountpoint)?;
                }
                _ => unreachable!(),
            }
        }
    }
    Ok(())
}
fn display_size(bytes: u64) -> String {
    let (unit, scale, precision) = if bytes >= 1_000_000_000 {
        ("GB", 1_000_000_000, 9)
    } else {
        ("MB", 1_000_000, 6)
    };
    let fraction = format!("{:0precision$}", bytes % scale);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        format!("{} {unit}", bytes / scale)
    } else {
        format!("{}.{fraction} {unit}", bytes / scale)
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}
