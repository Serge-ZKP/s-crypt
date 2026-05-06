use clap::{Parser, Subcommand};
use anyhow::Result;

mod pipeline;
mod crypto;
mod format;
mod metadata;

#[derive(Parser)]
#[command(
    name = "s-crypt",
    version = env!("CARGO_PKG_VERSION"),
    about = "Authenticated, compressed directory encryption tool (.senc)",
    long_about = r#"
S-CRYPT (.senc) FORMAT SPECIFICATION

OVERVIEW:
  s-crypt encrypts files and directories using:
    • tar archival (directories)
    • zstd compression
    • chunked AES-256-GCM
    • Argon2id key derivation (m=65536, t=3, p=4)
    • authenticated metadata binding
    • authenticated final seal (truncation detection)

PIPELINE:
  input → zstd → chunk → AEAD → .senc file

SECURITY MODEL:
  - Password-derived 256-bit key via Argon2id
  - Unique per-file 16-byte salt + 12-byte random base nonce
  - Per-chunk authenticated encryption (XOR counter nonce)
  - Authenticated final seal with chunk count
  - Metadata included in AEAD AAD
  - Wrong passwords detected via authentication failure
  - Truncation detected via final seal

FILE STRUCTURE (.senc):

  [ MAGIC 8 bytes ]
  [ VERSION u8 ]
  [ SALT 16 bytes ]
  [ BASE_NONCE 12 bytes ]
  [ CHUNK_SIZE u32 ]
  [ METADATA_LEN u32 ]
  [ METADATA JSON ]

  For each chunk:
      [ COUNTER u32 ]
      [ CIPHERTEXT_LEN u32 ]
      [ CIPHERTEXT || TAG ]

  Final:
      [ 0xFFFFFFFF ]
      [ FINAL_NONCE 12 bytes ]
      [ SEAL_LEN u32 ]
      [ SEAL (encrypted chunk count, metadata as AAD) ]

WARNING:
  Using --password on the command line exposes it to other
  users via process listings (e.g. ps). Prefer --password-file
  or --password-env for non-interactive use.
"#)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        input: String,
        output: String,
        #[arg(long, short, help = "Password (WARNING: visible in process listings — prefer --password-file or --password-env)")]
        password: Option<String>,
        #[arg(long, short)]
        password_file: Option<String>,
        #[arg(long)]
        password_env: Option<String>,
        #[arg(long, default_value = "1048576")]
        chunk_size: usize,
        #[arg(long, default_value = "10")]
        compression_level: i32,
    },
    EncryptDir {
        input: String,
        output: String,
        #[arg(long, short, help = "Password (WARNING: visible in process listings — prefer --password-file or --password-env)")]
        password: Option<String>,
        #[arg(long, short)]
        password_file: Option<String>,
        #[arg(long)]
        password_env: Option<String>,
        #[arg(long, default_value = "1048576")]
        chunk_size: usize,
        #[arg(long, default_value = "10")]
        compression_level: i32,
    },
    Decrypt {
        input: String,
        output: String,
        #[arg(long, short, help = "Password (WARNING: visible in process listings — prefer --password-file or --password-env)")]
        password: Option<String>,
        #[arg(long, short)]
        password_file: Option<String>,
        #[arg(long)]
        password_env: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { input, output, password, password_file, password_env, chunk_size, compression_level } => {
            pipeline::encrypt_file(&input, &output, password.as_deref(), password_file.as_deref(), password_env.as_deref(), chunk_size, compression_level).await?;
        }
        Commands::EncryptDir { input, output, password, password_file, password_env, chunk_size, compression_level } => {
            pipeline::encrypt_dir(&input, &output, password.as_deref(), password_file.as_deref(), password_env.as_deref(), chunk_size, compression_level).await?;
        }
        Commands::Decrypt { input, output, password, password_file, password_env } => {
            pipeline::decrypt_file(&input, &output, password.as_deref(), password_file.as_deref(), password_env.as_deref()).await?;
        }
    }

    Ok(())
}
