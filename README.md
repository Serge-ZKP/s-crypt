<div align="center">

# S-Crypt

**Authenticated archival encryption for files and directories**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-7%20passing-green.svg)](src/pipeline.rs)

A command-line tool that encrypts files and directories into a custom `.senc` format using AES-256-GCM authenticated encryption, Argon2id key derivation, and Zstandard compression — with full integrity verification against truncation, tampering, and wrong passwords.

</div>

---

## Features

- **Authenticated encryption** — AES-256-GCM with per-chunk authentication tags
- **Hardened key derivation** — Argon2id (64 MiB, 3 passes, 4 threads)
- **Compression** — Zstandard reduces output size before encryption
- **Truncation detection** — Authenticated final seal verifies the exact chunk count
- **Metadata binding** — JSON metadata included in AAD prevents undetected tampering
- **Unique nonces** — 12-byte random base nonce XOR'd with per-chunk counter
- **Pure Rust** — No external binaries required (no system `tar` dependency)
- **Multiple password sources** — Interactive prompt, file, or environment variable

## Quick Start

```bash
# Build
cargo build --release

# Encrypt a file
./target/release/s-crypt encrypt secret.txt secret.senc

# Encrypt a directory
./target/release/s-crypt encrypt-dir ./project project-backup.senc

# Decrypt
./target/release/s-crypt decrypt project-backup.senc ./restored-project
```

Password will be prompted interactively. For scripting, use `--password-file` or `--password-env`.

## Example

```
$ s-crypt encrypt-dir ./my-data backup.senc
Password:
⠋ Encrypting... 12.4MiB

$ ls -lh backup.senc
-rw-r--r-- 1 user user 8.7M backup.senc

$ s-crypt decrypt backup.senc ./restored
Password:
⠋ Decrypting... 8.7MiB

$ diff -r ./my-data ./restored/my-data
# no differences
```

```bash
# Wrong password is detected immediately
$ s-crypt decrypt backup.senc ./output --password wrong
Error: Decryption error: encryption error

# Truncated files are rejected
$ truncate -s 1000 backup.senc
$ s-crypt decrypt backup.senc ./output
Error: File integrity error: expected 5 chunks but found 0 — file may be truncated or corrupted
```

## Usage

```
$ s-crypt --help
S-CRYPT (.senc) FORMAT SPECIFICATION

Commands:
  encrypt       Encrypt a single file
  encrypt-dir   Encrypt a directory (creates tar archive)
  decrypt       Decrypt a .senc archive

Password options:
  -p, --password       Password (WARNING: visible in process listings)
  -f, --password-file  Read password from file
  -e, --password-env   Read password from environment variable

Encryption options:
  --chunk-size          Chunk size in bytes (default: 1048576 = 1 MiB)
  --compression-level   Zstd compression level 1–22 (default: 10)
```

## Security Model

| Property | Mechanism |
|----------|-----------|
| Confidentiality | AES-256-GCM with 256-bit key |
| Key derivation | Argon2id (m=65536 KiB, t=3, p=4) |
| Nonce uniqueness | 12-byte random base nonce ⊕ per-chunk counter |
| Integrity | AES-GCM authentication tag per chunk |
| Metadata binding | Metadata JSON as AAD on every chunk and final seal |
| Truncation detection | Authenticated final seal containing encrypted chunk count |
| Wrong password | Detected via authentication failure on first chunk |
| Key zeroing | `Zeroizing<[u8; 32]>` for derived key material |

## File Format (.senc) v7

```
Header:
  [SCRYPT07]          8 bytes    Magic bytes
  [VERSION]           1 byte     Format version (7)
  [SALT]             16 bytes   Argon2id salt
  [BASE_NONCE]       12 bytes   Random, XOR'd with counter per chunk
  [CHUNK_SIZE]        4 bytes   u32 BE
  [METADATA_LEN]      4 bytes   u32 BE
  [METADATA]          N bytes   JSON (path, compression, is_directory, ...)

Chunks (repeated):
  [COUNTER]           4 bytes   u32 BE chunk sequence number
  [CIPHERTEXT_LEN]    4 bytes   u32 BE
  [CIPHERTEXT+TAG]    N bytes   AES-256-GCM ciphertext + 16-byte auth tag

Final:
  [0xFFFFFFFF]        4 bytes   End marker
  [FINAL_NONCE]      12 bytes   Random nonce for seal
  [SEAL_LEN]          4 bytes   u32 BE
  [SEAL]              N bytes   Encrypted(chunk_count), metadata as AAD
```

### Metadata

```json
{
  "original_path": "/path/to/input",
  "created_at": 1743960000,
  "tool_version": "0.7.0",
  "os": "linux",
  "compression": { "algorithm": "zstd", "level": 10 },
  "is_directory": true
}
```

## Architecture

```
src/
├── main.rs        CLI argument parsing (clap)
├── crypto.rs      Argon2id key derivation, AES-256-GCM encrypt/decrypt
├── format.rs      File format constants (magic, version, nonce size)
├── metadata.rs     JSON metadata structure
└── pipeline.rs     Encrypt/decrypt pipelines + 7 integration tests
```

Encryption pipeline:

```
Input ──► zstd compress ──► chunk ──► AES-256-GCM encrypt ──► .senc file
                                      │
                                      ├─ Key: Argon2id(64 MiB, 3 iters, 4 threads)
                                      ├─ Salt: 16 random bytes per file
                                      ├─ Nonce: base_nonce ⊕ counter
                                      ├─ AAD: metadata JSON
                                      └─ Final seal: encrypted chunk count
```

## Testing

```bash
cargo test
```

7 integration tests covering:

| Test | Validates |
|------|-----------|
| `test_encrypt_decrypt_file_roundtrip` | File encrypt→decrypt produces original content |
| `test_encrypt_decrypt_file_small_chunk` | Multi-chunk path with 16-byte chunks |
| `test_encrypt_decrypt_dir_roundtrip` | Directory with files and subdirs |
| `test_wrong_password_fails` | Wrong password → authentication error |
| `test_truncated_file_detected` | Truncated file → seal verification error |
| `test_corrupted_magic_rejected` | Invalid magic bytes → rejected |
| `test_password_file` | `--password-file` round-trip |

## Limitations

- **No resumable encryption** — if encryption is interrupted, the partial `.senc` file will be detected as invalid (missing final seal) and must be re-encrypted from scratch
- **No streaming decryption** — the full `.senc` file must be read before decompression begins
- **Argon2id memory usage** — 64 MiB per derivation; may be slow on resource-constrained devices

## Dependencies

| Crate | Purpose |
|-------|---------|
| `aes-gcm` | AES-256-GCM encryption |
| `argon2` | Argon2id key derivation |
| `rand` | Cryptographic randomness |
| `zeroize` | Secure memory zeroing |
| `tokio` | Async runtime |
| `async-compression` | Zstd streaming compression |
| `zstd` | Zstd decompression |
| `tar` | Tar archive creation/extraction |
| `serde` + `serde_json` | Metadata serialization |
| `clap` | CLI argument parsing |
| `indicatif` | Progress bars |
| `rpassword` | Interactive password input |
| `chrono` | Timestamps |
| `anyhow` | Error handling |

## License

[MIT](LICENSE)