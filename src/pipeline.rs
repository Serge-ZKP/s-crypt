use anyhow::Result;
use tokio::{fs::File, io::{AsyncReadExt, AsyncWriteExt, BufReader}};
use rand::RngCore;
use aes_gcm::{Aes256Gcm, KeyInit};
use zeroize::Zeroizing;
use indicatif::{ProgressBar, ProgressStyle};
use async_compression::tokio::bufread::ZstdEncoder;
use std::io::Cursor;
use crate::{crypto, format, metadata::{Metadata, CompressionInfo}};

fn get_password(
    password: Option<&str>,
    password_file: Option<&str>,
    password_env: Option<&str>,
) -> Result<Zeroizing<String>> {
    if let Some(p) = password {
        return Ok(Zeroizing::new(p.to_string()));
    }
    
    if let Some(pf) = password_file {
        let content = std::fs::read_to_string(pf)?;
        let pwd = content.trim_end().to_string();
        return Ok(Zeroizing::new(pwd));
    }
    
    if let Some(env_var) = password_env
        && let Ok(pwd) = std::env::var(env_var) 
    {
        return Ok(Zeroizing::new(pwd));
    }
    
    Ok(Zeroizing::new(rpassword::prompt_password("Password: ")?))
}

pub async fn encrypt_dir(
    input: &str,
    output: &str,
    password: Option<&str>,
    password_file: Option<&str>,
    password_env: Option<&str>,
    chunk_size: usize,
    compression_level: i32,
) -> Result<()> {

    let password = get_password(password, password_file, password_env)?;

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = crypto::derive_key(&password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| anyhow::anyhow!("Invalid key length: {}", e))?;

    let metadata = Metadata {
        original_path: input.to_string(),
        created_at: chrono::Utc::now().timestamp() as u64,
        tool_version: env!("CARGO_PKG_VERSION").into(),
        os: std::env::consts::OS.into(),
        compression: CompressionInfo {
            algorithm: "zstd".into(),
            level: compression_level,
        },
        is_directory: true,
    };

    let metadata_bytes = serde_json::to_vec(&metadata)?;

    let mut file = File::create(output).await?;
    file.write_all(format::MAGIC).await?;
    file.write_u8(format::VERSION).await?;
    file.write_all(&salt).await?;

    let mut base_nonce = [0u8; format::NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut base_nonce);
    file.write_all(&base_nonce).await?;

    file.write_all(&(chunk_size as u32).to_be_bytes()).await?;
    file.write_all(&(metadata_bytes.len() as u32).to_be_bytes()).await?;
    file.write_all(&metadata_bytes).await?;

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::with_template("{spinner:.green} {msg} {bytes}").unwrap());
    pb.set_message("Encrypting...");

    let input_owned = input.to_string();
    let input_path = std::path::Path::new(&input_owned);
    let dir_name = input_path
        .file_name()
        .unwrap_or(std::ffi::OsStr::new("data"))
        .to_string_lossy()
        .to_string();
    let tar_data = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            builder.append_dir_all(&dir_name, &input_owned)?;
            builder.finish()?;
        }
        Ok(tar_buf)
    }).await??;

    let reader = BufReader::new(Cursor::new(tar_data));
    let mut compressor = ZstdEncoder::with_quality(
        reader,
        async_compression::Level::Precise(compression_level),
    );

    let mut buffer = vec![0u8; chunk_size];
    let mut counter = 0u32;

    loop {
        let n = compressor.read(&mut buffer).await?;
        if n == 0 { break; }

        pb.inc(n as u64);

        let mut nonce = base_nonce;
        let ctr = counter.to_be_bytes();
        nonce[8] ^= ctr[0];
        nonce[9] ^= ctr[1];
        nonce[10] ^= ctr[2];
        nonce[11] ^= ctr[3];

        let ciphertext = crypto::encrypt_chunk(
            &cipher,
            &nonce,
            &metadata_bytes,
            &buffer[..n],
        )?;

        let mut counter_bytes = [0u8; 4];
        counter_bytes.copy_from_slice(&counter.to_be_bytes());
        file.write_all(&counter_bytes).await?;
        file.write_all(&(ciphertext.len() as u32).to_be_bytes()).await?;
        file.write_all(&ciphertext).await?;

        counter += 1;
    }

    let mut final_marker = [0u8; 4];
    final_marker.copy_from_slice(&format::FINAL_MARKER.to_be_bytes());
    file.write_all(&final_marker).await?;

    let mut final_nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut final_nonce);
    let total_chunks = counter.to_be_bytes();
    let final_seal = crypto::encrypt_chunk(
        &cipher,
        &final_nonce,
        &metadata_bytes,
        &total_chunks,
    )?;
    file.write_all(&final_nonce).await?;
    file.write_all(&(final_seal.len() as u32).to_be_bytes()).await?;
    file.write_all(&final_seal).await?;
    file.flush().await?;
    pb.finish();

    Ok(())
}

pub async fn decrypt_file(input: &str, output: &str, password: Option<&str>, password_file: Option<&str>, password_env: Option<&str>) -> Result<()> {
    let password = get_password(password, password_file, password_env)?;

    let mut file = BufReader::new(File::open(input).await?);

    let mut magic = [0u8; 8];
    file.read_exact(&mut magic).await?;
    if &magic != format::MAGIC {
        anyhow::bail!("Invalid .senc file: bad magic bytes");
    }

    let version = file.read_u8().await?;
    if version != format::VERSION {
        anyhow::bail!("Unsupported .senc version: expected {}, got {}", format::VERSION, version);
    }

    let mut salt = [0u8; 16];
    file.read_exact(&mut salt).await?;

    let key = crypto::derive_key(&password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| anyhow::anyhow!("Invalid key length: {}", e))?;

    let mut base_nonce = [0u8; format::NONCE_SIZE];
    file.read_exact(&mut base_nonce).await?;

    let _chunk_size = file.read_u32().await? as usize;
    let metadata_len = file.read_u32().await? as usize;

    let mut metadata_bytes = vec![0u8; metadata_len];
    file.read_exact(&mut metadata_bytes).await?;

    let mut decrypted_data = Vec::new();
    let mut chunks_decrypted: u32 = 0;
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::with_template("{spinner:.green} {msg} {bytes}").unwrap());
    pb.set_message("Decrypting...");

    loop {
        let counter_or_marker = file.read_u32().await?;
        if counter_or_marker == format::FINAL_MARKER {
            break;
        }

        let chunk_counter = counter_or_marker;

        let ciphertext_len = file.read_u32().await? as usize;
        let mut ciphertext = vec![0u8; ciphertext_len];
        file.read_exact(&mut ciphertext).await?;

        let mut nonce = base_nonce;
        let ctr = chunk_counter.to_be_bytes();
        nonce[8] ^= ctr[0];
        nonce[9] ^= ctr[1];
        nonce[10] ^= ctr[2];
        nonce[11] ^= ctr[3];

        let plaintext = crypto::decrypt_chunk(&cipher, &nonce, &metadata_bytes, &ciphertext)?;
        decrypted_data.extend_from_slice(&plaintext);

        chunks_decrypted += 1;
        pb.inc(ciphertext_len as u64);
    }

    let mut final_nonce = [0u8; 12];
    file.read_exact(&mut final_nonce).await?;
    let final_seal_len = file.read_u32().await? as usize;
    let mut final_seal = vec![0u8; final_seal_len];
    file.read_exact(&mut final_seal).await?;

    let seal_plaintext = crypto::decrypt_chunk(&cipher, &final_nonce, &metadata_bytes, &final_seal)?;
    let expected_chunks = u32::from_be_bytes(
        seal_plaintext[..format::FINAL_SEAL_PLAINTEXT_LEN].try_into()?,
    );
    if chunks_decrypted != expected_chunks {
        anyhow::bail!(
            "File integrity error: expected {} chunks but found {} — file may be truncated or corrupted",
            expected_chunks,
            chunks_decrypted,
        );
    }

    pb.finish_with_message("Decryption complete");

    let metadata_obj: Metadata = serde_json::from_slice(&metadata_bytes)?;

    let compressed_data = decrypted_data;
    let decompressed = tokio::task::spawn_blocking(move || {
        zstd::decode_all(std::io::Cursor::new(compressed_data))
    }).await??;

    if metadata_obj.is_directory {
        std::fs::create_dir_all(output)?;
        let output_owned = output.to_string();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut archive = tar::Archive::new(Cursor::new(decompressed));
            archive.unpack(&output_owned)?;
            Ok(())
        }).await??;
    } else {
        if let Some(parent) = std::path::Path::new(output).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out_file = File::create(output).await?;
        out_file.write_all(&decompressed).await?;
        out_file.flush().await?;
    }

    Ok(())
}

pub async fn encrypt_file(
    input: &str,
    output: &str,
    password: Option<&str>,
    password_file: Option<&str>,
    password_env: Option<&str>,
    chunk_size: usize,
    compression_level: i32,
) -> Result<()> {

    let password = get_password(password, password_file, password_env)?;

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = crypto::derive_key(&password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|e| anyhow::anyhow!("Invalid key length: {}", e))?;

    let file_meta = std::fs::metadata(input)?;
    let metadata = Metadata {
        original_path: input.to_string(),
        created_at: chrono::Utc::now().timestamp() as u64,
        tool_version: env!("CARGO_PKG_VERSION").into(),
        os: std::env::consts::OS.into(),
        compression: CompressionInfo {
            algorithm: "zstd".into(),
            level: compression_level,
        },
        is_directory: false,
    };

    let metadata_bytes = serde_json::to_vec(&metadata)?;

    let mut out_file = File::create(output).await?;
    out_file.write_all(format::MAGIC).await?;
    out_file.write_u8(format::VERSION).await?;
    out_file.write_all(&salt).await?;

    let mut base_nonce = [0u8; format::NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut base_nonce);
    out_file.write_all(&base_nonce).await?;

    out_file.write_all(&(chunk_size as u32).to_be_bytes()).await?;
    out_file.write_all(&(metadata_bytes.len() as u32).to_be_bytes()).await?;
    out_file.write_all(&metadata_bytes).await?;

    let file_size = file_meta.len();
    let pb = ProgressBar::new(file_size);
    pb.set_style(ProgressStyle::with_template("{spinner:.green} {msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})").unwrap());

    let input_file = File::open(input).await?;
    let reader = BufReader::new(input_file);
    let mut compressor = ZstdEncoder::with_quality(
        reader,
        async_compression::Level::Precise(compression_level),
    );

    let mut buffer = vec![0u8; chunk_size];
    let mut counter = 0u32;

    loop {
        let n = compressor.read(&mut buffer).await?;
        if n == 0 { break; }

        pb.inc(n as u64);

        let mut nonce = base_nonce;
        let ctr = counter.to_be_bytes();
        nonce[8] ^= ctr[0];
        nonce[9] ^= ctr[1];
        nonce[10] ^= ctr[2];
        nonce[11] ^= ctr[3];

        let ciphertext = crypto::encrypt_chunk(
            &cipher,
            &nonce,
            &metadata_bytes,
            &buffer[..n],
        )?;

        let mut counter_bytes = [0u8; 4];
        counter_bytes.copy_from_slice(&counter.to_be_bytes());
        out_file.write_all(&counter_bytes).await?;
        out_file.write_all(&(ciphertext.len() as u32).to_be_bytes()).await?;
        out_file.write_all(&ciphertext).await?;

        counter += 1;
    }

    let mut final_marker = [0u8; 4];
    final_marker.copy_from_slice(&format::FINAL_MARKER.to_be_bytes());
    out_file.write_all(&final_marker).await?;

    let mut final_nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut final_nonce);
    let total_chunks = counter.to_be_bytes();
    let final_seal = crypto::encrypt_chunk(
        &cipher,
        &final_nonce,
        &metadata_bytes,
        &total_chunks,
    )?;
    out_file.write_all(&final_nonce).await?;
    out_file.write_all(&(final_seal.len() as u32).to_be_bytes()).await?;
    out_file.write_all(&final_seal).await?;
    out_file.flush().await?;
    pb.finish();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_test_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("s-crypt-test").join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn teardown_test_dir(dir: &std::path::Path) {
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_file_roundtrip() {
        let dir = setup_test_dir("file_roundtrip");
        let input = dir.join("input.txt");
        let encrypted = dir.join("output.senc");
        let decrypted = dir.join("output.txt");

        let original_data = b"Hello, World! This is a test file for s-crypt encryption and decryption.";
        fs::write(&input, original_data).unwrap();

        encrypt_file(
            input.to_str().unwrap(),
            encrypted.to_str().unwrap(),
            Some("testpassword123"),
            None,
            None,
            1048576,
            3,
        ).await.unwrap();

        assert!(encrypted.exists(), "Encrypted file should exist");

        let result = decrypt_file(
            encrypted.to_str().unwrap(),
            decrypted.to_str().unwrap(),
            Some("testpassword123"),
            None,
            None,
        ).await;

        if let Err(e) = &result {
            eprintln!("Decryption error: {:?}", e);
        }

        let result_data = fs::read(&decrypted).unwrap_or_default();
        if original_data.to_vec() != result_data {
            eprintln!("Expected {} bytes, got {} bytes", original_data.len(), result_data.len());
            if !result_data.is_empty() {
                eprintln!("First 20 decrypted bytes: {:02x?}", &result_data[..20.min(result_data.len())]);
            }
        }
        assert_eq!(original_data.to_vec(), result_data, "Decrypted content should match original");

        teardown_test_dir(&dir);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_file_small_chunk() {
        let dir = setup_test_dir("small_chunk");
        let input = dir.join("input.txt");
        let encrypted = dir.join("output.senc");
        let decrypted = dir.join("output.txt");

        let original_data = b"Testing with small chunks to verify multi-chunk encryption.";
        fs::write(&input, original_data).unwrap();

        encrypt_file(
            input.to_str().unwrap(),
            encrypted.to_str().unwrap(),
            Some("pass"),
            None,
            None,
            16,
            3,
        ).await.unwrap();

        decrypt_file(
            encrypted.to_str().unwrap(),
            decrypted.to_str().unwrap(),
            Some("pass"),
            None,
            None,
        ).await.unwrap();

        let result_data = fs::read(&decrypted).unwrap();
        assert_eq!(original_data.to_vec(), result_data, "Decrypted content should match original with small chunks");

        teardown_test_dir(&dir);
    }

    #[tokio::test]
    async fn test_wrong_password_fails() {
        let dir = setup_test_dir("wrong_pass");
        let input = dir.join("input.txt");
        let encrypted = dir.join("output.senc");
        let decrypted = dir.join("output.txt");

        fs::write(&input, b"secret data").unwrap();

        encrypt_file(
            input.to_str().unwrap(),
            encrypted.to_str().unwrap(),
            Some("correct_password"),
            None,
            None,
            1048576,
            3,
        ).await.unwrap();

        let result = decrypt_file(
            encrypted.to_str().unwrap(),
            decrypted.to_str().unwrap(),
            Some("wrong_password"),
            None,
            None,
        ).await;

        assert!(result.is_err(), "Decryption with wrong password should fail");

        teardown_test_dir(&dir);
    }

    #[tokio::test]
    async fn test_truncated_file_detected() {
        let dir = setup_test_dir("truncated");
        let input = dir.join("input.txt");
        let encrypted = dir.join("output.senc");
        let decrypted = dir.join("output.txt");

        fs::write(&input, b"This file will be truncated after encryption").unwrap();

        encrypt_file(
            input.to_str().unwrap(),
            encrypted.to_str().unwrap(),
            Some("password"),
            None,
            None,
            16,
            3,
        ).await.unwrap();

        let original_size = fs::metadata(&encrypted).unwrap().len();
        let truncated_size = original_size / 2;
        let data = fs::read(&encrypted).unwrap();
        fs::write(&encrypted, &data[..truncated_size as usize]).unwrap();

        let result = decrypt_file(
            encrypted.to_str().unwrap(),
            decrypted.to_str().unwrap(),
            Some("password"),
            None,
            None,
        ).await;

        assert!(result.is_err(), "Decryption of truncated file should fail");

        teardown_test_dir(&dir);
    }

    #[tokio::test]
    async fn test_corrupted_magic_rejected() {
        let dir = setup_test_dir("bad_magic");
        let encrypted = dir.join("output.senc");
        let decrypted = dir.join("output.txt");

        let mut data = b"BADMAGIC".to_vec();
        data.extend_from_slice(&[0u8; 100]);
        fs::write(&encrypted, &data).unwrap();

        let result = decrypt_file(
            encrypted.to_str().unwrap(),
            decrypted.to_str().unwrap(),
            Some("password"),
            None,
            None,
        ).await;

        assert!(result.is_err(), "Decryption with invalid magic bytes should fail");

        teardown_test_dir(&dir);
    }

    #[tokio::test]
    async fn test_password_file() {
        let dir = setup_test_dir("pass_file");
        let input = dir.join("input.txt");
        let encrypted = dir.join("output.senc");
        let decrypted = dir.join("output.txt");
        let pass_file = dir.join("password.txt");

        let original_data = b"Testing password file authentication";
        fs::write(&input, original_data).unwrap();
        fs::write(&pass_file, "file_password\n").unwrap();

        encrypt_file(
            input.to_str().unwrap(),
            encrypted.to_str().unwrap(),
            None,
            Some(pass_file.to_str().unwrap()),
            None,
            1048576,
            3,
        ).await.unwrap();

        decrypt_file(
            encrypted.to_str().unwrap(),
            decrypted.to_str().unwrap(),
            None,
            Some(pass_file.to_str().unwrap()),
            None,
        ).await.unwrap();

        let result_data = fs::read(&decrypted).unwrap();
        assert_eq!(original_data.to_vec(), result_data, "Decrypted content should match original with password file");

        teardown_test_dir(&dir);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_dir_roundtrip() {
        let dir = setup_test_dir("dir_roundtrip");
        let input_dir = dir.join("input_dir");
        let encrypted = dir.join("output.senc");
        let output_dir = dir.join("output_dir");

        fs::create_dir_all(&input_dir).unwrap();
        fs::write(input_dir.join("file1.txt"), b"File 1 content").unwrap();
        fs::write(input_dir.join("file2.txt"), b"File 2 content").unwrap();
        fs::create_dir_all(input_dir.join("subdir")).unwrap();
        fs::write(input_dir.join("subdir").join("file3.txt"), b"File 3 content").unwrap();

        encrypt_dir(
            input_dir.to_str().unwrap(),
            encrypted.to_str().unwrap(),
            Some("dirpassword"),
            None,
            None,
            1048576,
            3,
        ).await.unwrap();

        assert!(encrypted.exists(), "Encrypted file should exist");

        decrypt_file(
            encrypted.to_str().unwrap(),
            output_dir.to_str().unwrap(),
            Some("dirpassword"),
            None,
            None,
        ).await.unwrap();

        let f1 = fs::read(input_dir.join("file1.txt")).unwrap();
        let f2 = fs::read(input_dir.join("file2.txt")).unwrap();
        let f3 = fs::read(input_dir.join("subdir").join("file3.txt")).unwrap();

        assert!(!f1.is_empty(), "file1.txt should exist in decrypted output");
        assert!(!f2.is_empty(), "file2.txt should exist in decrypted output");
        assert!(!f3.is_empty(), "file3.txt should exist in decrypted output");

        teardown_test_dir(&dir);
    }
}
