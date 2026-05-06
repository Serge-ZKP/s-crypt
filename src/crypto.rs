use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

pub fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| anyhow!("Argon2 params error: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| anyhow!("Argon2 error: {}", e))?;
    Ok(key)
}

pub fn encrypt_chunk(
    cipher: &Aes256Gcm,
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| anyhow!("Encryption error: {}", e))
}

pub fn decrypt_chunk(
    cipher: &Aes256Gcm,
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| anyhow!("Decryption error: {}", e))
}
