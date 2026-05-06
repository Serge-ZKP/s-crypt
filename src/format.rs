pub const MAGIC: &[u8; 8] = b"SCRYPT07";
pub const VERSION: u8 = 7;
pub const FINAL_MARKER: u32 = 0xFFFFFFFF;
pub const FINAL_SEAL_PLAINTEXT_LEN: usize = 4;
pub const NONCE_SIZE: usize = 12;
