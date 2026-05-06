use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CompressionInfo {
    pub algorithm: String,
    pub level: i32,
}

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    pub original_path: String,
    pub created_at: u64,
    pub tool_version: String,
    pub os: String,
    pub compression: CompressionInfo,
    pub is_directory: bool,
}
