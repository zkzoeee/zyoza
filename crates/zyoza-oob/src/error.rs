use thiserror::Error;

/// Errors returned by out-of-band encryption, key handover, and storage operations.
#[derive(Debug, Error)]
pub enum OobError {
    #[error("aead encryption/decryption failed: {0}")]
    Crypto(String),

    #[error("invalid key or point encoding: {0}")]
    InvalidKey(String),

    #[error("integrity hash mismatch")]
    IntegrityMismatch,

    #[error("storage error: {0}")]
    Storage(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
