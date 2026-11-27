use thiserror::Error;

/// Errors returned by Zyoza core, profile, settlement, and proof operations.
#[derive(Debug, Error)]
pub enum ZyozaError {
    /// Invalid binary encoding or length mismatch.
    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),

    /// Invalid magic bytes or unsupported protocol version.
    #[error("invalid seal header: {0}")]
    InvalidSealHeader(String),

    /// Out-of-band URI exceeds the 372-byte Orchard memo budget.
    #[error("oob uri too long: {len} bytes (max {max})")]
    OobUriTooLong { len: usize, max: usize },

    /// State transition rejected by the active `AssetProfile`.
    #[error("invalid state transition: {0}")]
    InvalidTransition(String),

    /// Settlement anchor or single-use seal verification failed.
    #[error("settlement error: {0}")]
    Settlement(String),

    /// Zero-knowledge proof generation or verification failed.
    #[error("proof error: {0}")]
    Proof(String),

    /// Selective disclosure or viewing-key error.
    #[error("disclosure error: {0}")]
    Disclosure(String),
}
