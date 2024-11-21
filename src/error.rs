// src/error.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MeshError {
    #[error("Packet validation failed: {0}")]
    ValidationError(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Invalid packet format: {0}")]
    PacketError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<ring::error::Unspecified> for MeshError {
    fn from(_: ring::error::Unspecified) -> Self {
        MeshError::CryptoError("Cryptographic operation failed".to_string())
    }
}
