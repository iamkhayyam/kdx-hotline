//! Credential-related crypto for KDX: Argon2id password hashing and
//! challenge-response auth helpers. Transport security is TLS 1.3 (rustls),
//! handled at the connection layer — nothing here touches transport keys.

pub mod challenge;
pub mod password;

pub use challenge::{
    client_response, expected_response, extract_kdf, generate_challenge, verify_response,
    KdfParams,
};
pub use password::{hash_password, verify_password};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("password hash error: {0}")]
    Hash(argon2::password_hash::Error),
    #[error("argon2 parameter error: {0}")]
    Params(argon2::Error),
    #[error("stored hash is missing salt or digest")]
    MissingSalt,
}
