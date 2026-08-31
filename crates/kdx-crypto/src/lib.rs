//! Credential-related crypto for KDX: Argon2id password hashing and
//! challenge-response auth helpers. Transport security is TLS 1.3 (rustls),
//! handled at the connection layer — nothing here touches transport keys.

pub mod challenge;
pub mod password;
pub mod shamir;

pub use challenge::{
    client_response, expected_response, extract_kdf, generate_challenge, verify_response,
    KdfParams,
};
pub use password::{hash_password, verify_password};
pub use shamir::{
    combine, split, verify_share, Commitments, MerkleProof, ProofStep, Share, SplitResult,
    MAX_SHARES,
};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("password hash error: {0}")]
    Hash(argon2::password_hash::Error),
    #[error("argon2 parameter error: {0}")]
    Params(argon2::Error),
    #[error("stored hash is missing salt or digest")]
    MissingSalt,
    #[error("shamir: invalid parameters: {0}")]
    ShamirParams(String),
    #[error("shamir: need at least {required} shares to reconstruct, got {got}")]
    ShamirThreshold { required: u8, got: usize },
    #[error("shamir: share payload lengths differ")]
    ShamirLengthMismatch,
}
