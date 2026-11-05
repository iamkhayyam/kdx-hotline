//! Credential-related crypto for KDX: Argon2id-salted SCRAM-style
//! credentials and the TLS-channel-bound challenge-response proof.
//! Transport security is TLS 1.3 (rustls), handled at the connection layer —
//! nothing here touches transport keys (the channel binding is an exporter
//! value the caller reads from its TLS session).

pub mod challenge;
pub mod password;
pub mod scram;
pub mod shamir;

pub use challenge::{
    generate_challenge, KdfParams, MAX_M_COST, MAX_P_COST, MAX_SALT_LEN, MAX_T_COST, MIN_M_COST,
    MIN_P_COST, MIN_SALT_LEN, MIN_T_COST, SALT_LEN,
};
pub use password::{hash_password, verify_password};
pub use scram::{
    client_proof, decoy_salt, AuthContext, ClientProof, StoredCredential, CHANNEL_BINDING_LEN,
    TLS_EXPORTER_LABEL,
};
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
    /// The server asked for KDF parameters outside the client's bounds.
    #[error("unacceptable KDF parameters: {0}")]
    UnacceptableKdf(&'static str),
    #[error("malformed stored credential")]
    MalformedCredential,
    #[error("cannot convert legacy password hash: {0}")]
    LegacyHash(&'static str),
    #[error("shamir: invalid parameters: {0}")]
    ShamirParams(String),
    #[error("shamir: need at least {required} shares to reconstruct, got {got}")]
    ShamirThreshold { required: u8, got: usize },
    #[error("shamir: share payload lengths differ")]
    ShamirLengthMismatch,
}
