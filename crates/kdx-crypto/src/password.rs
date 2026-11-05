//! At-rest credentials for new accounts. Never used for transport keys —
//! TLS owns the channel.

use crate::scram::StoredCredential;
use crate::CryptoError;

/// Derive the at-rest credential string for a new password: a fresh random
/// salt, Argon2id with [`crate::KdfParams::DEFAULT`], and the SCRAM
/// StoredKey/ServerKey derived from it, encoded with
/// [`StoredCredential::encode`]. The Argon2 output itself (the salted
/// password, which would be password-equivalent) is not stored.
///
/// Runs Argon2 (blocking, ~19 MiB) — async callers should use
/// `spawn_blocking`.
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    Ok(StoredCredential::derive(password)?.encode())
}

/// Verify a password directly against a stored credential string. Used for
/// direct verification paths (account management); the wire protocol uses
/// the challenge-response proof instead (see [`crate::scram`]).
pub fn verify_password(password: &str, stored: &str) -> Result<bool, CryptoError> {
    StoredCredential::decode(stored)?.matches_password(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_round_trip() {
        let stored = hash_password("hunter2").unwrap();
        assert!(stored.starts_with("$kdx-scram-sha256$"));
        assert!(verify_password("hunter2", &stored).unwrap());
    }

    #[test]
    fn wrong_password_rejected() {
        let stored = hash_password("hunter2").unwrap();
        assert!(!verify_password("hunter3", &stored).unwrap());
    }

    #[test]
    fn salts_differ_between_hashes() {
        let a = hash_password("same").unwrap();
        let b = hash_password("same").unwrap();
        assert_ne!(a, b);
    }
}
