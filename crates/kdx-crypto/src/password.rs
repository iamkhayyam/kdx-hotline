//! Argon2id password hashing for credentials at rest. Never used for
//! transport keys — TLS owns the channel.

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, SaltString};
use argon2::{Argon2, PasswordVerifier};

use crate::CryptoError;

/// Hash a password to a PHC string (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`)
/// with the argon2 crate's current recommended defaults (19 MiB, t=2, p=1).
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(CryptoError::Hash)?;
    Ok(hash.to_string())
}

/// Verify a password against a stored PHC string. Used for direct
/// verification paths (account management); the wire protocol uses
/// challenge-response instead (see [`crate::challenge`]).
pub fn verify_password(password: &str, stored_phc: &str) -> Result<bool, CryptoError> {
    let parsed = PasswordHash::new(stored_phc).map_err(CryptoError::Hash)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_round_trip() {
        let phc = hash_password("hunter2").unwrap();
        assert!(phc.starts_with("$argon2id$"));
        assert!(verify_password("hunter2", &phc).unwrap());
    }

    #[test]
    fn wrong_password_rejected() {
        let phc = hash_password("hunter2").unwrap();
        assert!(!verify_password("hunter3", &phc).unwrap());
    }

    #[test]
    fn salts_differ_between_hashes() {
        let a = hash_password("same").unwrap();
        let b = hash_password("same").unwrap();
        assert_ne!(a, b);
    }
}
