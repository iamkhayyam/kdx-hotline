//! Challenge-response authentication.
//!
//! The server stores only an Argon2id PHC string. To log in, the client
//! receives a random 32-byte challenge plus the account's Argon2 salt and
//! parameters, recomputes the Argon2 output (the "verifier") from the
//! password locally, and answers with `SHA-256(challenge || verifier)`.
//! The server compares that against the same digest computed from its stored
//! verifier, in constant time. The password itself never crosses the wire —
//! not even inside TLS — and a transcript replay is useless because each
//! login gets a fresh challenge.

use argon2::password_hash::PasswordHash;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::CryptoError;

/// Argon2id cost parameters shipped to the client so it can recompute the
/// verifier. Mirrors what's encoded in the stored PHC string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

/// A fresh random 32-byte login challenge.
pub fn generate_challenge() -> [u8; 32] {
    let mut challenge = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut challenge);
    challenge
}

/// Extract the salt and cost parameters from a stored PHC string, for
/// inclusion in the `AuthChallenge` sent to the client.
pub fn extract_kdf(stored_phc: &str) -> Result<(Vec<u8>, KdfParams), CryptoError> {
    let parsed = PasswordHash::new(stored_phc).map_err(CryptoError::Hash)?;
    let salt = parsed.salt.ok_or(CryptoError::MissingSalt)?;
    let mut salt_buf = [0u8; 64];
    let salt_bytes = salt.decode_b64(&mut salt_buf).map_err(CryptoError::Hash)?;
    let params = Params::try_from(&parsed).map_err(CryptoError::Hash)?;
    Ok((
        salt_bytes.to_vec(),
        KdfParams {
            m_cost: params.m_cost(),
            t_cost: params.t_cost(),
            p_cost: params.p_cost(),
        },
    ))
}

/// Client side: derive the verifier from the password and answer the
/// challenge. `salt` and `params` come from the server's `AuthChallenge`.
pub fn client_response(
    password: &str,
    salt: &[u8],
    params: &KdfParams,
    challenge: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(CryptoError::Params)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut verifier = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, verifier.as_mut())
        .map_err(CryptoError::Params)?;
    Ok(digest(challenge, verifier.as_ref()))
}

/// Server side: the response a correct client would produce, computed from
/// the stored PHC string's embedded verifier.
pub fn expected_response(stored_phc: &str, challenge: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let parsed = PasswordHash::new(stored_phc).map_err(CryptoError::Hash)?;
    let verifier = parsed.hash.ok_or(CryptoError::MissingSalt)?;
    Ok(digest(challenge, verifier.as_bytes()))
}

/// Constant-time comparison of the client's response with the expected one.
pub fn verify_response(expected: &[u8; 32], got: &[u8; 32]) -> bool {
    expected.ct_eq(got).into()
}

fn digest(challenge: &[u8; 32], verifier: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    hasher.update(verifier);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::password::hash_password;

    #[test]
    fn correct_password_authenticates() {
        let phc = hash_password("open sesame").unwrap();
        let (salt, params) = extract_kdf(&phc).unwrap();
        let challenge = generate_challenge();

        let response = client_response("open sesame", &salt, &params, &challenge).unwrap();
        let expected = expected_response(&phc, &challenge).unwrap();
        assert!(verify_response(&expected, &response));
    }

    #[test]
    fn wrong_password_fails() {
        let phc = hash_password("open sesame").unwrap();
        let (salt, params) = extract_kdf(&phc).unwrap();
        let challenge = generate_challenge();

        let response = client_response("open salami", &salt, &params, &challenge).unwrap();
        let expected = expected_response(&phc, &challenge).unwrap();
        assert!(!verify_response(&expected, &response));
    }

    #[test]
    fn replayed_response_fails_on_new_challenge() {
        let phc = hash_password("open sesame").unwrap();
        let (salt, params) = extract_kdf(&phc).unwrap();

        let first = generate_challenge();
        let replay = client_response("open sesame", &salt, &params, &first).unwrap();

        let second = generate_challenge();
        let expected = expected_response(&phc, &second).unwrap();
        assert!(!verify_response(&expected, &replay));
    }

    #[test]
    fn challenges_are_unique() {
        assert_ne!(generate_challenge(), generate_challenge());
    }
}
