//! SCRAM-SHA-256-style login proof, bound to the TLS channel.
//!
//! Key schedule (RFC 5802 names, Argon2id in place of PBKDF2):
//!
//! ```text
//! SaltedPassword  = Argon2id(password, salt, m, t, p)          32 bytes
//! ClientKey       = HMAC-SHA256(SaltedPassword, "Client Key")
//! StoredKey       = SHA-256(ClientKey)
//! ServerKey       = HMAC-SHA256(SaltedPassword, "Server Key")
//! AuthMessage     = "KDX-AUTH-v2" 0x00
//!                   || u32 len(username) || username
//!                   || challenge (32)
//!                   || u32 len(salt) || salt || m || t || p      (u32 each)
//!                   || channel_binding (32)
//! ClientSignature = HMAC-SHA256(StoredKey, AuthMessage)
//! ClientProof     = ClientKey XOR ClientSignature                (client → server)
//! ServerSignature = HMAC-SHA256(ServerKey, AuthMessage)          (server → client)
//! ```
//!
//! The server stores only salt, params, StoredKey and ServerKey
//! ([`StoredCredential`]). It recovers `ClientKey = ClientProof XOR
//! ClientSignature` and accepts iff `SHA-256(ClientKey) == StoredKey`, so a
//! copy of the database is not enough to log in: StoredKey is a one-way hash
//! of the ClientKey the proof needs.
//!
//! `channel_binding` is a 32-byte TLS exporter value
//! ([`TLS_EXPORTER_LABEL`], no context) that both ends read from their own
//! TLS session. A malicious server relaying a victim's login to another
//! server sits on two different TLS sessions, so the proof it forwards was
//! computed for the wrong exporter value and fails. The client also checks
//! the ServerSignature, which only a holder of the account's ServerKey can
//! produce, before treating the login as successful.

use std::fmt;

use argon2::password_hash::PasswordHash;
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::challenge::{KdfParams, MAX_SALT_LEN, SALT_LEN};
use crate::CryptoError;

/// Length of the TLS channel-binding value mixed into the proof.
pub const CHANNEL_BINDING_LEN: usize = 32;
/// RFC 5705 / RFC 8446 exporter label both sides use to derive the channel
/// binding from their TLS session (`export_keying_material(32, label, None)`).
pub const TLS_EXPORTER_LABEL: &[u8] = b"EXPORTER-KDX-AUTH-v2";

const AUTH_MESSAGE_LABEL: &[u8] = b"KDX-AUTH-v2\0";
const DECOY_SALT_LABEL: &[u8] = b"KDX-decoy-salt-v1\0";
const CREDENTIAL_SCHEME: &str = "kdx-scram-sha256";
const CREDENTIAL_VERSION: &str = "v=1";

type HmacSha256 = Hmac<Sha256>;

/// Everything the proof is bound to, identical on both ends of an honest
/// login.
#[derive(Debug, Clone, Copy)]
pub struct AuthContext<'a> {
    /// The username exactly as sent in `AuthRequest`.
    pub username: &'a str,
    /// The server's fresh challenge from `AuthChallenge`.
    pub challenge: &'a [u8; 32],
    /// Argon2 salt from `AuthChallenge`.
    pub salt: &'a [u8],
    /// Argon2 parameters from `AuthChallenge`.
    pub params: KdfParams,
    /// TLS exporter value for this connection (all zeros only in in-memory
    /// tests that have no TLS session).
    pub channel_binding: &'a [u8; CHANNEL_BINDING_LEN],
}

impl AuthContext<'_> {
    /// The canonical AuthMessage both sides MAC (see the module docs).
    pub fn auth_message(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(
            AUTH_MESSAGE_LABEL.len() + 4 + self.username.len() + 32 + 4 + self.salt.len() + 12 + 32,
        );
        m.extend_from_slice(AUTH_MESSAGE_LABEL);
        put_bytes(&mut m, self.username.as_bytes());
        m.extend_from_slice(self.challenge);
        put_bytes(&mut m, self.salt);
        m.extend_from_slice(&self.params.m_cost.to_be_bytes());
        m.extend_from_slice(&self.params.t_cost.to_be_bytes());
        m.extend_from_slice(&self.params.p_cost.to_be_bytes());
        m.extend_from_slice(self.channel_binding);
        m
    }
}

/// The client's answer to a challenge, plus the server signature an honest
/// server will send back.
#[derive(Debug, Clone)]
pub struct ClientProof {
    /// `ClientKey XOR ClientSignature` — goes on the wire in `AuthResponse`.
    pub proof: [u8; 32],
    server_signature: [u8; 32],
}

impl ClientProof {
    /// Constant-time check of the `ServerSignature` from a successful
    /// `AuthResult`. A server that doesn't hold this account's ServerKey (a
    /// phishing server, or a relay on a different TLS session) can't pass.
    pub fn verify_server_signature(&self, got: &[u8; 32]) -> bool {
        self.server_signature.ct_eq(got).into()
    }
}

/// Client side: derive the salted password from `password` and answer the
/// challenge described by `ctx`.
///
/// Refuses (before running Argon2) any salt or cost parameters outside the
/// client bounds in [`KdfParams::check_bounds`]. Argon2 is CPU- and
/// memory-heavy by design; async callers should run this on a blocking
/// thread (`tokio::task::spawn_blocking`).
pub fn client_proof(password: &str, ctx: &AuthContext<'_>) -> Result<ClientProof, CryptoError> {
    ctx.params.check_bounds(ctx.salt.len())?;
    let salted = salted_password(password.as_bytes(), ctx.salt, &ctx.params)?;
    let keys = Keys::from_salted_password(&salted);
    let auth_message = ctx.auth_message();
    let client_signature = Zeroizing::new(hmac(&keys.stored_key, &auth_message));
    let mut proof = [0u8; 32];
    for (i, byte) in proof.iter_mut().enumerate() {
        *byte = keys.client_key[i] ^ client_signature[i];
    }
    Ok(ClientProof {
        proof,
        server_signature: hmac(&keys.server_key, &auth_message),
    })
}

/// Server side: a deterministic per-username salt for accounts that don't
/// exist, keyed by a per-server random secret so it can't be predicted (and
/// so can't be told apart from a real account's random salt).
pub fn decoy_salt(server_secret: &[u8; 32], username: &str) -> Vec<u8> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(server_secret).expect("HMAC accepts any key length");
    mac.update(DECOY_SALT_LABEL);
    mac.update(username.as_bytes());
    let digest = mac.finalize().into_bytes();
    digest[..SALT_LEN].to_vec()
}

/// What the server stores for an account: never the password, and never the
/// salted password (which would be password-equivalent).
#[derive(Clone, PartialEq, Eq)]
pub struct StoredCredential {
    pub salt: Vec<u8>,
    pub params: KdfParams,
    pub stored_key: [u8; 32],
    pub server_key: [u8; 32],
}

impl StoredCredential {
    /// Derive a credential for a new password with a fresh random salt and
    /// [`KdfParams::DEFAULT`]. Runs Argon2 (blocking).
    pub fn derive(password: &str) -> Result<Self, CryptoError> {
        let mut salt = vec![0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        Self::derive_with(password, &salt, KdfParams::DEFAULT)
    }

    /// Derive a credential with an explicit salt and parameters.
    pub fn derive_with(
        password: &str,
        salt: &[u8],
        params: KdfParams,
    ) -> Result<Self, CryptoError> {
        let salted = salted_password(password.as_bytes(), salt, &params)?;
        Ok(Self::from_salted_password(&salted, salt.to_vec(), params))
    }

    /// Convert a legacy (protocol v1) Argon2id PHC string. Its hash output is
    /// exactly the SaltedPassword, so StoredKey/ServerKey derive from it with
    /// no user action; the PHC string itself must then be discarded.
    pub fn from_legacy_phc(phc: &str) -> Result<Self, CryptoError> {
        let parsed = PasswordHash::new(phc).map_err(CryptoError::Hash)?;
        if parsed.algorithm.as_str() != "argon2id" {
            return Err(CryptoError::LegacyHash("not an argon2id hash"));
        }
        if parsed.version.is_some_and(|v| v != Version::V0x13 as u32) {
            return Err(CryptoError::LegacyHash("unsupported argon2 version"));
        }
        let salt = parsed.salt.ok_or(CryptoError::MissingSalt)?;
        let mut salt_buf = [0u8; MAX_SALT_LEN];
        let salt_bytes = salt.decode_b64(&mut salt_buf).map_err(CryptoError::Hash)?;
        let params = Params::try_from(&parsed).map_err(CryptoError::Hash)?;
        if !params.keyid().is_empty() || !params.data().is_empty() {
            return Err(CryptoError::LegacyHash(
                "keyed argon2 hashes are not supported",
            ));
        }
        let hash = parsed.hash.ok_or(CryptoError::MissingSalt)?;
        let salted: [u8; 32] = hash
            .as_bytes()
            .try_into()
            .map_err(|_| CryptoError::LegacyHash("hash output is not 32 bytes"))?;
        let salted = Zeroizing::new(salted);
        Ok(Self::from_salted_password(
            &salted,
            salt_bytes.to_vec(),
            KdfParams {
                m_cost: params.m_cost(),
                t_cost: params.t_cost(),
                p_cost: params.p_cost(),
            },
        ))
    }

    fn from_salted_password(salted: &[u8; 32], salt: Vec<u8>, params: KdfParams) -> Self {
        let keys = Keys::from_salted_password(salted);
        Self {
            salt,
            params,
            stored_key: keys.stored_key,
            server_key: keys.server_key,
        }
    }

    /// Server side: check a client's proof for this account. Returns the
    /// `ServerSignature` to send back on success, `None` on any mismatch
    /// (wrong password, different challenge, different TLS session, or a
    /// proof forged from the stored record alone).
    pub fn verify_proof(
        &self,
        username: &str,
        challenge: &[u8; 32],
        channel_binding: &[u8; CHANNEL_BINDING_LEN],
        proof: &[u8; 32],
    ) -> Option<[u8; 32]> {
        let ctx = AuthContext {
            username,
            challenge,
            salt: &self.salt,
            params: self.params,
            channel_binding,
        };
        let auth_message = ctx.auth_message();
        let client_signature = Zeroizing::new(hmac(&self.stored_key, &auth_message));
        let mut client_key = Zeroizing::new([0u8; 32]);
        for (i, byte) in client_key.iter_mut().enumerate() {
            *byte = proof[i] ^ client_signature[i];
        }
        let candidate: [u8; 32] = Sha256::digest(client_key.as_ref()).into();
        if bool::from(candidate.ct_eq(&self.stored_key)) {
            Some(hmac(&self.server_key, &auth_message))
        } else {
            None
        }
    }

    /// Direct password check (no challenge): re-derive and compare StoredKey
    /// in constant time. Runs Argon2 (blocking).
    pub fn matches_password(&self, password: &str) -> Result<bool, CryptoError> {
        let candidate = Self::derive_with(password, &self.salt, self.params)?;
        Ok(candidate.stored_key.ct_eq(&self.stored_key).into())
    }

    /// Serialize for storage:
    /// `$kdx-scram-sha256$v=1$m=<m>,t=<t>,p=<p>$<salt>$<StoredKey>$<ServerKey>`
    /// (binary fields lowercase hex).
    pub fn encode(&self) -> String {
        format!(
            "${CREDENTIAL_SCHEME}${CREDENTIAL_VERSION}$m={},t={},p={}${}${}${}",
            self.params.m_cost,
            self.params.t_cost,
            self.params.p_cost,
            to_hex(&self.salt),
            to_hex(&self.stored_key),
            to_hex(&self.server_key),
        )
    }

    /// Parse the [`StoredCredential::encode`] form.
    pub fn decode(encoded: &str) -> Result<Self, CryptoError> {
        let bad = || CryptoError::MalformedCredential;
        let parts: Vec<&str> = encoded.split('$').collect();
        let [empty, scheme, version, params, salt, stored_key, server_key] = parts[..] else {
            return Err(bad());
        };
        if !empty.is_empty() || scheme != CREDENTIAL_SCHEME || version != CREDENTIAL_VERSION {
            return Err(bad());
        }
        let mut m_cost = None;
        let mut t_cost = None;
        let mut p_cost = None;
        for kv in params.split(',') {
            let (key, value) = kv.split_once('=').ok_or_else(bad)?;
            let value: u32 = value.parse().map_err(|_| bad())?;
            let slot = match key {
                "m" => &mut m_cost,
                "t" => &mut t_cost,
                "p" => &mut p_cost,
                _ => return Err(bad()),
            };
            if slot.replace(value).is_some() {
                return Err(bad());
            }
        }
        let params = KdfParams {
            m_cost: m_cost.ok_or_else(bad)?,
            t_cost: t_cost.ok_or_else(bad)?,
            p_cost: p_cost.ok_or_else(bad)?,
        };
        let salt = from_hex(salt).ok_or_else(bad)?;
        if salt.is_empty() || salt.len() > MAX_SALT_LEN {
            return Err(bad());
        }
        let stored_key: [u8; 32] = from_hex(stored_key)
            .and_then(|v| v.try_into().ok())
            .ok_or_else(bad)?;
        let server_key: [u8; 32] = from_hex(server_key)
            .and_then(|v| v.try_into().ok())
            .ok_or_else(bad)?;
        Ok(Self {
            salt,
            params,
            stored_key,
            server_key,
        })
    }
}

impl Drop for StoredCredential {
    fn drop(&mut self) {
        self.stored_key.zeroize();
        self.server_key.zeroize();
    }
}

impl fmt::Debug for StoredCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredCredential")
            .field("params", &self.params)
            .field("salt_len", &self.salt.len())
            .finish_non_exhaustive()
    }
}

struct Keys {
    client_key: Zeroizing<[u8; 32]>,
    stored_key: [u8; 32],
    server_key: [u8; 32],
}

impl Keys {
    fn from_salted_password(salted: &[u8; 32]) -> Self {
        let client_key = Zeroizing::new(hmac(salted, b"Client Key"));
        let stored_key: [u8; 32] = Sha256::digest(client_key.as_ref()).into();
        let server_key = hmac(salted, b"Server Key");
        Self {
            client_key,
            stored_key,
            server_key,
        }
    }
}

fn salted_password(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(CryptoError::Params)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, salt, out.as_mut())
        .map_err(CryptoError::Params)?;
    Ok(out)
}

fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0F) as usize] as char);
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::generate_challenge;
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};

    const USER: &str = "phraq";
    const BINDING_A: [u8; 32] = [0xA1; 32];
    const BINDING_B: [u8; 32] = [0xB2; 32];

    fn ctx<'a>(
        cred: &'a StoredCredential,
        challenge: &'a [u8; 32],
        binding: &'a [u8; 32],
    ) -> AuthContext<'a> {
        AuthContext {
            username: USER,
            challenge,
            salt: &cred.salt,
            params: cred.params,
            channel_binding: binding,
        }
    }

    #[test]
    fn correct_password_verifies_and_server_signature_checks_out() {
        let cred = StoredCredential::derive("open sesame").unwrap();
        let challenge = generate_challenge();
        let client = client_proof("open sesame", &ctx(&cred, &challenge, &BINDING_A)).unwrap();

        let signature = cred
            .verify_proof(USER, &challenge, &BINDING_A, &client.proof)
            .expect("proof verifies");
        assert!(client.verify_server_signature(&signature));
        assert!(!client.verify_server_signature(&[0u8; 32]));
    }

    #[test]
    fn wrong_password_fails() {
        let cred = StoredCredential::derive("open sesame").unwrap();
        let challenge = generate_challenge();
        let client = client_proof("open salami", &ctx(&cred, &challenge, &BINDING_A)).unwrap();
        assert!(cred
            .verify_proof(USER, &challenge, &BINDING_A, &client.proof)
            .is_none());
    }

    #[test]
    fn relayed_proof_fails_on_another_channel() {
        // A malicious server M relays the victim's login to server T: the
        // victim computes its proof on its TLS session with M (binding A),
        // while T checks it against its own session with M (binding B).
        let cred = StoredCredential::derive("open sesame").unwrap();
        let challenge = generate_challenge();
        let client = client_proof("open sesame", &ctx(&cred, &challenge, &BINDING_A)).unwrap();
        assert!(cred
            .verify_proof(USER, &challenge, &BINDING_B, &client.proof)
            .is_none());
    }

    #[test]
    fn proof_is_bound_to_challenge_and_username() {
        let cred = StoredCredential::derive("open sesame").unwrap();
        let first = generate_challenge();
        let client = client_proof("open sesame", &ctx(&cred, &first, &BINDING_A)).unwrap();
        let second = generate_challenge();
        assert!(cred
            .verify_proof(USER, &second, &BINDING_A, &client.proof)
            .is_none());
        assert!(cred
            .verify_proof("someone-else", &first, &BINDING_A, &client.proof)
            .is_none());
    }

    #[test]
    fn stored_record_alone_cannot_log_in() {
        // An attacker with a copy of the database has salt, params,
        // StoredKey and ServerKey — but not ClientKey.
        let cred = StoredCredential::derive("open sesame").unwrap();
        let challenge = generate_challenge();
        let auth_message = ctx(&cred, &challenge, &BINDING_A).auth_message();
        let client_signature = hmac(&cred.stored_key, &auth_message);

        let guesses = [
            // Treat StoredKey or ServerKey as if it were ClientKey.
            xor(&cred.stored_key, &client_signature),
            xor(&cred.server_key, &client_signature),
            // The protocol-v1 answer computed from stored data.
            Sha256::new()
                .chain_update(challenge)
                .chain_update(cred.stored_key)
                .finalize()
                .into(),
            cred.stored_key,
            client_signature,
        ];
        for guess in guesses {
            assert!(cred
                .verify_proof(USER, &challenge, &BINDING_A, &guess)
                .is_none());
        }
        // The encoded record carries no password-equivalent material either.
        let encoded = cred.encode();
        let decoded = StoredCredential::decode(&encoded).unwrap();
        assert_eq!(decoded, cred);
    }

    #[test]
    fn hostile_kdf_params_are_refused_before_argon2() {
        let challenge = generate_challenge();
        let salt = [7u8; 16];
        for params in [
            KdfParams {
                m_cost: u32::MAX,
                t_cost: 1,
                p_cost: 1,
            },
            KdfParams {
                m_cost: 8,
                t_cost: u32::MAX,
                p_cost: 1,
            },
            KdfParams {
                m_cost: 8,
                t_cost: 1,
                p_cost: 1,
            },
        ] {
            let ctx = AuthContext {
                username: USER,
                challenge: &challenge,
                salt: &salt,
                params,
                channel_binding: &BINDING_A,
            };
            assert!(matches!(
                client_proof("pw", &ctx),
                Err(CryptoError::UnacceptableKdf(_))
            ));
        }
    }

    #[test]
    fn legacy_phc_conversion_is_equivalent() {
        // A protocol-v1 database row: Argon2id PHC with the crate defaults.
        let salt = SaltString::generate(&mut OsRng);
        let phc = Argon2::default()
            .hash_password(b"open sesame", &salt)
            .unwrap()
            .to_string();

        let converted = StoredCredential::from_legacy_phc(&phc).unwrap();
        assert_eq!(converted.params, KdfParams::DEFAULT);
        assert_eq!(converted.salt.len(), SALT_LEN);
        // Same keys as a fresh derivation from the password with that salt.
        let fresh = StoredCredential::derive_with("open sesame", &converted.salt, converted.params)
            .unwrap();
        assert_eq!(converted, fresh);

        // And a v2 client login against the converted record works.
        let challenge = generate_challenge();
        let client = client_proof("open sesame", &ctx(&converted, &challenge, &BINDING_A)).unwrap();
        let sig = converted
            .verify_proof(USER, &challenge, &BINDING_A, &client.proof)
            .unwrap();
        assert!(client.verify_server_signature(&sig));
        assert!(converted.matches_password("open sesame").unwrap());
        assert!(!converted.matches_password("open salami").unwrap());
    }

    #[test]
    fn legacy_conversion_rejects_other_algorithms() {
        let salt = SaltString::generate(&mut OsRng);
        let argon2i = Argon2::new(Algorithm::Argon2i, Version::V0x13, Params::default());
        let phc = argon2i.hash_password(b"pw", &salt).unwrap().to_string();
        assert!(StoredCredential::from_legacy_phc(&phc).is_err());
        assert!(StoredCredential::from_legacy_phc("not a phc").is_err());
    }

    #[test]
    fn decode_rejects_malformed_records() {
        let good = StoredCredential::derive("pw").unwrap().encode();
        assert!(StoredCredential::decode(&good).is_ok());
        for bad in [
            "",
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA",
            &good.replace("v=1", "v=2"),
            &good.replace("m=", "x="),
            &good.replace(",p=1", ",p=1,p=1"),
            &good[..good.len() - 2],
            &format!("{good}$extra"),
        ] {
            assert!(StoredCredential::decode(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn decoy_salt_is_keyed_and_stable() {
        let secret_a = [1u8; 32];
        let secret_b = [2u8; 32];
        let a = decoy_salt(&secret_a, "nobody");
        assert_eq!(a.len(), SALT_LEN);
        assert_eq!(a, decoy_salt(&secret_a, "nobody"));
        assert_ne!(a, decoy_salt(&secret_b, "nobody"));
        assert_ne!(a, decoy_salt(&secret_a, "somebody"));
        // Not the protocol-v1 predictable SHA-256(username) prefix.
        assert_ne!(a[..], Sha256::digest(b"nobody")[..SALT_LEN]);
    }

    #[test]
    fn debug_output_redacts_keys() {
        let cred = StoredCredential::derive("pw").unwrap();
        let shown = format!("{cred:?}");
        assert!(!shown.contains(&to_hex(&cred.stored_key)));
        assert!(!shown.contains("stored_key"));
    }

    fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = a[i] ^ b[i];
        }
        out
    }
}
