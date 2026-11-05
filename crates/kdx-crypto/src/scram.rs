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
//!
//! # Password change
//!
//! A logged-in user changes their password with the same kind of proof over
//! a different message ([`PasswordChangeContext`]): a distinct domain label,
//! the login fields for the *current* credential (with a fresh change
//! challenge), plus the whole *new* credential the client derived locally
//! (fresh salt, StoredKey, ServerKey). Neither password crosses the wire,
//! the proof authorizes exactly that new credential, and the distinct label
//! means a login proof never verifies as a password-change proof or vice
//! versa:
//!
//! ```text
//! ChangeMessage   = "KDX-PWCHANGE-v1" 0x00
//!                   || u32 len(username) || username
//!                   || challenge (32)
//!                   || u32 len(salt) || salt || m || t || p      (current)
//!                   || channel_binding (32)
//!                   || u32 len(new salt) || new salt || m || t || p
//!                   || new StoredKey (32) || new ServerKey (32)
//! ClientProof     = ClientKey XOR HMAC-SHA256(StoredKey, ChangeMessage)
//! ServerSignature = HMAC-SHA256(ServerKey, ChangeMessage)       (current keys)
//! ```
//!
//! A credential that arrives from a client (password change, admin reset,
//! account creation) must pass [`StoredCredential::check_acceptable`] before
//! a server stores it.

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
const PASSWORD_CHANGE_LABEL: &[u8] = b"KDX-PWCHANGE-v1\0";
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
        self.message_with_label(AUTH_MESSAGE_LABEL, 0)
    }

    /// `label` followed by every AuthMessage field, with room for `extra`
    /// more bytes.
    fn message_with_label(&self, label: &[u8], extra: usize) -> Vec<u8> {
        let mut m = Vec::with_capacity(
            label.len() + 4 + self.username.len() + 32 + 4 + self.salt.len() + 12 + 32 + extra,
        );
        m.extend_from_slice(label);
        put_bytes(&mut m, self.username.as_bytes());
        m.extend_from_slice(self.challenge);
        put_bytes(&mut m, self.salt);
        put_params(&mut m, &self.params);
        m.extend_from_slice(self.channel_binding);
        m
    }
}

/// Everything a password-change proof is bound to: the login fields for the
/// account's *current* credential (with a fresh change challenge) plus the
/// complete *new* credential the client wants stored.
#[derive(Debug, Clone, Copy)]
pub struct PasswordChangeContext<'a> {
    /// The session's username, the change challenge, the *current* salt and
    /// parameters, and this connection's TLS exporter value.
    pub current: AuthContext<'a>,
    /// The credential to store if the proof verifies.
    pub new_credential: &'a StoredCredential,
}

impl PasswordChangeContext<'_> {
    /// The canonical ChangeMessage both sides MAC (see the module docs).
    pub fn change_message(&self) -> Vec<u8> {
        let new = self.new_credential;
        let mut m = self
            .current
            .message_with_label(PASSWORD_CHANGE_LABEL, 4 + new.salt.len() + 12 + 64);
        put_bytes(&mut m, &new.salt);
        put_params(&mut m, &new.params);
        m.extend_from_slice(&new.stored_key);
        m.extend_from_slice(&new.server_key);
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
    prove(password, ctx.salt, &ctx.params, &ctx.auth_message())
}

/// Client side: prove knowledge of the *current* password for a change to
/// `ctx.new_credential` (derive that from the new password first, with
/// [`StoredCredential::derive`]). The returned proof's server signature is
/// the one an honest server answers a successful change with.
///
/// Refuses, before running Argon2, current parameters outside the client
/// bounds and a new credential that fails
/// [`StoredCredential::check_acceptable`]. Runs Argon2 (blocking).
pub fn password_change_proof(
    current_password: &str,
    ctx: &PasswordChangeContext<'_>,
) -> Result<ClientProof, CryptoError> {
    ctx.new_credential.check_acceptable()?;
    let current = &ctx.current;
    prove(
        current_password,
        current.salt,
        &current.params,
        &ctx.change_message(),
    )
}

/// `ClientKey XOR HMAC(StoredKey, message)` for `password`, plus the
/// ServerSignature an honest server answers with. Checks the KDF bounds
/// before running Argon2.
fn prove(
    password: &str,
    salt: &[u8],
    params: &KdfParams,
    message: &[u8],
) -> Result<ClientProof, CryptoError> {
    params.check_bounds(salt.len())?;
    let salted = salted_password(password.as_bytes(), salt, params)?;
    let keys = Keys::from_salted_password(&salted);
    let client_signature = Zeroizing::new(hmac(&keys.stored_key, message));
    let mut proof = [0u8; 32];
    for (i, byte) in proof.iter_mut().enumerate() {
        *byte = keys.client_key[i] ^ client_signature[i];
    }
    Ok(ClientProof {
        proof,
        server_signature: hmac(&keys.server_key, message),
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
        self.verify(&ctx.auth_message(), proof)
    }

    /// Server side: check a password-change proof made against this (the
    /// account's current) credential for replacing it with `new` — like
    /// [`StoredCredential::verify_proof`], but over the ChangeMessage.
    /// Returns the `ServerSignature` (current ServerKey) on success. A login
    /// proof never verifies here, nor does a change proof made for any other
    /// new credential. Validate `new` with
    /// [`StoredCredential::check_acceptable`] before storing it.
    pub fn verify_password_change_proof(
        &self,
        username: &str,
        challenge: &[u8; 32],
        channel_binding: &[u8; CHANNEL_BINDING_LEN],
        new: &StoredCredential,
        proof: &[u8; 32],
    ) -> Option<[u8; 32]> {
        let ctx = PasswordChangeContext {
            current: AuthContext {
                username,
                challenge,
                salt: &self.salt,
                params: self.params,
                channel_binding,
            },
            new_credential: new,
        };
        self.verify(&ctx.change_message(), proof)
    }

    /// Recover `ClientKey = proof XOR HMAC(StoredKey, message)` and accept
    /// iff `SHA-256(ClientKey) == StoredKey` (constant time); the answer is
    /// `HMAC(ServerKey, message)`.
    fn verify(&self, message: &[u8], proof: &[u8; 32]) -> Option<[u8; 32]> {
        let client_signature = Zeroizing::new(hmac(&self.stored_key, message));
        let mut client_key = Zeroizing::new([0u8; 32]);
        for (i, byte) in client_key.iter_mut().enumerate() {
            *byte = proof[i] ^ client_signature[i];
        }
        let candidate: [u8; 32] = Sha256::digest(client_key.as_ref()).into();
        if bool::from(candidate.ct_eq(&self.stored_key)) {
            Some(hmac(&self.server_key, message))
        } else {
            None
        }
    }

    /// Whether a credential that came from a client (a password change, an
    /// admin's reset, a new account) is fit to store: salt length and KDF
    /// parameters within the client bounds ([`KdfParams::check_bounds`] —
    /// no client would ever log in against anything outside them) and
    /// non-zero keys (key lengths are fixed by the type). The password
    /// behind it can't be checked here; password policy is the deriving
    /// client's job.
    pub fn check_acceptable(&self) -> Result<(), CryptoError> {
        self.params.check_bounds(self.salt.len())?;
        if self.stored_key == [0u8; 32] || self.server_key == [0u8; 32] {
            return Err(CryptoError::UnacceptableKdf("credential key is all zeros"));
        }
        Ok(())
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

fn put_params(out: &mut Vec<u8>, params: &KdfParams) {
    out.extend_from_slice(&params.m_cost.to_be_bytes());
    out.extend_from_slice(&params.t_cost.to_be_bytes());
    out.extend_from_slice(&params.p_cost.to_be_bytes());
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

    fn change_ctx<'a>(
        current: &'a StoredCredential,
        challenge: &'a [u8; 32],
        binding: &'a [u8; 32],
        new: &'a StoredCredential,
    ) -> PasswordChangeContext<'a> {
        PasswordChangeContext {
            current: ctx(current, challenge, binding),
            new_credential: new,
        }
    }

    #[test]
    fn password_change_proof_verifies_and_signs() {
        let current = StoredCredential::derive("open sesame").unwrap();
        let new = StoredCredential::derive("open barley").unwrap();
        let challenge = generate_challenge();
        let client = password_change_proof(
            "open sesame",
            &change_ctx(&current, &challenge, &BINDING_A, &new),
        )
        .unwrap();
        let signature = current
            .verify_password_change_proof(USER, &challenge, &BINDING_A, &new, &client.proof)
            .expect("change proof verifies");
        assert!(client.verify_server_signature(&signature));
        // The new credential works for the new password only.
        assert!(new.matches_password("open barley").unwrap());
        assert!(!new.matches_password("open sesame").unwrap());
    }

    #[test]
    fn password_change_proof_needs_the_current_password() {
        let current = StoredCredential::derive("open sesame").unwrap();
        let new = StoredCredential::derive("open barley").unwrap();
        let challenge = generate_challenge();
        // Proving with the NEW password (or any other) is not enough.
        for guess in ["open barley", "open salami"] {
            let client =
                password_change_proof(guess, &change_ctx(&current, &challenge, &BINDING_A, &new))
                    .unwrap();
            assert!(current
                .verify_password_change_proof(USER, &challenge, &BINDING_A, &new, &client.proof)
                .is_none());
        }
    }

    #[test]
    fn login_and_change_proofs_are_not_interchangeable() {
        let current = StoredCredential::derive("open sesame").unwrap();
        let new = StoredCredential::derive("open barley").unwrap();
        let challenge = generate_challenge();

        // A login proof (same challenge, same channel) is no change proof...
        let login = client_proof("open sesame", &ctx(&current, &challenge, &BINDING_A)).unwrap();
        assert!(current
            .verify_proof(USER, &challenge, &BINDING_A, &login.proof)
            .is_some());
        assert!(current
            .verify_password_change_proof(USER, &challenge, &BINDING_A, &new, &login.proof)
            .is_none());

        // ...and a change proof is no login proof.
        let change = password_change_proof(
            "open sesame",
            &change_ctx(&current, &challenge, &BINDING_A, &new),
        )
        .unwrap();
        assert!(current
            .verify_proof(USER, &challenge, &BINDING_A, &change.proof)
            .is_none());
        // Different labels, so the messages differ even with every field equal.
        let auth_message = ctx(&current, &challenge, &BINDING_A).auth_message();
        let change_message = change_ctx(&current, &challenge, &BINDING_A, &new).change_message();
        assert!(!change_message.starts_with(&auth_message[..12]));
    }

    #[test]
    fn change_proof_is_bound_to_the_new_credential_channel_and_challenge() {
        let current = StoredCredential::derive("open sesame").unwrap();
        let new = StoredCredential::derive("open barley").unwrap();
        let swapped = StoredCredential::derive("attacker's choice").unwrap();
        let challenge = generate_challenge();
        let client = password_change_proof(
            "open sesame",
            &change_ctx(&current, &challenge, &BINDING_A, &new),
        )
        .unwrap();
        // Someone who swaps in their own credential can't reuse the proof.
        assert!(current
            .verify_password_change_proof(USER, &challenge, &BINDING_A, &swapped, &client.proof)
            .is_none());
        // Nor relay it to another TLS session, another challenge or account.
        assert!(current
            .verify_password_change_proof(USER, &challenge, &BINDING_B, &new, &client.proof)
            .is_none());
        assert!(current
            .verify_password_change_proof(
                USER,
                &generate_challenge(),
                &BINDING_A,
                &new,
                &client.proof
            )
            .is_none());
        assert!(current
            .verify_password_change_proof("someone-else", &challenge, &BINDING_A, &new, &client.proof)
            .is_none());
    }

    #[test]
    fn unacceptable_new_credentials_are_refused() {
        let good = StoredCredential::derive("pw").unwrap();
        good.check_acceptable().unwrap();
        let tweak = |f: &dyn Fn(&mut StoredCredential)| {
            let mut c = good.clone();
            f(&mut c);
            c
        };
        let bad = [
            tweak(&|c| c.params.m_cost = 8),
            tweak(&|c| c.params.t_cost = 1),
            tweak(&|c| c.params.p_cost = 0),
            tweak(&|c| c.params.m_cost = u32::MAX),
            tweak(&|c| c.salt = vec![1; 8]),
            tweak(&|c| c.salt = vec![1; 65]),
            tweak(&|c| c.stored_key = [0; 32]),
            tweak(&|c| c.server_key = [0; 32]),
        ];
        let current = StoredCredential::derive("open sesame").unwrap();
        let challenge = generate_challenge();
        for new in &bad {
            assert!(
                matches!(new.check_acceptable(), Err(CryptoError::UnacceptableKdf(_))),
                "{new:?} accepted"
            );
            // The client refuses to authorize one too.
            assert!(matches!(
                password_change_proof(
                    "open sesame",
                    &change_ctx(&current, &challenge, &BINDING_A, new)
                ),
                Err(CryptoError::UnacceptableKdf(_))
            ));
        }
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
