//! Challenge-response authentication (SCRAM-style, TLS-channel-bound; see
//! `kdx_crypto::scram`) and the in-memory session table.

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use dashmap::DashMap;
use kdx_crypto::{KdfParams, StoredCredential, CHANNEL_BINDING_LEN};
use kdx_storage::accounts::{self, AccountRow};
use kdx_storage::{SqlitePool, StorageError};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;
use tokio::time::Instant;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::classes::{effective_privileges, BaseClass, Privileges};

/// `server_secrets` row holding the key for unknown-user decoy salts.
const DECOY_KEY_SECRET: &str = "auth.decoy_salt_key";

/// How long a password-change challenge stays valid for its proof.
pub const PASSWORD_CHANGE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    /// The account is banned until `until` (unix seconds). The credentials may
    /// have been correct; login is refused regardless.
    #[error("account banned")]
    Banned { until: i64, reason: String },
    #[error("an account with that name already exists")]
    AccountExists,
    #[error("username must be 1 to {} bytes", crate::limits::MAX_USERNAME_LEN)]
    InvalidUsername,
    /// The session's account was deleted or replaced.
    #[error("your account no longer exists")]
    AccountGone,
    /// The credential a password change was proven against was replaced
    /// meanwhile (another change, or an admin reset).
    #[error("your password was changed meanwhile; start again")]
    CredentialChanged,
    #[error("storage error: {0}")]
    Storage(#[from] kdx_storage::StorageError),
    #[error("crypto error: {0}")]
    Crypto(#[from] kdx_crypto::CryptoError),
    #[error("internal error: {0}")]
    Internal(&'static str),
}

/// An authenticated session. It stays registered for exactly as long as its
/// connection is logged in: the connection's guards end it on every path,
/// and the connection enforces `session_ttl` as an idle timeout.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: Uuid,
    pub account_id: String,
    pub username: String,
    pub class: BaseClass,
    pub privileges: Privileges,
    /// Login time plus `session_ttl`. Informational only: nothing expires a
    /// live session by age (that let `max_users` stop counting long-lived
    /// connections).
    pub expires_at: Instant,
}

/// Data for the `AuthChallenge` packet.
#[derive(Debug)]
pub struct ChallengeData {
    pub challenge: [u8; 32],
    pub salt: Vec<u8>,
    pub params: KdfParams,
}

/// Server-side state for one in-flight login attempt, held by the
/// connection task between challenge and response. It pins the whole
/// transcript the client's proof must be bound to.
#[derive(Debug)]
pub struct PendingAuth {
    challenge: [u8; 32],
    /// The username exactly as requested (part of the AuthMessage).
    username: String,
    /// This connection's TLS exporter value.
    channel_binding: [u8; CHANNEL_BINDING_LEN],
    /// The salt sent in the challenge (real or decoy).
    salt: Vec<u8>,
    /// `None` when the username didn't exist (or its credential is
    /// unusable) — we still issued a decoy challenge so the wire looks
    /// identical (anti-enumeration), and the response check will simply fail.
    account: Option<(AccountRow, StoredCredential)>,
}

/// A verified login, not yet registered: the connection registers it with
/// [`AuthManager::activate`] once it is ready to deliver the result.
#[derive(Debug)]
pub struct Verified {
    pub session: Session,
    /// `HMAC(ServerKey, AuthMessage)`, returned in the successful
    /// `AuthResult` so the client can authenticate the server.
    pub server_signature: [u8; 32],
    /// Which credential the login was proven against, so the connection can
    /// tell (with [`AuthManager::credential_stamp`]) whether a password
    /// change or reset replaced it while the login was in flight.
    pub credential_stamp: CredentialStamp,
}

/// Identifies one stored credential (a hash of its encoding) without
/// holding any of its key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialStamp([u8; 32]);

impl CredentialStamp {
    fn of(credential: &StoredCredential) -> Self {
        Self(Sha256::digest(credential.encode().as_bytes()).into())
    }
}

/// A password change in flight on one connection, between
/// `PasswordChangeChallenge` and `PasswordChangeProof`: it pins the
/// transcript the proof must be bound to and the credential the change may
/// replace. Valid for one proof, until [`PASSWORD_CHANGE_TIMEOUT`].
pub struct PendingPasswordChange {
    challenge: [u8; 32],
    account_id: String,
    username: String,
    channel_binding: [u8; CHANNEL_BINDING_LEN],
    /// The account's credential when the challenge went out.
    credential: StoredCredential,
    /// Its stored encoding, which the change compares-and-swaps against.
    stored: String,
    expires_at: Instant,
}

impl PendingPasswordChange {
    /// Whether the challenge is too old to answer.
    pub fn expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// The account being changed.
    pub fn username(&self) -> &str {
        &self.username
    }
}

impl std::fmt::Debug for PendingPasswordChange {
    // Credential material stays out of logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingPasswordChange")
            .field("username", &self.username)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Keeps an activated session registered only if the login completes: drop
/// it without calling [`SessionGuard::keep`] (an error return, a timeout
/// cancelling the future) and the session is removed again.
#[must_use = "dropping the guard ends the session"]
pub struct SessionGuard<'a> {
    auth: &'a AuthManager,
    id: Option<Uuid>,
}

impl SessionGuard<'_> {
    /// The login was delivered; keep the session.
    pub fn keep(mut self) {
        self.id = None;
    }
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.auth.end_session(id);
        }
    }
}

pub struct AuthManager {
    pool: SqlitePool,
    sessions: DashMap<Uuid, Session>,
    /// Makes the `max_users` check and the insert it guards one step (see
    /// [`AuthManager::admit`]).
    admission: Mutex<()>,
    session_ttl: Duration,
    /// Per-server key for unknown-user decoy salts. Initialising it also
    /// converts legacy credentials (see [`AuthManager::prepare`]).
    decoy_key: OnceCell<[u8; 32]>,
}

impl AuthManager {
    pub fn new(pool: SqlitePool, session_ttl: Duration) -> Self {
        Self {
            pool,
            sessions: DashMap::new(),
            admission: Mutex::new(()),
            session_ttl,
            decoy_key: OnceCell::new(),
        }
    }

    /// One-time startup work: convert any legacy (protocol v1) Argon2 PHC
    /// rows — which are password-equivalent — to SCRAM credentials and wipe
    /// the PHC strings, then load (or generate) the decoy-salt key.
    /// Idempotent. `begin` runs it lazily too, but a server should call it
    /// at startup so old hashes don't sit in the database until the next
    /// login attempt.
    pub async fn prepare(&self) -> Result<(), AuthError> {
        self.decoy_key().await.map(|_| ())
    }

    async fn decoy_key(&self) -> Result<&[u8; 32], AuthError> {
        self.decoy_key
            .get_or_try_init(|| async {
                self.upgrade_legacy_credentials().await?;
                let mut candidate = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut candidate);
                let stored =
                    accounts::server_secret(&self.pool, DECOY_KEY_SECRET, &candidate).await?;
                <[u8; 32]>::try_from(stored)
                    .map_err(|_| AuthError::Internal("stored decoy key has the wrong length"))
            })
            .await
    }

    async fn upgrade_legacy_credentials(&self) -> Result<usize, AuthError> {
        let rows = accounts::legacy_rows(&self.pool).await?;
        let mut converted = 0;
        for row in rows {
            match StoredCredential::from_legacy_phc(&row.password_phc) {
                Ok(credential) => {
                    if accounts::upgrade_credential(&self.pool, &row.id, &credential.encode())
                        .await?
                    {
                        converted += 1;
                    }
                }
                Err(e) => warn!(
                    user = %row.username,
                    error = %e,
                    "cannot convert legacy password hash; the account cannot log in"
                ),
            }
        }
        if converted > 0 {
            info!(
                converted,
                "converted legacy password hashes to SCRAM credentials"
            );
            // Don't leave the wiped hashes in free pages or the WAL.
            if let Err(e) = accounts::compact(&self.pool).await {
                warn!(error = %e, "could not compact the database after credential conversion");
            }
        }
        Ok(converted)
    }

    /// The usable credential for an account row, converting a legacy row on
    /// the fly. `None` (logged) if the row's credential can't be used.
    async fn credential_for(&self, row: &AccountRow) -> Option<StoredCredential> {
        if let Some(encoded) = &row.credential {
            return match StoredCredential::decode(encoded) {
                Ok(credential) => Some(credential),
                Err(e) => {
                    warn!(user = %row.username, error = %e, "unusable stored credential");
                    None
                }
            };
        }
        match StoredCredential::from_legacy_phc(&row.password_phc) {
            Ok(credential) => {
                if let Err(e) =
                    accounts::upgrade_credential(&self.pool, &row.id, &credential.encode()).await
                {
                    warn!(user = %row.username, error = %e, "could not store converted credential");
                }
                Some(credential)
            }
            Err(e) => {
                warn!(user = %row.username, error = %e, "cannot convert legacy password hash");
                None
            }
        }
    }

    /// Start a login: look up the account and issue a challenge bound to
    /// `channel_binding` (this connection's TLS exporter value). Unknown
    /// usernames get a decoy challenge — a salt keyed by a per-server secret
    /// and the same parameters real accounts use — so the response from the
    /// wire can't distinguish "no such user" from "wrong password".
    pub async fn begin(
        &self,
        username: &str,
        channel_binding: [u8; CHANNEL_BINDING_LEN],
    ) -> Result<(ChallengeData, PendingAuth), AuthError> {
        let decoy_key = *self.decoy_key().await?;
        let challenge = kdx_crypto::generate_challenge();
        let account = match accounts::by_username(&self.pool, username).await? {
            Some(row) => self.credential_for(&row).await.map(|c| (row, c)),
            None => None,
        };

        let (salt, params) = match &account {
            Some((_, credential)) => (credential.salt.clone(), credential.params),
            None => (
                kdx_crypto::decoy_salt(&decoy_key, username),
                KdfParams::DEFAULT,
            ),
        };

        Ok((
            ChallengeData {
                challenge,
                salt: salt.clone(),
                params,
            },
            PendingAuth {
                challenge,
                username: username.to_owned(),
                channel_binding,
                salt,
                account,
            },
        ))
    }

    /// Verify the client's proof and build (but don't register) a session.
    pub async fn complete(
        &self,
        pending: PendingAuth,
        proof: &[u8; 32],
    ) -> Result<Verified, AuthError> {
        let Some((account, credential)) = pending.account else {
            // Same work as a wrong password against a real record, so the
            // failure takes the same time.
            let decoy = StoredCredential {
                salt: pending.salt,
                params: KdfParams::DEFAULT,
                stored_key: [0u8; 32],
                server_key: [0u8; 32],
            };
            let _ = decoy.verify_proof(
                &pending.username,
                &pending.challenge,
                &pending.channel_binding,
                proof,
            );
            return Err(AuthError::InvalidCredentials);
        };
        let Some(server_signature) = credential.verify_proof(
            &pending.username,
            &pending.challenge,
            &pending.channel_binding,
            proof,
        ) else {
            return Err(AuthError::InvalidCredentials);
        };

        // `account` was read when the challenge went out, up to the whole
        // auth timeout ago. A demotion or override change since then found
        // no live session to kick, so build the session from the row as it
        // is now. An account deleted (or replaced) meanwhile can't log in on
        // the old one's proof.
        // Likewise a password change or reset since then: the old password
        // must not log in once its credential has been replaced.
        let account = match accounts::by_username(&self.pool, &pending.username).await? {
            Some(row) if row.id == account.id && holds_credential(&row, &credential) => row,
            _ => return Err(AuthError::InvalidCredentials),
        };

        // Credentials check out, but an active ban still refuses the login.
        // Checked only after verification so ban status isn't observable to
        // someone who can't authenticate as the account.
        if let Some(ban) =
            kdx_storage::bans::active(&self.pool, &account.id, crate::presence::unix_now() as i64)
                .await?
        {
            return Err(AuthError::Banned {
                until: ban.until,
                reason: ban.reason,
            });
        }

        let class = BaseClass::try_from(account.base_class as u8)
            .map_err(|_| AuthError::InvalidCredentials)?;
        let roles = kdx_storage::roles::for_account(&self.pool, &account.id).await?;
        let role_privileges = roles
            .iter()
            .fold(Privileges::empty(), |acc, r| acc | Privileges::from_bits_truncate(r.privileges as u32));
        let now = Instant::now();
        let session = Session {
            id: Uuid::new_v4(),
            account_id: account.id,
            username: account.username,
            class,
            privileges: effective_privileges(
                class,
                role_privileges,
                account.granted as u32,
                account.revoked as u32,
            ),
            // A huge configured TTL must not overflow (and panic) here.
            expires_at: now
                .checked_add(self.session_ttl)
                .unwrap_or_else(|| now + Duration::from_secs(u32::MAX as u64)),
        };
        Ok(Verified {
            session,
            server_signature,
            credential_stamp: CredentialStamp::of(&credential),
        })
    }

    /// The stamp of `username`'s current credential, if the account still
    /// exists as `account_id` and its credential is usable: compare with
    /// [`Verified::credential_stamp`] to see whether a login went stale.
    pub async fn credential_stamp(
        &self,
        username: &str,
        account_id: &str,
    ) -> Result<Option<CredentialStamp>, AuthError> {
        let Some(row) = accounts::by_username(&self.pool, username).await? else {
            return Ok(None);
        };
        if row.id != account_id {
            return Ok(None);
        }
        Ok(self
            .credential_for(&row)
            .await
            .map(|credential| CredentialStamp::of(&credential)))
    }

    /// Start a password change for `session`'s own account: a fresh
    /// challenge plus the current credential's salt and parameters, pinned
    /// (with `channel_binding`) in the returned pending state.
    pub async fn begin_password_change(
        &self,
        session: &Session,
        channel_binding: [u8; CHANNEL_BINDING_LEN],
    ) -> Result<(ChallengeData, PendingPasswordChange), AuthError> {
        let row = accounts::by_username(&self.pool, &session.username)
            .await?
            .filter(|row| row.id == session.account_id)
            .ok_or(AuthError::AccountGone)?;
        let credential = self
            .credential_for(&row)
            .await
            .ok_or(AuthError::Internal("the account's stored credential is unusable"))?;
        // A legacy row was just converted, and stored as this encoding.
        let stored = row.credential.clone().unwrap_or_else(|| credential.encode());
        let challenge = kdx_crypto::generate_challenge();
        let data = ChallengeData {
            challenge,
            salt: credential.salt.clone(),
            params: credential.params,
        };
        let now = Instant::now();
        Ok((
            data,
            PendingPasswordChange {
                challenge,
                account_id: row.id,
                username: row.username,
                channel_binding,
                credential,
                stored,
                expires_at: now
                    .checked_add(PASSWORD_CHANGE_TIMEOUT)
                    .unwrap_or(now),
            },
        ))
    }

    /// Finish a password change: refuse an unacceptable `new` credential
    /// ([`AuthError::Crypto`], before looking at the proof), verify the
    /// proof of the current password in constant time
    /// ([`AuthError::InvalidCredentials`]), then store `new` in place of
    /// exactly the credential the challenge was issued for
    /// ([`AuthError::CredentialChanged`] if it was replaced meanwhile).
    /// Returns the `ServerSignature` for the client.
    pub async fn complete_password_change(
        &self,
        pending: PendingPasswordChange,
        proof: &[u8; 32],
        new: &StoredCredential,
    ) -> Result<[u8; 32], AuthError> {
        new.check_acceptable()?;
        let Some(server_signature) = pending.credential.verify_password_change_proof(
            &pending.username,
            &pending.challenge,
            &pending.channel_binding,
            new,
            proof,
        ) else {
            return Err(AuthError::InvalidCredentials);
        };
        if !accounts::set_credential(
            &self.pool,
            &pending.account_id,
            &new.encode(),
            Some(&pending.stored),
        )
        .await?
        {
            return Err(AuthError::CredentialChanged);
        }
        Ok(server_signature)
    }

    /// An administrator's password reset: store `credential` for account
    /// `account_id` unconditionally. `false` if there is no such account.
    pub async fn set_credential(
        &self,
        account_id: &str,
        credential: &StoredCredential,
    ) -> Result<bool, AuthError> {
        credential.check_acceptable()?;
        Ok(accounts::set_credential(&self.pool, account_id, &credential.encode(), None).await?)
    }

    /// Register a verified session. Call right before delivering the
    /// successful `AuthResult`, and `keep()` the guard once it (and anything
    /// else the login sends) went out — otherwise the session is removed
    /// again, so an undeliverable login can't leak one.
    pub fn activate(&self, session: &Session) -> SessionGuard<'_> {
        self.admit(session, None)
            .expect("an uncapped admission always succeeds")
    }

    /// [`AuthManager::activate`] under a cap: registers the session only if
    /// fewer than `cap` sessions are registered (`None` = no cap). The check
    /// and the insert are one step, so concurrent logins can't overshoot
    /// the cap. `None` means the server is full.
    pub fn admit(&self, session: &Session, cap: Option<usize>) -> Option<SessionGuard<'_>> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if cap.is_some_and(|cap| self.sessions.len() >= cap) {
            return None;
        }
        self.sessions.insert(session.id, session.clone());
        debug!(user = %session.username, class = ?session.class, "session created");
        Some(SessionGuard {
            auth: self,
            id: Some(session.id),
        })
    }

    /// Number of registered sessions, i.e. logged-in connections: what the
    /// `max_users` cap counts.
    pub fn live_session_count(&self) -> usize {
        self.sessions.len()
    }

    /// The ban in force on an account right now, if any: `(until, reason)`.
    pub async fn active_ban(&self, account_id: &str) -> Result<Option<(i64, String)>, AuthError> {
        let now = crate::presence::unix_now() as i64;
        Ok(kdx_storage::bans::active(&self.pool, account_id, now)
            .await?
            .map(|ban| (ban.until, ban.reason)))
    }

    /// Resolve a username to its account id, for admin operations (e.g. role
    /// assignment) that address accounts by username over the wire.
    pub async fn account_id(&self, username: &str) -> Result<Option<String>, AuthError> {
        Ok(accounts::by_username(&self.pool, username)
            .await?
            .map(|row| row.id))
    }

    /// Look up an account's base class (for admin rank checks against offline
    /// targets). `None` if the account doesn't exist.
    pub async fn account_class(&self, username: &str) -> Result<Option<BaseClass>, AuthError> {
        let Some(row) = accounts::by_username(&self.pool, username).await? else {
            return Ok(None);
        };
        Ok(BaseClass::try_from(row.base_class as u8).ok())
    }

    /// Provision a new account from a local plaintext `password` (the
    /// `kdxd useradd` CLI): its SCRAM credential is derived here, on a
    /// blocking thread, and only that is stored. Over the wire, accounts are
    /// created with a client-derived credential instead
    /// ([`AuthManager::create_account_with_credential`]).
    pub async fn create_account(
        &self,
        username: &str,
        password: &str,
        base_class: i64,
        granted: i64,
        revoked: i64,
    ) -> Result<(), AuthError> {
        if username.is_empty() || username.len() > crate::limits::MAX_USERNAME_LEN {
            return Err(AuthError::InvalidUsername);
        }
        let password = password.to_owned();
        let credential = tokio::task::spawn_blocking(move || StoredCredential::derive(&password))
            .await
            .map_err(|_| AuthError::Internal("credential derivation task failed"))??;
        self.create_account_with_credential(username, &credential, base_class, granted, revoked)
            .await
    }

    /// Provision a new account with `credential` (derived by the creating
    /// client from the initial password, which the server never sees; it
    /// must pass `check_acceptable`). The account and its
    /// `granted`/`revoked` privilege overrides are written in one INSERT; a
    /// taken name (including a concurrent create) is
    /// [`AuthError::AccountExists`].
    pub async fn create_account_with_credential(
        &self,
        username: &str,
        credential: &StoredCredential,
        base_class: i64,
        granted: i64,
        revoked: i64,
    ) -> Result<(), AuthError> {
        if username.is_empty() || username.len() > crate::limits::MAX_USERNAME_LEN {
            return Err(AuthError::InvalidUsername);
        }
        credential.check_acceptable()?;
        match accounts::create(
            &self.pool,
            username,
            &credential.encode(),
            base_class,
            granted,
            revoked,
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(e) if is_unique_violation(&e) => Err(AuthError::AccountExists),
            Err(e) => Err(e.into()),
        }
    }

    /// Change an existing account's class and privilege overrides (not its
    /// password).
    pub async fn update_account(
        &self,
        username: &str,
        base_class: i64,
        granted: i64,
        revoked: i64,
    ) -> Result<(), AuthError> {
        accounts::update(&self.pool, username, base_class, granted, revoked).await?;
        Ok(())
    }

    /// Every account, for the Accounts window: `(username, base_class,
    /// granted, revoked)`. No password material is returned.
    pub async fn list_accounts(&self) -> Result<Vec<(String, u8, u32, u32)>, AuthError> {
        let rows = accounts::all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.username,
                    r.base_class as u8,
                    r.granted as u32,
                    r.revoked as u32,
                )
            })
            .collect())
    }

    /// Record (or replace) an expiring ban on an account. `until` is a
    /// unix-seconds expiry. Live sessions are dropped separately (via the
    /// presence kick); this only governs future logins.
    pub async fn set_ban(
        &self,
        account_id: &str,
        until: i64,
        reason: &str,
        banned_by: &str,
    ) -> Result<(), AuthError> {
        kdx_storage::bans::set(&self.pool, account_id, until, reason, banned_by).await?;
        Ok(())
    }

    /// Look up a registered session. `None` once its connection has logged
    /// out; callers treat that as "reauthentication required".
    pub fn validate(&self, session_id: Uuid) -> Option<Session> {
        self.sessions.get(&session_id).map(|entry| entry.clone())
    }

    pub fn end_session(&self, session_id: Uuid) {
        self.sessions.remove(&session_id);
    }

    /// The configured idle session lifetime (`session_ttl_secs`).
    pub fn session_ttl(&self) -> Duration {
        self.session_ttl
    }
}

/// Whether `row` still holds `credential` (it doesn't once a password change
/// or reset replaced it). A not-yet-converted legacy row is compared by its
/// conversion, which runs no KDF.
fn holds_credential(row: &AccountRow, credential: &StoredCredential) -> bool {
    match &row.credential {
        Some(encoded) => StoredCredential::decode(encoded).is_ok_and(|c| c == *credential),
        None => StoredCredential::from_legacy_phc(&row.password_phc).is_ok_and(|c| c == *credential),
    }
}

/// A UNIQUE-constraint violation from the database (a taken username).
fn is_unique_violation(err: &StorageError) -> bool {
    match err {
        StorageError::AlreadyExists => true,
        StorageError::Sqlx(e) => e
            .as_database_error()
            .is_some_and(|d| d.is_unique_violation()),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdx_crypto::{client_proof, hash_password, AuthContext, ClientProof};

    /// Channel binding used by these tests (no TLS here).
    const BINDING: [u8; 32] = [0x42; 32];

    /// A protocol-v1 row for password "legacy pass" (Argon2id defaults,
    /// 16-byte salt), as the old server stored it.
    const LEGACY_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$a2R4bGVnYWN5c2FsdDE2IQ$1MaVnJW11DoDj6dBG8Pyjl8ME3i+BpQLmf5+5xVimQU";

    async fn test_pool() -> (SqlitePool, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = kdx_storage::connect(&dir.path().join("test.db"))
            .await
            .unwrap();
        (pool, dir)
    }

    async fn seed(pool: &SqlitePool, username: &str, password: &str, class: i64) {
        let credential = hash_password(password).unwrap();
        accounts::create(pool, username, &credential, class, 0, 0)
            .await
            .unwrap();
    }

    fn prove(username: &str, data: &ChallengeData, password: &str) -> ClientProof {
        client_proof(
            password,
            &AuthContext {
                username,
                challenge: &data.challenge,
                salt: &data.salt,
                params: data.params,
                channel_binding: &BINDING,
            },
        )
        .unwrap()
    }

    async fn login(
        mgr: &AuthManager,
        username: &str,
        password: &str,
    ) -> Result<Verified, AuthError> {
        let (data, pending) = mgr.begin(username, BINDING).await.unwrap();
        let proof = prove(username, &data, password);
        let verified = mgr.complete(pending, &proof.proof).await?;
        assert!(proof.verify_server_signature(&verified.server_signature));
        Ok(verified)
    }

    #[tokio::test]
    async fn full_login_flow() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "phraq", "s3cret", 2).await;
        let mgr = AuthManager::new(pool, Duration::from_secs(60));

        let session = login(&mgr, "phraq", "s3cret").await.unwrap().session;
        assert_eq!(session.class, BaseClass::PowerUser);
        assert!(session.privileges.contains(Privileges::CHAT_CREATE_ROOM));

        // Verified but not yet registered until the connection activates it.
        assert!(mgr.validate(session.id).is_none());
        mgr.activate(&session).keep();
        assert!(mgr.validate(session.id).is_some());
        assert_eq!(mgr.live_session_count(), 1);
    }

    #[tokio::test]
    async fn dropped_session_guard_unregisters() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "phraq", "s3cret", 1).await;
        let mgr = AuthManager::new(pool, Duration::from_secs(60));

        let session = login(&mgr, "phraq", "s3cret").await.unwrap().session;
        {
            let _guard = mgr.activate(&session);
            assert!(mgr.validate(session.id).is_some());
            // e.g. the AuthResult send failed and authenticate() returned.
        }
        assert!(mgr.validate(session.id).is_none());
        assert_eq!(mgr.live_session_count(), 0);
    }

    #[tokio::test]
    async fn wrong_password_rejected() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "phraq", "s3cret", 1).await;
        let mgr = AuthManager::new(pool, Duration::from_secs(60));

        let result = login(&mgr, "phraq", "wrong").await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn proof_for_another_channel_is_rejected() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "phraq", "s3cret", 1).await;
        let mgr = AuthManager::new(pool, Duration::from_secs(60));

        // The challenge was issued on a connection whose binding is BINDING,
        // but the proof was computed for a different TLS session (a relay).
        let (data, pending) = mgr.begin("phraq", BINDING).await.unwrap();
        let relayed = client_proof(
            "s3cret",
            &AuthContext {
                username: "phraq",
                challenge: &data.challenge,
                salt: &data.salt,
                params: data.params,
                channel_binding: &[0x13; 32],
            },
        )
        .unwrap();
        let result = mgr.complete(pending, &relayed.proof).await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn unknown_user_gets_indistinguishable_challenge() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "phraq", "s3cret", 1).await;
        let mgr = AuthManager::new(pool, Duration::from_secs(60));

        let (real, _) = mgr.begin("phraq", BINDING).await.unwrap();
        let (data, pending) = mgr.begin("nobody", BINDING).await.unwrap();
        assert_eq!(data.salt.len(), real.salt.len());
        assert_eq!(data.params, real.params);
        assert_eq!(data.params, KdfParams::DEFAULT);
        let proof = prove("nobody", &data, "anything");
        let result = mgr.complete(pending, &proof.proof).await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn decoy_salt_is_not_predictable_but_is_stable() {
        use sha2::{Digest, Sha256};
        let (pool, _dir) = test_pool().await;
        let mgr = AuthManager::new(pool.clone(), Duration::from_secs(60));

        let (first, _) = mgr.begin("nobody", BINDING).await.unwrap();
        // Protocol v1 used SHA-256(username)[..16]: anyone could compute it
        // and tell "no such account" from a real (random) salt.
        assert_ne!(first.salt[..], Sha256::digest(b"nobody")[..16]);
        // Stable across retries, and across restarts (the key is persisted).
        let (again, _) = mgr.begin("nobody", BINDING).await.unwrap();
        assert_eq!(first.salt, again.salt);
        let restarted = AuthManager::new(pool, Duration::from_secs(60));
        let (after_restart, _) = restarted.begin("nobody", BINDING).await.unwrap();
        assert_eq!(first.salt, after_restart.salt);

        // A different server (different secret) gives a different salt.
        let (other_pool, _other_dir) = test_pool().await;
        let other = AuthManager::new(other_pool, Duration::from_secs(60));
        let (elsewhere, _) = other.begin("nobody", BINDING).await.unwrap();
        assert_ne!(first.salt, elsewhere.salt);
    }

    #[tokio::test]
    async fn legacy_rows_are_converted_and_still_log_in() {
        let (pool, _dir) = test_pool().await;
        accounts::create_legacy(&pool, "oldtimer", LEGACY_PHC, 1)
            .await
            .unwrap();
        let mgr = AuthManager::new(pool.clone(), Duration::from_secs(60));
        mgr.prepare().await.unwrap();

        // The password-equivalent PHC string is gone; a credential replaced it.
        let row = accounts::by_username(&pool, "oldtimer")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.password_phc, "");
        let credential = StoredCredential::decode(row.credential.as_deref().unwrap()).unwrap();
        assert!(credential.matches_password("legacy pass").unwrap());

        // And the user logs in with the unchanged password.
        let session = login(&mgr, "oldtimer", "legacy pass")
            .await
            .unwrap()
            .session;
        assert_eq!(session.username, "oldtimer");
        assert!(matches!(
            login(&mgr, "oldtimer", "wrong").await,
            Err(AuthError::InvalidCredentials)
        ));
    }

    #[tokio::test]
    async fn create_account_writes_overrides_and_maps_duplicates() {
        let (pool, _dir) = test_pool().await;
        let mgr = AuthManager::new(pool.clone(), Duration::from_secs(60));
        mgr.create_account("muted", "pw", 1, 0, Privileges::CHAT_SEND.bits() as i64)
            .await
            .unwrap();
        // A client-derived credential must be acceptable.
        let mut weak = StoredCredential::derive("pw").unwrap();
        weak.salt.truncate(8);
        assert!(matches!(
            mgr.create_account_with_credential("weak", &weak, 1, 0, 0).await,
            Err(AuthError::Crypto(_))
        ));
        assert!(accounts::by_username(&pool, "weak").await.unwrap().is_none());
        let row = accounts::by_username(&pool, "muted")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.revoked, Privileges::CHAT_SEND.bits() as i64);
        assert_eq!(row.password_phc, "");
        assert!(row.credential.is_some());

        let dup = mgr.create_account("muted", "other", 3, 0, 0).await;
        assert!(matches!(dup, Err(AuthError::AccountExists)), "{dup:?}");

        let long = "x".repeat(crate::limits::MAX_USERNAME_LEN + 1);
        assert!(matches!(
            mgr.create_account(&long, "pw", 1, 0, 0).await,
            Err(AuthError::InvalidUsername)
        ));

        // The created account logs in with its overrides applied.
        let session = login(&mgr, "muted", "pw").await.unwrap().session;
        assert!(!session.privileges.contains(Privileges::CHAT_SEND));
    }

    fn change_proof(
        username: &str,
        data: &ChallengeData,
        current: &str,
        new: &StoredCredential,
    ) -> ClientProof {
        kdx_crypto::password_change_proof(
            current,
            &kdx_crypto::PasswordChangeContext {
                current: AuthContext {
                    username,
                    challenge: &data.challenge,
                    salt: &data.salt,
                    params: data.params,
                    channel_binding: &BINDING,
                },
                new_credential: new,
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn password_change_replaces_the_credential() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "phraq", "s3cret", 1).await;
        let mgr = AuthManager::new(pool, Duration::from_secs(60));
        let session = login(&mgr, "phraq", "s3cret").await.unwrap().session;

        let new = StoredCredential::derive("n3w pass").unwrap();
        let (data, pending) = mgr.begin_password_change(&session, BINDING).await.unwrap();
        assert!(!pending.expired());
        let proof = change_proof("phraq", &data, "s3cret", &new);
        let signature = mgr
            .complete_password_change(pending, &proof.proof, &new)
            .await
            .unwrap();
        assert!(proof.verify_server_signature(&signature));

        assert!(matches!(
            login(&mgr, "phraq", "s3cret").await,
            Err(AuthError::InvalidCredentials)
        ));
        assert!(login(&mgr, "phraq", "n3w pass").await.is_ok());
    }

    #[tokio::test]
    async fn password_change_challenges_expire() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "phraq", "s3cret", 1).await;
        let mgr = AuthManager::new(pool, Duration::from_secs(60));
        let session = login(&mgr, "phraq", "s3cret").await.unwrap().session;
        let (_, pending) = mgr.begin_password_change(&session, BINDING).await.unwrap();
        assert_eq!(pending.username(), "phraq");
        // Pure in-memory from here on (sqlx misbehaves under a paused clock).
        tokio::time::pause();
        tokio::time::advance(PASSWORD_CHANGE_TIMEOUT - Duration::from_secs(1)).await;
        assert!(!pending.expired());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(pending.expired());
    }

    #[tokio::test]
    async fn password_change_refusals() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "phraq", "s3cret", 1).await;
        let mgr = AuthManager::new(pool, Duration::from_secs(60));
        let session = login(&mgr, "phraq", "s3cret").await.unwrap().session;
        let new = StoredCredential::derive("n3w pass").unwrap();

        // Wrong current password.
        let (data, pending) = mgr.begin_password_change(&session, BINDING).await.unwrap();
        let proof = change_proof("phraq", &data, "guess", &new);
        assert!(matches!(
            mgr.complete_password_change(pending, &proof.proof, &new).await,
            Err(AuthError::InvalidCredentials)
        ));

        // A login proof for the same challenge is not a change proof.
        let (data, pending) = mgr.begin_password_change(&session, BINDING).await.unwrap();
        let login_proof = prove("phraq", &data, "s3cret");
        assert!(matches!(
            mgr.complete_password_change(pending, &login_proof.proof, &new).await,
            Err(AuthError::InvalidCredentials)
        ));

        // An unacceptable new credential is refused before the proof.
        let mut weak = new.clone();
        weak.params.m_cost = 8;
        let (_, pending) = mgr.begin_password_change(&session, BINDING).await.unwrap();
        assert!(matches!(
            mgr.complete_password_change(pending, &[0u8; 32], &weak).await,
            Err(AuthError::Crypto(_))
        ));

        // Replaced meanwhile (an admin reset): the proof is right, but the
        // change no longer applies.
        let (data, pending) = mgr.begin_password_change(&session, BINDING).await.unwrap();
        let proof = change_proof("phraq", &data, "s3cret", &new);
        let reset = StoredCredential::derive("admin set").unwrap();
        assert!(mgr.set_credential(&session.account_id, &reset).await.unwrap());
        assert!(matches!(
            mgr.complete_password_change(pending, &proof.proof, &new).await,
            Err(AuthError::CredentialChanged)
        ));
        assert!(login(&mgr, "phraq", "admin set").await.is_ok());

        // Nothing changed by any of the refusals above but the reset.
        assert!(matches!(
            login(&mgr, "phraq", "n3w pass").await,
            Err(AuthError::InvalidCredentials)
        ));
    }

    #[tokio::test]
    async fn a_login_in_flight_fails_once_its_credential_is_replaced() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "phraq", "s3cret", 1).await;
        let mgr = AuthManager::new(pool, Duration::from_secs(60));
        let session = login(&mgr, "phraq", "s3cret").await.unwrap().session;
        let id = session.account_id.clone();

        // Challenge issued for the old credential, proof made with the old
        // password, password reset in between: refused.
        let (data, pending) = mgr.begin("phraq", BINDING).await.unwrap();
        let proof = prove("phraq", &data, "s3cret");
        let stamp_before = mgr.credential_stamp("phraq", &id).await.unwrap().unwrap();
        let reset = StoredCredential::derive("fresh").unwrap();
        mgr.set_credential(&id, &reset).await.unwrap();
        assert!(matches!(
            mgr.complete(pending, &proof.proof).await,
            Err(AuthError::InvalidCredentials)
        ));

        // The stamp tells a completed-but-not-yet-live login it went stale.
        let fresh = login(&mgr, "phraq", "fresh").await.unwrap();
        let stamp_now = mgr.credential_stamp("phraq", &id).await.unwrap().unwrap();
        assert_ne!(stamp_before, stamp_now);
        assert_eq!(fresh.credential_stamp, stamp_now);
        assert!(mgr.credential_stamp("phraq", "other-id").await.unwrap().is_none());
        assert!(mgr.credential_stamp("nobody", &id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn privilege_overrides_apply() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "phraq", "s3cret", 1).await;
        accounts::set_overrides(
            &pool,
            "phraq",
            Privileges::CHAT_SET_TOPIC.bits() as i64,
            Privileges::FILE_UPLOAD.bits() as i64,
        )
        .await
        .unwrap();
        let mgr = AuthManager::new(pool, Duration::from_secs(60));

        let session = login(&mgr, "phraq", "s3cret").await.unwrap().session;
        assert!(session.privileges.contains(Privileges::CHAT_SET_TOPIC)); // granted beyond class
        assert!(!session.privileges.contains(Privileges::FILE_UPLOAD)); // revoked from class
    }

    #[tokio::test]
    async fn active_ban_refuses_login_despite_correct_password() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "lamer", "s3cret", 1).await;
        let account_id = accounts::by_username(&pool, "lamer").await.unwrap().unwrap().id;
        // Ban far into the future relative to the wall clock.
        let until = crate::presence::unix_now() as i64 + 10_000;
        kdx_storage::bans::set(&pool, &account_id, until, "spamming", "admin")
            .await
            .unwrap();
        let mgr = AuthManager::new(pool, Duration::from_secs(60));

        let result = login(&mgr, "lamer", "s3cret").await;
        match result {
            Err(AuthError::Banned { reason, .. }) => assert_eq!(reason, "spamming"),
            other => panic!("expected Banned, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn lapsed_ban_permits_login() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "reformed", "s3cret", 1).await;
        let account_id = accounts::by_username(&pool, "reformed")
            .await
            .unwrap()
            .unwrap()
            .id;
        // A ban that already expired (until in the past) must not block login.
        kdx_storage::bans::set(&pool, &account_id, 1, "old news", "admin")
            .await
            .unwrap();
        let mgr = AuthManager::new(pool, Duration::from_secs(60));

        assert!(login(&mgr, "reformed", "s3cret").await.is_ok());
    }

    #[tokio::test]
    async fn huge_session_ttl_does_not_panic() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "phraq", "s3cret", 1).await;
        let mgr = AuthManager::new(pool, Duration::from_secs(i64::MAX as u64));
        assert!(login(&mgr, "phraq", "s3cret").await.is_ok());
    }

    #[tokio::test]
    async fn live_sessions_do_not_expire_by_age() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "phraq", "s3cret", 1).await;
        let mgr = AuthManager::new(pool, Duration::from_secs(30));

        let session = login(&mgr, "phraq", "s3cret").await.unwrap().session;
        mgr.activate(&session).keep();
        assert!(mgr.validate(session.id).is_some());

        // Pause the clock only now — sqlx's pool timeouts misbehave under a
        // paused clock, but everything past this point is pure in-memory.
        // The connection enforces `session_ttl` as an idle timeout; the
        // registration itself lives exactly as long as the connection, so
        // `max_users` keeps counting it.
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(31)).await;
        assert!(mgr.validate(session.id).is_some());
        assert_eq!(mgr.live_session_count(), 1);
        // Logging out is what ends it.
        mgr.end_session(session.id);
        assert!(mgr.validate(session.id).is_none());
    }

    #[tokio::test]
    async fn admission_is_capped_and_freed_by_logouts() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "phraq", "s3cret", 1).await;
        let mgr = AuthManager::new(pool, Duration::from_secs(60));
        let first = login(&mgr, "phraq", "s3cret").await.unwrap().session;
        let second = login(&mgr, "phraq", "s3cret").await.unwrap().session;

        let held = mgr.admit(&first, Some(1)).expect("room for one");
        assert!(mgr.admit(&second, Some(1)).is_none(), "the cap is full");
        assert!(
            mgr.validate(second.id).is_none(),
            "a refused session is not registered"
        );
        // No cap (e.g. an admin) still gets in.
        mgr.admit(&second, None).expect("uncapped").keep();
        assert_eq!(mgr.live_session_count(), 2);

        // Dropping the guard (the login never completed) frees the slot.
        drop(held);
        assert_eq!(mgr.live_session_count(), 1);
        assert!(mgr.admit(&first, Some(2)).is_some());
    }

    #[tokio::test]
    async fn changes_while_a_login_is_pending_apply_to_it() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "deputy", "s3cret", 3).await;
        let mgr = AuthManager::new(pool.clone(), Duration::from_secs(60));

        // Demoted (and a privilege revoked) between challenge and proof.
        let (data, pending) = mgr.begin("deputy", BINDING).await.unwrap();
        let proof = prove("deputy", &data, "s3cret");
        mgr.update_account("deputy", 1, 0, Privileges::CHAT_SEND.bits() as i64)
            .await
            .unwrap();
        let session = mgr.complete(pending, &proof.proof).await.unwrap().session;
        assert_eq!(session.class, BaseClass::User);
        assert!(!session.privileges.contains(Privileges::CHAT_SEND));
        assert!(!session.privileges.contains(Privileges::SERVER_ADMIN));

        // Banned between challenge and proof.
        let (data, pending) = mgr.begin("deputy", BINDING).await.unwrap();
        let proof = prove("deputy", &data, "s3cret");
        let id = mgr.account_id("deputy").await.unwrap().unwrap();
        let until = crate::presence::unix_now() as i64 + 1000;
        mgr.set_ban(&id, until, "spam", "sysop").await.unwrap();
        assert!(matches!(
            mgr.complete(pending, &proof.proof).await,
            Err(AuthError::Banned { .. })
        ));
        assert_eq!(mgr.active_ban(&id).await.unwrap().unwrap().1, "spam");
    }
}
