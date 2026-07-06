//! Challenge-response authentication and the in-memory session table.

use std::time::Duration;

use dashmap::DashMap;
use kdx_crypto::KdfParams;
use kdx_storage::accounts::{self, AccountRow};
use kdx_storage::SqlitePool;
use tokio::time::Instant;
use tracing::debug;
use uuid::Uuid;

use super::classes::{effective_privileges, BaseClass, Privileges};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("storage error: {0}")]
    Storage(#[from] kdx_storage::StorageError),
    #[error("crypto error: {0}")]
    Crypto(#[from] kdx_crypto::CryptoError),
}

/// An authenticated session.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: Uuid,
    pub account_id: String,
    pub username: String,
    pub class: BaseClass,
    pub privileges: Privileges,
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
/// connection task between challenge and response.
#[derive(Debug)]
pub struct PendingAuth {
    challenge: [u8; 32],
    /// `None` when the username didn't exist — we still issued a decoy
    /// challenge so the wire looks identical (anti-enumeration), and the
    /// response check will simply fail.
    account: Option<AccountRow>,
}

pub struct AuthManager {
    pool: SqlitePool,
    sessions: DashMap<Uuid, Session>,
    session_ttl: Duration,
}

impl AuthManager {
    pub fn new(pool: SqlitePool, session_ttl: Duration) -> Self {
        Self {
            pool,
            sessions: DashMap::new(),
            session_ttl,
        }
    }

    /// Start a login: look up the account and issue a challenge. Unknown
    /// usernames get a decoy challenge with plausible salt/params so the
    /// response from the wire can't distinguish "no such user" from "wrong
    /// password".
    pub async fn begin(&self, username: &str) -> Result<(ChallengeData, PendingAuth), AuthError> {
        let challenge = kdx_crypto::generate_challenge();
        let account = accounts::by_username(&self.pool, username).await?;

        let (salt, params) = match &account {
            Some(row) => kdx_crypto::extract_kdf(&row.password_phc)?,
            None => {
                // Deterministic decoy salt per username, so retries don't
                // reveal freshness either.
                use sha2::{Digest, Sha256};
                let digest = Sha256::digest(username.as_bytes());
                (
                    digest[..16].to_vec(),
                    KdfParams {
                        m_cost: 19456,
                        t_cost: 2,
                        p_cost: 1,
                    },
                )
            }
        };

        Ok((
            ChallengeData {
                challenge,
                salt,
                params,
            },
            PendingAuth { challenge, account },
        ))
    }

    /// Verify the client's response and mint a session.
    pub async fn complete(&self, pending: PendingAuth, response: &[u8; 32]) -> Result<Session, AuthError> {
        let Some(account) = pending.account else {
            return Err(AuthError::InvalidCredentials);
        };
        let expected = kdx_crypto::expected_response(&account.password_phc, &pending.challenge)?;
        if !kdx_crypto::verify_response(&expected, response) {
            return Err(AuthError::InvalidCredentials);
        }

        let class = BaseClass::try_from(account.base_class as u8)
            .map_err(|_| AuthError::InvalidCredentials)?;
        let roles = kdx_storage::roles::for_account(&self.pool, &account.id).await?;
        let role_privileges = roles
            .iter()
            .fold(Privileges::empty(), |acc, r| acc | Privileges::from_bits_truncate(r.privileges as u32));
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
            expires_at: Instant::now() + self.session_ttl,
        };
        self.sessions.insert(session.id, session.clone());
        debug!(user = %session.username, class = ?class, "session created");
        Ok(session)
    }

    /// Resolve a username to its account id, for admin operations (e.g. role
    /// assignment) that address accounts by username over the wire.
    pub async fn account_id(&self, username: &str) -> Result<Option<String>, AuthError> {
        Ok(accounts::by_username(&self.pool, username)
            .await?
            .map(|row| row.id))
    }

    /// Look up a live session, evicting it if expired. Callers treat `None`
    /// as "reauthentication required".
    pub fn validate(&self, session_id: Uuid) -> Option<Session> {
        let entry = self.sessions.get(&session_id)?;
        if entry.expires_at <= Instant::now() {
            drop(entry);
            self.sessions.remove(&session_id);
            return None;
        }
        Some(entry.clone())
    }

    pub fn end_session(&self, session_id: Uuid) {
        self.sessions.remove(&session_id);
    }

    /// Drop all expired sessions. Run periodically from a sweep task.
    pub fn sweep(&self) {
        let now = Instant::now();
        self.sessions.retain(|_, s| s.expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdx_crypto::{client_response, hash_password};

    async fn test_pool() -> (SqlitePool, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = kdx_storage::connect(&dir.path().join("test.db"))
            .await
            .unwrap();
        (pool, dir)
    }

    async fn seed(pool: &SqlitePool, username: &str, password: &str, class: i64) {
        let phc = hash_password(password).unwrap();
        accounts::create(pool, username, &phc, class).await.unwrap();
    }

    fn answer(data: &ChallengeData, password: &str) -> [u8; 32] {
        client_response(password, &data.salt, &data.params, &data.challenge).unwrap()
    }

    #[tokio::test]
    async fn full_login_flow() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "phraq", "s3cret", 2).await;
        let mgr = AuthManager::new(pool, Duration::from_secs(60));

        let (data, pending) = mgr.begin("phraq").await.unwrap();
        let session = mgr.complete(pending, &answer(&data, "s3cret")).await.unwrap();

        assert_eq!(session.class, BaseClass::PowerUser);
        assert!(session.privileges.contains(Privileges::CHAT_CREATE_ROOM));
        assert!(mgr.validate(session.id).is_some());
    }

    #[tokio::test]
    async fn wrong_password_rejected() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "phraq", "s3cret", 1).await;
        let mgr = AuthManager::new(pool, Duration::from_secs(60));

        let (data, pending) = mgr.begin("phraq").await.unwrap();
        let result = mgr.complete(pending, &answer(&data, "wrong")).await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn unknown_user_gets_indistinguishable_challenge() {
        let (pool, _dir) = test_pool().await;
        let mgr = AuthManager::new(pool, Duration::from_secs(60));

        let (data, pending) = mgr.begin("nobody").await.unwrap();
        assert_eq!(data.salt.len(), 16);
        let result = mgr.complete(pending, &answer(&data, "anything")).await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
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

        let (data, pending) = mgr.begin("phraq").await.unwrap();
        let session = mgr.complete(pending, &answer(&data, "s3cret")).await.unwrap();

        assert!(session.privileges.contains(Privileges::CHAT_SET_TOPIC)); // granted beyond class
        assert!(!session.privileges.contains(Privileges::FILE_UPLOAD)); // revoked from class
    }

    #[tokio::test]
    async fn session_expires_and_requires_reauth() {
        let (pool, _dir) = test_pool().await;
        seed(&pool, "phraq", "s3cret", 1).await;
        let mgr = AuthManager::new(pool, Duration::from_secs(30));

        let (data, pending) = mgr.begin("phraq").await.unwrap();
        let session = mgr.complete(pending, &answer(&data, "s3cret")).await.unwrap();
        assert!(mgr.validate(session.id).is_some());

        // Pause the clock only now — sqlx's pool timeouts misbehave under a
        // paused clock, but everything past this point is pure in-memory.
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(31)).await;
        assert!(mgr.validate(session.id).is_none());
        // Even after a sweep the id stays invalid.
        mgr.sweep();
        assert!(mgr.validate(session.id).is_none());
    }
}
