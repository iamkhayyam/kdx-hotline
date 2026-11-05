use std::fmt;

use sqlx::SqlitePool;
use uuid::Uuid;

use crate::StorageError;

/// One row of the `accounts` table. Privilege semantics (what the bits mean,
/// how base class and overrides combine) live in kdx-server-core, and
/// credential semantics in kdx-crypto; storage only persists the raw values.
#[derive(Clone, sqlx::FromRow)]
pub struct AccountRow {
    pub id: String,
    pub username: String,
    /// Legacy (protocol v1) Argon2id PHC string. Password-equivalent, so the
    /// server converts it to `credential` at startup and then sets this to
    /// `''`; new rows never carry one.
    pub password_phc: String,
    /// Encoded SCRAM credential (`kdx_crypto::StoredCredential::encode`).
    /// `None` only on a legacy row that hasn't been converted yet.
    pub credential: Option<String>,
    pub base_class: i64,
    pub granted: i64,
    pub revoked: i64,
}

impl fmt::Debug for AccountRow {
    // Credential material stays out of logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountRow")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("base_class", &self.base_class)
            .field("granted", &self.granted)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

/// Create an account with its credential and privilege overrides in a single
/// INSERT, so a failure can never leave a live account missing its
/// revocations. `credential` is an encoded SCRAM credential (see
/// `kdx_crypto::hash_password`). A duplicate username fails with the
/// database's UNIQUE violation (`StorageError::Sqlx`).
pub async fn create(
    pool: &SqlitePool,
    username: &str,
    credential: &str,
    base_class: i64,
    granted: i64,
    revoked: i64,
) -> Result<AccountRow, StorageError> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO accounts (id, username, password_phc, credential, base_class, granted, revoked)
         VALUES (?, ?, '', ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(username)
    .bind(credential)
    .bind(base_class)
    .bind(granted)
    .bind(revoked)
    .execute(pool)
    .await?;
    Ok(AccountRow {
        id,
        username: username.to_owned(),
        password_phc: String::new(),
        credential: Some(credential.to_owned()),
        base_class,
        granted,
        revoked,
    })
}

pub async fn by_username(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<AccountRow>, StorageError> {
    let row = sqlx::query_as::<_, AccountRow>(
        "SELECT id, username, password_phc, credential, base_class, granted, revoked
         FROM accounts WHERE username = ?",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Set privilege override bits for an account.
pub async fn set_overrides(
    pool: &SqlitePool,
    username: &str,
    granted: i64,
    revoked: i64,
) -> Result<(), StorageError> {
    let result = sqlx::query("UPDATE accounts SET granted = ?, revoked = ? WHERE username = ?")
        .bind(granted)
        .bind(revoked)
        .bind(username)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(StorageError::NotFound);
    }
    Ok(())
}

/// Set base class and privilege overrides in one shot (the Accounts editor).
pub async fn update(
    pool: &SqlitePool,
    username: &str,
    base_class: i64,
    granted: i64,
    revoked: i64,
) -> Result<(), StorageError> {
    let result = sqlx::query(
        "UPDATE accounts SET base_class = ?, granted = ?, revoked = ? WHERE username = ?",
    )
    .bind(base_class)
    .bind(granted)
    .bind(revoked)
    .bind(username)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(StorageError::NotFound);
    }
    Ok(())
}

/// Every account (username, class, overrides), for the Accounts window.
/// Callers must not forward the credential columns.
pub async fn all(pool: &SqlitePool) -> Result<Vec<AccountRow>, StorageError> {
    let rows = sqlx::query_as::<_, AccountRow>(
        "SELECT id, username, password_phc, credential, base_class, granted, revoked
         FROM accounts ORDER BY base_class DESC, username",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Insert a row the way protocol v1 did: a PHC string and no credential.
/// Only for tests of the legacy conversion path; never use for new accounts.
#[doc(hidden)]
pub async fn create_legacy(
    pool: &SqlitePool,
    username: &str,
    password_phc: &str,
    base_class: i64,
) -> Result<AccountRow, StorageError> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO accounts (id, username, password_phc, base_class) VALUES (?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(username)
    .bind(password_phc)
    .bind(base_class)
    .execute(pool)
    .await?;
    Ok(AccountRow {
        id,
        username: username.to_owned(),
        password_phc: password_phc.to_owned(),
        credential: None,
        base_class,
        granted: 0,
        revoked: 0,
    })
}

/// Accounts still holding only a legacy (protocol v1) PHC string.
pub async fn legacy_rows(pool: &SqlitePool) -> Result<Vec<AccountRow>, StorageError> {
    let rows = sqlx::query_as::<_, AccountRow>(
        "SELECT id, username, password_phc, credential, base_class, granted, revoked
         FROM accounts WHERE credential IS NULL",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Store a converted credential for a legacy row and wipe its PHC string in
/// the same statement. Returns `false` if the row is gone or was already
/// converted (a concurrent conversion won).
pub async fn upgrade_credential(
    pool: &SqlitePool,
    id: &str,
    credential: &str,
) -> Result<bool, StorageError> {
    let result = sqlx::query(
        "UPDATE accounts SET credential = ?, password_phc = '' WHERE id = ? AND credential IS NULL",
    )
    .bind(credential)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Rewrite the database file and truncate the WAL, so overwritten values
/// (wiped legacy password hashes) don't linger in free pages or old WAL
/// frames. Run once after converting legacy rows; not cheap on a big DB.
pub async fn compact(pool: &SqlitePool) -> Result<(), StorageError> {
    sqlx::query("VACUUM").execute(pool).await?;
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(pool)
        .await?;
    Ok(())
}

/// The per-server secret called `name`: `candidate` is stored on first use
/// and the stored value is returned from then on (also when two callers race).
pub async fn server_secret(
    pool: &SqlitePool,
    name: &str,
    candidate: &[u8],
) -> Result<Vec<u8>, StorageError> {
    sqlx::query("INSERT OR IGNORE INTO server_secrets (name, value) VALUES (?, ?)")
        .bind(name)
        .bind(candidate)
        .execute(pool)
        .await?;
    let value: Vec<u8> = sqlx::query_scalar("SELECT value FROM server_secrets WHERE name = ?")
        .bind(name)
        .fetch_one(pool)
        .await?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> (SqlitePool, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::connect(&dir.path().join("test.db")).await.unwrap();
        (pool, dir)
    }

    #[tokio::test]
    async fn create_writes_overrides_in_the_same_row() {
        let (pool, _dir) = pool().await;
        let created = create(&pool, "muted", "$cred", 1, 0b0100, 0b0011)
            .await
            .unwrap();
        let row = by_username(&pool, "muted").await.unwrap().unwrap();
        assert_eq!(row.id, created.id);
        assert_eq!(row.credential.as_deref(), Some("$cred"));
        assert_eq!(row.password_phc, "");
        assert_eq!(
            (row.base_class, row.granted, row.revoked),
            (1, 0b0100, 0b0011)
        );
    }

    #[tokio::test]
    async fn duplicate_username_is_a_unique_violation() {
        let (pool, _dir) = pool().await;
        create(&pool, "phraq", "$a", 1, 0, 0).await.unwrap();
        let err = create(&pool, "phraq", "$b", 3, 0, 0).await.unwrap_err();
        let unique = match &err {
            StorageError::Sqlx(e) => e
                .as_database_error()
                .is_some_and(|d| d.is_unique_violation()),
            _ => false,
        };
        assert!(unique, "unexpected error: {err:?}");
        // The original row is untouched.
        let row = by_username(&pool, "phraq").await.unwrap().unwrap();
        assert_eq!(row.credential.as_deref(), Some("$a"));
    }

    #[tokio::test]
    async fn legacy_rows_upgrade_and_wipe_the_phc() {
        let (pool, _dir) = pool().await;
        // A row as protocol v1 wrote it: PHC only.
        let old = create_legacy(
            &pool,
            "oldtimer",
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaA",
            1,
        )
        .await
        .unwrap();
        create(&pool, "newcomer", "$cred", 1, 0, 0).await.unwrap();

        let legacy = legacy_rows(&pool).await.unwrap();
        assert_eq!(legacy.len(), 1);
        assert_eq!(legacy[0].username, "oldtimer");

        assert!(upgrade_credential(&pool, &old.id, "$converted")
            .await
            .unwrap());
        // Already converted: a second (racing) conversion is a no-op.
        assert!(!upgrade_credential(&pool, &old.id, "$other").await.unwrap());
        compact(&pool).await.unwrap();

        let row = by_username(&pool, "oldtimer").await.unwrap().unwrap();
        assert_eq!(row.password_phc, "");
        assert_eq!(row.credential.as_deref(), Some("$converted"));
        assert!(legacy_rows(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn server_secret_is_generated_once() {
        let (pool, _dir) = pool().await;
        let first = server_secret(&pool, "decoy", &[1u8; 32]).await.unwrap();
        assert_eq!(first, vec![1u8; 32]);
        let second = server_secret(&pool, "decoy", &[2u8; 32]).await.unwrap();
        assert_eq!(second, first);
    }

    #[test]
    fn debug_omits_credentials() {
        let row = AccountRow {
            id: "x".into(),
            username: "phraq".into(),
            password_phc: "$argon2id$secret".into(),
            credential: Some("$kdx-scram-sha256$secret".into()),
            base_class: 1,
            granted: 0,
            revoked: 0,
        };
        let shown = format!("{row:?}");
        assert!(shown.contains("phraq"));
        assert!(!shown.contains("secret"));
    }
}
