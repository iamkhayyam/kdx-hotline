use sqlx::SqlitePool;
use uuid::Uuid;

use crate::StorageError;

/// One row of the `accounts` table. Privilege semantics (what the bits mean,
/// how base class and overrides combine) live in kdx-server-core; storage
/// only persists the raw values.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AccountRow {
    pub id: String,
    pub username: String,
    pub password_phc: String,
    pub base_class: i64,
    pub granted: i64,
    pub revoked: i64,
}

pub async fn create(
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
        base_class,
        granted: 0,
        revoked: 0,
    })
}

pub async fn by_username(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<AccountRow>, StorageError> {
    let row = sqlx::query_as::<_, AccountRow>(
        "SELECT id, username, password_phc, base_class, granted, revoked
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
