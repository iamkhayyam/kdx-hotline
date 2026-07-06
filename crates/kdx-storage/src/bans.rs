//! Expiring account bans. Semantics (who may ban whom, how a ban interacts
//! with a live session) live in kdx-server-core; storage only records the
//! expiry and reason and answers "is this account currently banned?".

use sqlx::SqlitePool;

use crate::StorageError;

/// An active ban, as read back for the login-refusal message.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct BanRow {
    pub account_id: String,
    /// Unix seconds; the ban is active while `now < until`.
    pub until: i64,
    pub reason: String,
    pub banned_by: String,
}

/// Record (or replace) a ban on an account. `until` is a unix-seconds expiry.
pub async fn set(
    pool: &SqlitePool,
    account_id: &str,
    until: i64,
    reason: &str,
    banned_by: &str,
) -> Result<(), StorageError> {
    sqlx::query(
        "INSERT INTO bans (account_id, until, reason, banned_by) VALUES (?, ?, ?, ?)
         ON CONFLICT(account_id) DO UPDATE SET
            until = excluded.until,
            reason = excluded.reason,
            banned_by = excluded.banned_by,
            created_at = datetime('now')",
    )
    .bind(account_id)
    .bind(until)
    .bind(reason)
    .bind(banned_by)
    .execute(pool)
    .await?;
    Ok(())
}

/// The active ban for an account, if any. `now` is unix seconds; a ban whose
/// `until <= now` has lapsed and is returned as `None` (and swept out).
pub async fn active(
    pool: &SqlitePool,
    account_id: &str,
    now: i64,
) -> Result<Option<BanRow>, StorageError> {
    let row = sqlx::query_as::<_, BanRow>(
        "SELECT account_id, until, reason, banned_by FROM bans
         WHERE account_id = ? AND until > ?",
    )
    .bind(account_id)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Lift a ban outright (an admin "unban", or cleanup of a lapsed row).
pub async fn clear(pool: &SqlitePool, account_id: &str) -> Result<(), StorageError> {
    sqlx::query("DELETE FROM bans WHERE account_id = ?")
        .bind(account_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool_with_account() -> (SqlitePool, String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::connect(&dir.path().join("test.db")).await.unwrap();
        // The ban tests only need a row to satisfy the FK; the PHC contents are
        // never verified here, so a placeholder is fine.
        let acct = crate::accounts::create(&pool, "crash", "phc$placeholder", 1)
            .await
            .unwrap();
        (pool, acct.id, dir)
    }

    #[tokio::test]
    async fn set_then_active_within_window() {
        let (pool, id, _dir) = pool_with_account().await;
        set(&pool, &id, 1_000, "spamming", "admin").await.unwrap();

        let ban = active(&pool, &id, 500).await.unwrap().expect("active");
        assert_eq!(ban.reason, "spamming");
        assert_eq!(ban.banned_by, "admin");
        // Lapsed once now passes `until`.
        assert!(active(&pool, &id, 1_000).await.unwrap().is_none());
        assert!(active(&pool, &id, 2_000).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn set_replaces_prior_ban() {
        let (pool, id, _dir) = pool_with_account().await;
        set(&pool, &id, 1_000, "first", "a").await.unwrap();
        set(&pool, &id, 5_000, "second", "b").await.unwrap();
        let ban = active(&pool, &id, 1_500).await.unwrap().expect("active");
        assert_eq!(ban.until, 5_000);
        assert_eq!(ban.reason, "second");
    }

    #[tokio::test]
    async fn clear_lifts_ban() {
        let (pool, id, _dir) = pool_with_account().await;
        set(&pool, &id, 1_000, "x", "a").await.unwrap();
        clear(&pool, &id).await.unwrap();
        assert!(active(&pool, &id, 500).await.unwrap().is_none());
    }
}
