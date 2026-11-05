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

/// Record a ban set by an account of class `banned_by_class`, without letting
/// a lower rank undo a higher rank's ban. Returns the `until` now in force.
///
/// If an active ban already exists, the new one replaces it outright only
/// when the new banner outranks the old one, or is the same account at the
/// same or higher class (adjusting their own ban). Otherwise the bans merge:
/// the later `until` wins (with its reason), and the original banner and
/// class stay on record, so the lower-ranked banner can extend the ban but
/// never shorten it. Lapsed rows (`until <= now`) are swept first, so a
/// lapsed ban never constrains a new one.
#[allow(clippy::too_many_arguments)]
pub async fn set_ranked(
    pool: &SqlitePool,
    account_id: &str,
    until: i64,
    reason: &str,
    banned_by: &str,
    banned_by_class: i64,
    now: i64,
) -> Result<i64, StorageError> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM bans WHERE until <= ?")
        .bind(now)
        .execute(&mut *tx)
        .await?;
    // In an upsert's SET, every right-hand side sees the pre-update row, so
    // the shared "replace" test means the same thing in each column.
    let effective: i64 = sqlx::query_scalar(
        "INSERT INTO bans (account_id, until, reason, banned_by, banned_by_class)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(account_id) DO UPDATE SET
            until = CASE WHEN excluded.banned_by_class > bans.banned_by_class
                           OR (excluded.banned_by = bans.banned_by
                               AND excluded.banned_by_class >= bans.banned_by_class)
                         THEN excluded.until
                         ELSE MAX(bans.until, excluded.until) END,
            reason = CASE WHEN excluded.banned_by_class > bans.banned_by_class
                            OR (excluded.banned_by = bans.banned_by
                                AND excluded.banned_by_class >= bans.banned_by_class)
                            OR excluded.until > bans.until
                          THEN excluded.reason
                          ELSE bans.reason END,
            banned_by = CASE WHEN excluded.banned_by_class > bans.banned_by_class
                             THEN excluded.banned_by
                             ELSE bans.banned_by END,
            banned_by_class = MAX(bans.banned_by_class, excluded.banned_by_class),
            created_at = datetime('now')
         RETURNING until",
    )
    .bind(account_id)
    .bind(until)
    .bind(reason)
    .bind(banned_by)
    .bind(banned_by_class)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(effective)
}

/// Delete every lapsed ban (`until <= now`). Returns how many were removed.
pub async fn sweep(pool: &SqlitePool, now: i64) -> Result<u64, StorageError> {
    let result = sqlx::query("DELETE FROM bans WHERE until <= ?")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
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
        let acct = crate::accounts::create(&pool, "crash", "phc$placeholder", 1, 0, 0)
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
    async fn lower_rank_cannot_shorten_a_ban() {
        let (pool, id, _dir) = pool_with_account().await;
        // An admin (class 3) bans until 5000.
        let until = set_ranked(&pool, &id, 5_000, "admin ban", "sysop", 3, 100)
            .await
            .unwrap();
        assert_eq!(until, 5_000);
        // A moderator (class 2) re-bans for a few seconds: the longer ban stays.
        let until = set_ranked(&pool, &id, 110, "short", "mod", 2, 100).await.unwrap();
        assert_eq!(until, 5_000);
        let ban = active(&pool, &id, 200).await.unwrap().expect("still banned");
        assert_eq!(ban.until, 5_000);
        assert_eq!(ban.reason, "admin ban");
        assert_eq!(ban.banned_by, "sysop");

        // The moderator may extend it; the admin stays the owner of record,
        // so the moderator still can't shorten it afterwards.
        let until = set_ranked(&pool, &id, 9_000, "longer", "mod", 2, 100).await.unwrap();
        assert_eq!(until, 9_000);
        let ban = active(&pool, &id, 200).await.unwrap().unwrap();
        assert_eq!(ban.banned_by, "sysop");
        assert_eq!(ban.reason, "longer");
        let until = set_ranked(&pool, &id, 150, "undo", "mod", 2, 100).await.unwrap();
        assert_eq!(until, 9_000);

        // The original banner may shorten their own ban; so may a higher rank.
        let until = set_ranked(&pool, &id, 300, "relent", "sysop", 3, 100).await.unwrap();
        assert_eq!(until, 300);
    }

    #[tokio::test]
    async fn higher_rank_replaces_and_lapsed_bans_are_swept() {
        let (pool, id, _dir) = pool_with_account().await;
        set_ranked(&pool, &id, 5_000, "mod ban", "mod", 2, 100).await.unwrap();
        let until = set_ranked(&pool, &id, 200, "admin says less", "sysop", 3, 100)
            .await
            .unwrap();
        assert_eq!(until, 200);

        // Once lapsed, even a lower rank's new ban applies as given.
        let until = set_ranked(&pool, &id, 400, "new", "mod", 2, 300).await.unwrap();
        assert_eq!(until, 400);
        assert_eq!(active(&pool, &id, 350).await.unwrap().unwrap().banned_by, "mod");

        assert_eq!(sweep(&pool, 1_000).await.unwrap(), 1);
        assert!(active(&pool, &id, 0).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn clear_lifts_ban() {
        let (pool, id, _dir) = pool_with_account().await;
        set(&pool, &id, 1_000, "x", "a").await.unwrap();
        clear(&pool, &id).await.unwrap();
        assert!(active(&pool, &id, 500).await.unwrap().is_none());
    }
}
