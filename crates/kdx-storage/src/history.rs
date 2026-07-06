//! Server History: an append-only audit log. Semantics (which events get
//! recorded, what `action` strings mean) live in kdx-server-core; storage
//! only persists rows and reads them back, most-recent-first.

use sqlx::SqlitePool;
use uuid::Uuid;

use crate::StorageError;

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct HistoryRow {
    pub id: String,
    pub timestamp: i64,
    pub actor: Option<String>,
    pub action: String,
    pub detail: String,
}

pub async fn record(
    pool: &SqlitePool,
    timestamp: i64,
    actor: Option<&str>,
    action: &str,
    detail: &str,
) -> Result<(), StorageError> {
    let id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO history (id, timestamp, actor, action, detail) VALUES (?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(timestamp)
        .bind(actor)
        .bind(action)
        .bind(detail)
        .execute(pool)
        .await?;
    Ok(())
}

/// The most recent `limit` entries, newest first.
///
/// Ties on `timestamp` (unix seconds — multiple events routinely land in the
/// same second) break on the table's implicit `rowid`, which is monotonic
/// insertion order. `id` (a random UUID) is *not* used as the tiebreak: it
/// would sort same-second events in an arbitrary order instead of the order
/// they actually happened.
pub async fn recent(pool: &SqlitePool, limit: u32) -> Result<Vec<HistoryRow>, StorageError> {
    let rows = sqlx::query_as::<_, HistoryRow>(
        "SELECT id, timestamp, actor, action, detail FROM history
         ORDER BY timestamp DESC, rowid DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
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
    async fn record_then_recent_newest_first() {
        let (pool, _dir) = pool().await;
        record(&pool, 100, Some("phraq"), "login", "").await.unwrap();
        record(&pool, 200, Some("sysop"), "kicked", "target=lamer").await.unwrap();

        let rows = recent(&pool, 10).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].action, "kicked"); // newest first
        assert_eq!(rows[0].actor.as_deref(), Some("sysop"));
        assert_eq!(rows[1].action, "login");
    }

    #[tokio::test]
    async fn same_timestamp_ties_break_on_insertion_order() {
        let (pool, _dir) = pool().await;
        // All three land in the same unix second — a routine case (e.g. a
        // sysop's quick sequence of actions). The random UUID `id` must not
        // be the tiebreak; only rowid (insertion order) gives a stable,
        // correct "newest first" ordering here.
        record(&pool, 500, Some("sysop"), "role_created", "mods").await.unwrap();
        record(&pool, 500, Some("sysop"), "account_created", "newbie").await.unwrap();
        record(&pool, 500, Some("sysop"), "server_settings_updated", "").await.unwrap();

        let rows = recent(&pool, 10).await.unwrap();
        assert_eq!(
            rows.iter().map(|r| r.action.as_str()).collect::<Vec<_>>(),
            vec!["server_settings_updated", "account_created", "role_created"],
        );
    }

    #[tokio::test]
    async fn recent_respects_limit() {
        let (pool, _dir) = pool().await;
        for i in 0..5 {
            record(&pool, i, Some("a"), "login", "").await.unwrap();
        }
        assert_eq!(recent(&pool, 3).await.unwrap().len(), 3);
        assert_eq!(recent(&pool, 100).await.unwrap().len(), 5);
    }

    #[tokio::test]
    async fn actor_can_be_absent() {
        let (pool, _dir) = pool().await;
        record(&pool, 1, None, "server_started", "").await.unwrap();
        let rows = recent(&pool, 10).await.unwrap();
        assert_eq!(rows[0].actor, None);
    }
}
