//! Server History: an append-only audit log. Semantics (which events get
//! recorded, what `action` strings mean, the per-field policy limits and the
//! retention policy) live in kdx-server-core; storage persists rows, reads
//! them back most-recent-first, and prunes on request.
//!
//! Writes clip `actor` / `action` / `detail` to fixed backstop sizes so no
//! caller can store an unbounded string, whatever limits it applies itself.

use sqlx::SqlitePool;
use uuid::Uuid;

use crate::StorageError;

/// Backstop cap on a stored `actor`, in bytes. The server applies tighter
/// policy limits before this; this only guarantees nothing unbounded lands.
pub const MAX_ACTOR_BYTES: usize = 256;
/// Backstop cap on a stored `action`, in bytes.
pub const MAX_ACTION_BYTES: usize = 64;
/// Backstop cap on a stored `detail`, in bytes.
pub const MAX_DETAIL_BYTES: usize = 4096;

/// Rows deleted per statement when pruning, so a large prune (e.g. the first
/// start after an upgrade, against an already-flooded table) releases the
/// write lock between chunks instead of holding it for one huge DELETE.
const PRUNE_CHUNK: i64 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct HistoryRow {
    pub id: String,
    pub timestamp: i64,
    pub actor: Option<String>,
    pub action: String,
    pub detail: String,
}

/// One row to insert with [`record_batch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewHistoryRow {
    pub timestamp: i64,
    pub actor: Option<String>,
    pub action: String,
    pub detail: String,
}

/// Longest prefix of `s` that is at most `max` bytes and ends on a char
/// boundary.
fn clip(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

async fn insert<'e, E>(
    executor: E,
    timestamp: i64,
    actor: Option<&str>,
    action: &str,
    detail: &str,
) -> Result<(), StorageError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO history (id, timestamp, actor, action, detail) VALUES (?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(timestamp)
        .bind(actor.map(|a| clip(a, MAX_ACTOR_BYTES)))
        .bind(clip(action, MAX_ACTION_BYTES))
        .bind(clip(detail, MAX_DETAIL_BYTES))
        .execute(executor)
        .await?;
    Ok(())
}

pub async fn record(
    pool: &SqlitePool,
    timestamp: i64,
    actor: Option<&str>,
    action: &str,
    detail: &str,
) -> Result<(), StorageError> {
    insert(pool, timestamp, actor, action, detail).await
}

/// Insert `rows` in one transaction (one commit for the whole batch), in
/// slice order — so `recent` lists later rows first among equal timestamps.
pub async fn record_batch(pool: &SqlitePool, rows: &[NewHistoryRow]) -> Result<(), StorageError> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    for row in rows {
        insert(&mut *tx, row.timestamp, row.actor.as_deref(), &row.action, &row.detail).await?;
    }
    tx.commit().await?;
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

/// Total number of rows.
pub async fn count(pool: &SqlitePool) -> Result<u64, StorageError> {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM history").fetch_one(pool).await?;
    Ok(n as u64)
}

/// Delete all but (at most) the `keep` most recently inserted rows; returns
/// the number deleted.
///
/// "Most recently inserted" is `rowid` order. Rows are only ever appended
/// (new rowid = max + 1) and pruning only removes the oldest, so rowids stay
/// contiguous and this keeps exactly `keep` rows; should there ever be gaps
/// it keeps fewer, never more. Computing the cutoff from `max(rowid)` keeps
/// this O(log n) however large `keep` is.
pub async fn prune_keep_newest(pool: &SqlitePool, keep: u64) -> Result<u64, StorageError> {
    let keep = i64::try_from(keep).unwrap_or(i64::MAX);
    let (max_rowid,): (Option<i64>,) =
        sqlx::query_as("SELECT MAX(rowid) FROM history").fetch_one(pool).await?;
    let Some(cutoff) = max_rowid.and_then(|max| max.checked_sub(keep)) else {
        return Ok(0);
    };
    delete_chunked(
        pool,
        "DELETE FROM history WHERE rowid IN
           (SELECT rowid FROM history WHERE rowid <= ? ORDER BY rowid LIMIT ?)",
        cutoff,
    )
    .await
}

/// Delete every row with `timestamp < cutoff` (unix seconds); returns the
/// number deleted.
pub async fn prune_older_than(pool: &SqlitePool, cutoff: i64) -> Result<u64, StorageError> {
    delete_chunked(
        pool,
        "DELETE FROM history WHERE rowid IN
           (SELECT rowid FROM history WHERE timestamp < ? LIMIT ?)",
        cutoff,
    )
    .await
}

async fn delete_chunked(pool: &SqlitePool, sql: &str, bound: i64) -> Result<u64, StorageError> {
    let mut total = 0;
    loop {
        let deleted = sqlx::query(sql)
            .bind(bound)
            .bind(PRUNE_CHUNK)
            .execute(pool)
            .await?
            .rows_affected();
        total += deleted;
        if deleted < PRUNE_CHUNK as u64 {
            return Ok(total);
        }
    }
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

    #[tokio::test]
    async fn oversized_fields_are_clipped_at_the_backstop() {
        let (pool, _dir) = pool().await;
        let actor = "é".repeat(10_000); // 20 KB, two bytes per char
        let detail = "d".repeat(100_000);
        record(&pool, 1, Some(&actor), &"a".repeat(1000), &detail).await.unwrap();
        let row = recent(&pool, 1).await.unwrap().remove(0);
        let stored_actor = row.actor.unwrap();
        assert_eq!(stored_actor.len(), MAX_ACTOR_BYTES);
        assert!(stored_actor.chars().all(|c| c == 'é'));
        assert_eq!(row.action.len(), MAX_ACTION_BYTES);
        assert_eq!(row.detail.len(), MAX_DETAIL_BYTES);
    }

    #[tokio::test]
    async fn clip_migration_shortens_legacy_rows() {
        let (pool, _dir) = pool().await;
        // A row as an older build stored it, bypassing today's clipping.
        sqlx::query("INSERT INTO history (id, timestamp, actor, action, detail) VALUES ('old', 1, ?, 'login_failed', ?)")
            .bind("ü".repeat(8000))
            .bind("d".repeat(9000))
            .execute(&pool)
            .await
            .unwrap();
        record(&pool, 2, Some("phraq"), "login", "short").await.unwrap();
        sqlx::raw_sql(include_str!("../migrations/0014_history_clip.sql"))
            .execute(&pool)
            .await
            .unwrap();
        let rows = recent(&pool, 10).await.unwrap();
        assert_eq!(rows[0].actor.as_deref(), Some("phraq"));
        assert_eq!(rows[0].detail, "short");
        assert_eq!(rows[1].actor.as_deref(), Some("ü".repeat(64).as_str()));
        assert_eq!(rows[1].detail, "d".repeat(512));
    }

    #[tokio::test]
    async fn record_batch_inserts_in_order() {
        let (pool, _dir) = pool().await;
        let rows: Vec<NewHistoryRow> = (0..3)
            .map(|i| NewHistoryRow {
                timestamp: 7,
                actor: None,
                action: "ip_denied".into(),
                detail: format!("n={i}"),
            })
            .collect();
        record_batch(&pool, &rows).await.unwrap();
        record_batch(&pool, &[]).await.unwrap();
        let details: Vec<String> = recent(&pool, 10).await.unwrap().into_iter().map(|r| r.detail).collect();
        assert_eq!(details, vec!["n=2", "n=1", "n=0"]);
    }

    #[tokio::test]
    async fn prune_keep_newest_keeps_exactly_the_newest() {
        let (pool, _dir) = pool().await;
        for i in 0..50 {
            record(&pool, i, None, "e", &i.to_string()).await.unwrap();
        }
        assert_eq!(prune_keep_newest(&pool, 100).await.unwrap(), 0);
        assert_eq!(prune_keep_newest(&pool, 10).await.unwrap(), 40);
        assert_eq!(count(&pool).await.unwrap(), 10);
        let rows = recent(&pool, 100).await.unwrap();
        assert_eq!(rows.first().unwrap().detail, "49");
        assert_eq!(rows.last().unwrap().detail, "40");
        // Idempotent, and appends after a prune still count from the top.
        assert_eq!(prune_keep_newest(&pool, 10).await.unwrap(), 0);
        record(&pool, 50, None, "e", "50").await.unwrap();
        assert_eq!(prune_keep_newest(&pool, 10).await.unwrap(), 1);
        assert_eq!(recent(&pool, 100).await.unwrap().last().unwrap().detail, "41");
        // keep = 0 empties the table.
        assert_eq!(prune_keep_newest(&pool, 0).await.unwrap(), 10);
        assert_eq!(count(&pool).await.unwrap(), 0);
        assert_eq!(prune_keep_newest(&pool, 0).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn prune_spans_multiple_chunks() {
        let (pool, _dir) = pool().await;
        let n = PRUNE_CHUNK as usize * 2 + 5;
        let rows: Vec<NewHistoryRow> = (0..n)
            .map(|i| NewHistoryRow {
                timestamp: i as i64,
                actor: None,
                action: "e".into(),
                detail: String::new(),
            })
            .collect();
        record_batch(&pool, &rows).await.unwrap();
        assert_eq!(prune_keep_newest(&pool, 3).await.unwrap(), n as u64 - 3);
        assert_eq!(count(&pool).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn prune_older_than_cuts_by_timestamp() {
        let (pool, _dir) = pool().await;
        for ts in [10, 20, 30, 40] {
            record(&pool, ts, None, "e", "").await.unwrap();
        }
        assert_eq!(prune_older_than(&pool, 30).await.unwrap(), 2);
        let ts: Vec<i64> = recent(&pool, 10).await.unwrap().into_iter().map(|r| r.timestamp).collect();
        assert_eq!(ts, vec![40, 30]);
    }
}
