//! Server History: an append-only audit log of admin-relevant events —
//! logins (success/failure/refused-while-banned), kicks/bans, account/role/
//! newsgroup mutations, settings changes, broadcasts, and shutdown. Thin
//! domain layer over `kdx_storage::history` (mirrors `NewsManager`): callers
//! pass a short machine-readable `action` string and a human-readable
//! `detail`; the connection dispatch decides what's worth recording.
//!
//! Some events are triggered by unauthenticated or denied peers (failed
//! logins, IP-rule denials), so the log defends itself:
//! - `actor` / `detail` are truncated to [`MAX_HISTORY_ACTOR_LEN`] /
//!   [`MAX_HISTORY_DETAIL_LEN`] bytes on every write;
//! - the table is kept to a bounded size ([`HistoryConfig::max_rows`],
//!   optionally [`HistoryConfig::max_age`]), pruned by the log itself at
//!   startup and after every [`HistoryConfig::prune_every`] writes;
//! - fire-and-forget writes ([`HistoryLog::record_detached`]) go through a
//!   bounded queue to a single writer task, which never makes the caller
//!   wait, drops (and counts) events when the queue is full, writes each
//!   batch in one transaction, and collapses identical events in a batch
//!   into one row with a repeat count.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use kdx_storage::history::{self as storage, NewHistoryRow};
use kdx_storage::SqlitePool;
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::limits::{truncate_utf8, MAX_HISTORY_ACTOR_LEN, MAX_HISTORY_DETAIL_LEN};
use crate::presence::unix_now;

/// Most queued messages the writer takes per transaction.
const MAX_BATCH: usize = 256;

/// `action` of the row the writer adds when queued events had to be dropped.
pub const ACTION_HISTORY_DROPPED: &str = "history_dropped";

#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    #[error("storage error: {0}")]
    Storage(#[from] kdx_storage::StorageError),
}

/// Retention and queueing knobs. `Default` is what the server uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryConfig {
    /// Keep at most this many of the newest rows (`None`: no row cap).
    pub max_rows: Option<u64>,
    /// Delete rows older than this (`None`: no age limit).
    pub max_age: Option<Duration>,
    /// Depth of the `record_detached` queue; events beyond it are dropped.
    pub queue_capacity: usize,
    /// Run retention after this many rows have been written since the last
    /// run (so the table overshoots `max_rows` by at most about this much).
    pub prune_every: u64,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            max_rows: Some(100_000),
            max_age: None,
            queue_capacity: 1024,
            prune_every: 1000,
        }
    }
}

/// One audit-log entry, timestamp already as `u64` unix seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    pub timestamp: u64,
    pub actor: Option<String>,
    pub action: String,
    pub detail: String,
}

fn from_row(row: storage::HistoryRow) -> HistoryEntry {
    HistoryEntry {
        timestamp: row.timestamp as u64,
        actor: row.actor,
        action: row.action,
        detail: row.detail,
    }
}

fn to_db_timestamp(timestamp: u64) -> i64 {
    i64::try_from(timestamp).unwrap_or(i64::MAX)
}

/// An entry waiting for the writer, already truncated.
struct Pending {
    timestamp: u64,
    actor: Option<String>,
    action: String,
    detail: String,
}

enum WriterMsg {
    Entry(Pending),
    /// Wake the writer to check whether retention is due (sent by the
    /// inline `record` path, which otherwise never talks to the writer).
    Prune,
    /// Acknowledge once everything queued before it has been written.
    Flush(oneshot::Sender<()>),
}

/// Counters shared between the log handle and its writer task.
#[derive(Default)]
struct Shared {
    /// `record_detached` events dropped because the queue was full, not yet
    /// reported in the table.
    dropped: AtomicU64,
    /// Rows written (by either path) since retention last ran.
    since_prune: AtomicU64,
}

pub struct HistoryLog {
    pool: SqlitePool,
    config: HistoryConfig,
    tx: mpsc::Sender<WriterMsg>,
    shared: Arc<Shared>,
}

impl HistoryLog {
    /// A log with the default [`HistoryConfig`].
    ///
    /// Spawns the background writer, so it must be called inside a Tokio
    /// runtime (it panics otherwise, like `tokio::spawn`).
    pub fn new(pool: SqlitePool) -> Self {
        Self::with_config(pool, HistoryConfig::default())
    }

    /// A log with explicit retention / queue settings. Spawns the background
    /// writer (must be called inside a Tokio runtime), which applies
    /// retention once right away.
    pub fn with_config(pool: SqlitePool, config: HistoryConfig) -> Self {
        let config = HistoryConfig {
            queue_capacity: config.queue_capacity.max(1),
            prune_every: config.prune_every.max(1),
            ..config
        };
        let (tx, rx) = mpsc::channel(config.queue_capacity);
        let shared = Arc::new(Shared::default());
        tokio::spawn(run_writer(pool.clone(), config.clone(), shared.clone(), rx));
        Self {
            pool,
            config,
            tx,
            shared,
        }
    }

    /// Record an event and wait for the write to land. Used where the write
    /// should be durable before the caller's next step (admin mutations,
    /// tests); a logging failure is still the caller's to ignore.
    /// `actor` / `detail` are truncated to the history limits.
    pub async fn record(
        &self,
        timestamp: u64,
        actor: Option<&str>,
        action: &str,
        detail: &str,
    ) -> Result<(), HistoryError> {
        let actor = actor.map(|a| truncate_utf8(a, MAX_HISTORY_ACTOR_LEN));
        let detail = truncate_utf8(detail, MAX_HISTORY_DETAIL_LEN);
        storage::record(&self.pool, to_db_timestamp(timestamp), actor, action, detail).await?;
        let since = self.shared.since_prune.fetch_add(1, Ordering::Relaxed) + 1;
        if since == self.config.prune_every {
            // Best-effort wake-up; if the queue is full the writer is busy
            // and checks the counter after its current batch anyway.
            let _ = self.tx.try_send(WriterMsg::Prune);
        }
        Ok(())
    }

    /// Queue an event for the background writer and return immediately:
    /// never awaits, never blocks, safe on hot paths such as the accept
    /// loop. `actor` / `detail` are truncated to the history limits. Returns
    /// `false` if the event was dropped because the queue is full (the
    /// writer then records one `history_dropped` row with the count).
    pub fn record_detached(
        &self,
        timestamp: u64,
        actor: Option<&str>,
        action: &str,
        detail: &str,
    ) -> bool {
        let entry = Pending {
            timestamp,
            actor: actor.map(|a| truncate_utf8(a, MAX_HISTORY_ACTOR_LEN).to_owned()),
            action: action.to_owned(),
            detail: truncate_utf8(detail, MAX_HISTORY_DETAIL_LEN).to_owned(),
        };
        match self.tx.try_send(WriterMsg::Entry(entry)) {
            Ok(()) => true,
            Err(_) => {
                self.shared.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Wait until every event queued by `record_detached` before this call
    /// has been written (or failed). For tests and graceful shutdown.
    pub async fn flush(&self) {
        let (ack, done) = oneshot::channel();
        if self.tx.send(WriterMsg::Flush(ack)).await.is_ok() {
            let _ = done.await;
        }
    }

    /// Apply retention now; returns the number of rows deleted. The writer
    /// does this on its own — this is for tests and operators.
    pub async fn prune(&self) -> Result<u64, HistoryError> {
        self.shared.since_prune.store(0, Ordering::Relaxed);
        Ok(apply_retention(&self.pool, &self.config).await?)
    }

    /// The most recent `limit` entries, newest first.
    pub async fn recent(&self, limit: u32) -> Result<Vec<HistoryEntry>, HistoryError> {
        Ok(storage::recent(&self.pool, limit)
            .await?
            .into_iter()
            .map(from_row)
            .collect())
    }
}

async fn apply_retention(
    pool: &SqlitePool,
    config: &HistoryConfig,
) -> Result<u64, kdx_storage::StorageError> {
    let mut deleted = 0;
    if let Some(max_age) = config.max_age {
        let cutoff = unix_now().saturating_sub(max_age.as_secs());
        deleted += storage::prune_older_than(pool, to_db_timestamp(cutoff)).await?;
    }
    if let Some(max_rows) = config.max_rows {
        deleted += storage::prune_keep_newest(pool, max_rows).await?;
    }
    Ok(deleted)
}

/// Collapse entries identical in (actor, action, detail) into the first
/// occurrence, whose detail gains a repeat count. Order and timestamps of
/// the surviving rows are those of each first occurrence.
fn coalesce(entries: Vec<Pending>) -> Vec<NewHistoryRow> {
    let mut out: Vec<(Pending, u64)> = Vec::with_capacity(entries.len());
    let mut seen: HashMap<(Option<String>, String, String), usize> = HashMap::new();
    for entry in entries {
        let key = (entry.actor.clone(), entry.action.clone(), entry.detail.clone());
        if let Some(&i) = seen.get(&key) {
            out[i].1 += 1;
        } else {
            seen.insert(key, out.len());
            out.push((entry, 1));
        }
    }
    out.into_iter()
        .map(|(entry, count)| NewHistoryRow {
            timestamp: to_db_timestamp(entry.timestamp),
            actor: entry.actor,
            action: entry.action,
            detail: if count > 1 {
                with_repeat_count(&entry.detail, count)
            } else {
                entry.detail
            },
        })
        .collect()
}

/// `detail` with a ` (xN)` suffix, still within `MAX_HISTORY_DETAIL_LEN`.
fn with_repeat_count(detail: &str, count: u64) -> String {
    let suffix = format!("(x{count})");
    if detail.is_empty() {
        return suffix;
    }
    let room = MAX_HISTORY_DETAIL_LEN.saturating_sub(suffix.len() + 1);
    format!("{} {suffix}", truncate_utf8(detail, room))
}

async fn run_writer(
    pool: SqlitePool,
    config: HistoryConfig,
    shared: Arc<Shared>,
    mut rx: mpsc::Receiver<WriterMsg>,
) {
    if let Err(e) = apply_retention(&pool, &config).await {
        warn!(error = %e, "history retention failed");
    }
    let mut batch = Vec::with_capacity(MAX_BATCH);
    while rx.recv_many(&mut batch, MAX_BATCH).await > 0 {
        let mut entries = Vec::with_capacity(batch.len());
        let mut acks = Vec::new();
        for msg in batch.drain(..) {
            match msg {
                WriterMsg::Entry(entry) => entries.push(entry),
                WriterMsg::Prune => {}
                WriterMsg::Flush(ack) => acks.push(ack),
            }
        }

        let mut rows = coalesce(entries);
        let dropped = shared.dropped.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            warn!(dropped, "history queue full; events dropped");
            rows.push(NewHistoryRow {
                timestamp: to_db_timestamp(unix_now()),
                actor: None,
                action: ACTION_HISTORY_DROPPED.to_owned(),
                detail: format!("{dropped} events dropped (history queue full)"),
            });
        }
        if !rows.is_empty() {
            match storage::record_batch(&pool, &rows).await {
                Ok(()) => {
                    shared.since_prune.fetch_add(rows.len() as u64, Ordering::Relaxed);
                }
                Err(e) => warn!(error = %e, rows = rows.len(), "history write failed"),
            }
        }

        if shared.since_prune.load(Ordering::Relaxed) >= config.prune_every {
            shared.since_prune.store(0, Ordering::Relaxed);
            if let Err(e) = apply_retention(&pool, &config).await {
                warn!(error = %e, "history retention failed");
            }
        }

        for ack in acks {
            let _ = ack.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> (SqlitePool, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = kdx_storage::connect(&dir.path().join("test.db")).await.unwrap();
        (pool, dir)
    }

    async fn log() -> (HistoryLog, tempfile::TempDir) {
        let (pool, dir) = pool().await;
        (HistoryLog::new(pool), dir)
    }

    async fn rows(history: &HistoryLog) -> u64 {
        storage::count(&history.pool).await.unwrap()
    }

    #[tokio::test]
    async fn record_and_read_back() {
        let (history, _dir) = log().await;
        history.record(100, Some("sysop"), "kicked", "target=lamer").await.unwrap();
        history.record(200, Some("phraq"), "login", "").await.unwrap();

        let entries = history.recent(10).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, "login"); // newest first
        assert_eq!(entries[1].action, "kicked");
        assert_eq!(entries[1].detail, "target=lamer");
    }

    #[tokio::test]
    async fn record_truncates_actor_and_detail() {
        let (history, _dir) = log().await;
        let actor = "x".repeat(20 * 1024);
        let detail = "ü".repeat(10 * 1024); // two bytes per char
        history.record(1, Some(&actor), "login_failed", &detail).await.unwrap();
        let entry = history.recent(1).await.unwrap().remove(0);
        assert_eq!(entry.actor.unwrap().len(), MAX_HISTORY_ACTOR_LEN);
        assert_eq!(entry.detail.len(), MAX_HISTORY_DETAIL_LEN);
        assert!(entry.detail.chars().all(|c| c == 'ü'));
    }

    #[tokio::test]
    async fn record_detached_lands_truncated_after_flush() {
        let (history, _dir) = log().await;
        let actor = "x".repeat(20 * 1024);
        assert!(history.record_detached(5, Some(&actor), "login_failed", ""));
        assert!(history.record_detached(6, None, "ip_denied", &"d".repeat(4096)));
        history.flush().await;

        let entries = history.recent(10).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, "ip_denied");
        assert_eq!(entries[0].detail.len(), MAX_HISTORY_DETAIL_LEN);
        assert_eq!(entries[1].action, "login_failed");
        assert_eq!(entries[1].actor.as_ref().unwrap().len(), MAX_HISTORY_ACTOR_LEN);
        assert_eq!(entries[1].timestamp, 5);
    }

    #[tokio::test]
    async fn record_detached_is_bounded_and_reports_drops() {
        let (pool, _dir) = pool().await;
        let config = HistoryConfig {
            queue_capacity: 8,
            ..HistoryConfig::default()
        };
        let history = HistoryLog::with_config(pool, config);
        // The writer can't run until this (current-thread) test yields, so a
        // burst sees exactly the queue's capacity and nothing more.
        let accepted = (0..1000)
            .filter(|i| history.record_detached(1, Some("flood"), "login_failed", &i.to_string()))
            .count();
        assert_eq!(accepted, 8);
        history.flush().await;

        let entries = history.recent(100).await.unwrap();
        assert_eq!(entries.len(), 9, "8 queued events + 1 drop report");
        let report = entries.iter().find(|e| e.action == ACTION_HISTORY_DROPPED).unwrap();
        assert_eq!(report.detail, "992 events dropped (history queue full)");
        // Once drained, the queue accepts again.
        assert!(history.record_detached(2, Some("flood"), "login_failed", "late"));
        history.flush().await;
        assert_eq!(rows(&history).await, 10);
    }

    #[tokio::test]
    async fn identical_events_in_a_batch_are_coalesced() {
        let (history, _dir) = log().await;
        for _ in 0..5 {
            history.record_detached(10, None, "ip_denied", "peer=10.0.0.1, note=spam");
        }
        history.record_detached(11, Some("phraq"), "login", "");
        history.record_detached(12, Some("phraq"), "login", "");
        history.flush().await;

        let entries = history.recent(10).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, "login");
        assert_eq!(entries[0].detail, "(x2)");
        assert_eq!(entries[1].detail, "peer=10.0.0.1, note=spam (x5)");
        assert_eq!(entries[1].timestamp, 10);
    }

    #[test]
    fn repeat_count_stays_within_detail_limit() {
        let long = "d".repeat(MAX_HISTORY_DETAIL_LEN);
        let s = with_repeat_count(&long, 12345);
        assert!(s.len() <= MAX_HISTORY_DETAIL_LEN);
        assert!(s.ends_with(" (x12345)"));
    }

    #[tokio::test]
    async fn writer_prunes_to_max_rows() {
        let (pool, _dir) = pool().await;
        let config = HistoryConfig {
            max_rows: Some(10),
            prune_every: 5,
            ..HistoryConfig::default()
        };
        let history = HistoryLog::with_config(pool, config);
        for i in 0..50u64 {
            assert!(history.record_detached(i, None, "e", &i.to_string()));
        }
        history.flush().await;

        assert_eq!(rows(&history).await, 10);
        let entries = history.recent(100).await.unwrap();
        assert_eq!(entries.first().unwrap().detail, "49");
        assert_eq!(entries.last().unwrap().detail, "40");
    }

    #[tokio::test]
    async fn inline_records_also_trigger_retention() {
        let (pool, _dir) = pool().await;
        let config = HistoryConfig {
            max_rows: Some(3),
            prune_every: 4,
            ..HistoryConfig::default()
        };
        let history = HistoryLog::with_config(pool, config);
        for i in 0..8u64 {
            history.record(i, None, "e", "").await.unwrap();
        }
        history.flush().await;
        // A prune ran after the 4th write (≤ 3 left), and at most 4 more
        // rows were written after it.
        assert!(rows(&history).await <= 7);
    }

    #[tokio::test]
    async fn retention_runs_at_startup() {
        let (pool, _dir) = pool().await;
        for i in 0..30 {
            storage::record(&pool, i, Some("old"), "e", "").await.unwrap();
        }
        let config = HistoryConfig {
            max_rows: Some(5),
            ..HistoryConfig::default()
        };
        let history = HistoryLog::with_config(pool, config);
        history.flush().await;
        assert_eq!(rows(&history).await, 5);
    }

    #[tokio::test]
    async fn max_age_drops_old_rows() {
        let (pool, _dir) = pool().await;
        let config = HistoryConfig {
            max_rows: None,
            max_age: Some(Duration::from_secs(24 * 3600)),
            ..HistoryConfig::default()
        };
        let history = HistoryLog::with_config(pool, config);
        history.flush().await; // startup retention done; table empty
        let now = unix_now();
        history.record(now - 3 * 24 * 3600, None, "ancient", "").await.unwrap();
        history.record(now - 3600, None, "recent", "").await.unwrap();
        assert_eq!(history.prune().await.unwrap(), 1);
        let entries = history.recent(10).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "recent");
    }
}
