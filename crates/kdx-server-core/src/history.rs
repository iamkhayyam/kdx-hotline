//! Server History: an append-only audit log of admin-relevant events —
//! logins (success/failure/refused-while-banned), kicks/bans, account/role/
//! newsgroup mutations, settings changes, broadcasts, and shutdown. Thin
//! domain layer over `kdx_storage::history` (mirrors `NewsManager`): callers
//! pass a short machine-readable `action` string and a human-readable
//! `detail`; the connection dispatch decides what's worth recording.

use kdx_storage::history as storage;
use kdx_storage::SqlitePool;

#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    #[error("storage error: {0}")]
    Storage(#[from] kdx_storage::StorageError),
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

pub struct HistoryLog {
    pool: SqlitePool,
}

impl HistoryLog {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Record an event. Best-effort by design: a logging failure should never
    /// block the action it's recording, so callers fire-and-forget this
    /// (the return value exists for the rare caller — e.g. tests — that
    /// wants to confirm the write landed).
    pub async fn record(
        &self,
        timestamp: u64,
        actor: Option<&str>,
        action: &str,
        detail: &str,
    ) -> Result<(), HistoryError> {
        storage::record(&self.pool, timestamp as i64, actor, action, detail).await?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn log() -> (HistoryLog, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = kdx_storage::connect(&dir.path().join("test.db")).await.unwrap();
        (HistoryLog::new(pool), dir)
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
}
