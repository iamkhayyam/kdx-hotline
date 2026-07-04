use std::path::Path;
use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};

use crate::StorageError;

/// Open (creating if missing) the SQLite database at `path` and run all
/// pending migrations. This is the only place migrations execute.
pub async fn connect(path: &Path) -> Result<SqlitePool, StorageError> {
    let url = format!("sqlite://{}", path.display());
    let options = SqliteConnectOptions::from_str(&url)?
        .create_if_missing(true)
        // WAL keeps readers unblocked during chunk-ack bitmap writes.
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}
