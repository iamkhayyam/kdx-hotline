//! Persistence layer for KDX: all sqlx queries and migrations live here so a
//! later SQLite → Postgres swap touches only this crate. Served file bytes
//! live on the filesystem, never in the database.

pub mod accounts;
pub mod bans;
pub mod db;
pub mod file_tree;
pub mod history;
pub mod ip_rules;
pub mod news;
pub mod roles;
pub mod settings;
pub mod transfer_state;

pub use db::connect;
pub use sqlx::SqlitePool;

/// Storage-layer error.
///
/// `From<sqlx::Error>` classifies constraint violations on the way in, so
/// every `?` on a query yields [`StorageError::AlreadyExists`] for a UNIQUE /
/// PRIMARY KEY violation and [`StorageError::ForeignKey`] for a FOREIGN KEY
/// violation — callers can map those to domain errors ("a role with that
/// name already exists") without inspecting driver errors, and their
/// `Display` text carries no SQL or schema detail. Everything else stays in
/// [`StorageError::Sqlx`], whose `Display` *does* include the driver message:
/// log it server-side, don't send it to a client.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Sqlx(sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("row not found")]
    NotFound,
    /// A UNIQUE or PRIMARY KEY constraint rejected the write.
    #[error("already exists")]
    AlreadyExists,
    /// A FOREIGN KEY constraint rejected the write: the row it references
    /// doesn't exist (or a delete would orphan rows that reference it).
    #[error("referenced item does not exist")]
    ForeignKey,
    /// Filesystem error preparing the database file (creation, permissions).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<sqlx::Error> for StorageError {
    fn from(e: sqlx::Error) -> Self {
        use sqlx::error::ErrorKind;
        if let Some(db) = e.as_database_error() {
            match db.kind() {
                ErrorKind::UniqueViolation => return StorageError::AlreadyExists,
                ErrorKind::ForeignKeyViolation => return StorageError::ForeignKey,
                _ => {}
            }
        }
        StorageError::Sqlx(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> (SqlitePool, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = connect(&dir.path().join("err.db")).await.unwrap();
        // Scratch tables so the test doesn't depend on the app schema.
        sqlx::query("CREATE TABLE t_parent (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE t_child (parent_id TEXT NOT NULL REFERENCES t_parent(id))")
            .execute(&pool)
            .await
            .unwrap();
        (pool, dir)
    }

    async fn exec(pool: &SqlitePool, sql: &str) -> Result<(), StorageError> {
        sqlx::query(sql).execute(pool).await?;
        Ok(())
    }

    #[tokio::test]
    async fn unique_violation_maps_to_already_exists() {
        let (pool, _dir) = pool().await;
        exec(&pool, "INSERT INTO t_parent VALUES ('p1', 'docs')").await.unwrap();

        // UNIQUE column.
        let err = exec(&pool, "INSERT INTO t_parent VALUES ('p2', 'docs')").await.unwrap_err();
        assert!(matches!(err, StorageError::AlreadyExists), "got {err:?}");
        // PRIMARY KEY.
        let err = exec(&pool, "INSERT INTO t_parent VALUES ('p1', 'other')").await.unwrap_err();
        assert!(matches!(err, StorageError::AlreadyExists), "got {err:?}");

        let text = err.to_string();
        assert!(!text.contains("UNIQUE") && !text.contains("code") && !text.contains("t_parent"));
    }

    #[tokio::test]
    async fn foreign_key_violation_maps_to_foreign_key() {
        let (pool, _dir) = pool().await;
        let err = exec(&pool, "INSERT INTO t_child VALUES ('missing')").await.unwrap_err();
        assert!(matches!(err, StorageError::ForeignKey), "got {err:?}");
        // `INSERT OR IGNORE` does not ignore FK failures either.
        let err = exec(&pool, "INSERT OR IGNORE INTO t_child VALUES ('missing')").await.unwrap_err();
        assert!(matches!(err, StorageError::ForeignKey), "got {err:?}");

        let text = err.to_string();
        assert!(!text.contains("FOREIGN") && !text.contains("code") && !text.contains("t_child"));
    }

    #[tokio::test]
    async fn other_errors_stay_sqlx() {
        let (pool, _dir) = pool().await;
        // NOT NULL violation and a syntax error are neither duplicate nor FK.
        let err = exec(&pool, "INSERT INTO t_parent (id) VALUES ('p9')").await.unwrap_err();
        assert!(matches!(err, StorageError::Sqlx(_)), "got {err:?}");
        let err = exec(&pool, "SELEC 1").await.unwrap_err();
        assert!(matches!(err, StorageError::Sqlx(_)), "got {err:?}");
        // RowNotFound (no database error at all) is untouched too.
        let err: StorageError = sqlx::Error::RowNotFound.into();
        assert!(matches!(err, StorageError::Sqlx(sqlx::Error::RowNotFound)));
    }
}
