//! Persisted live server settings: a small key/value table holding the
//! fields a SysOp edits remotely (name, description, greeting, max users).
//! Which keys exist and how values are validated live in kdx-server-core;
//! storage only reads and writes strings.

use sqlx::SqlitePool;

use crate::StorageError;

/// Every stored setting as `(key, value)`.
pub async fn all(pool: &SqlitePool) -> Result<Vec<(String, String)>, StorageError> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT key, value FROM server_settings ORDER BY key",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Insert or replace each `(key, value)`, all in one transaction so a
/// settings save is never half-applied.
pub async fn put_all(pool: &SqlitePool, entries: &[(&str, &str)]) -> Result<(), StorageError> {
    let mut tx = pool.begin().await?;
    for (key, value) in entries {
        sqlx::query(
            "INSERT INTO server_settings (key, value) VALUES (?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn put_then_read_back_and_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::connect(&dir.path().join("test.db")).await.unwrap();
        assert!(all(&pool).await.unwrap().is_empty());

        put_all(&pool, &[("name", "Underground"), ("greeting", "hi")])
            .await
            .unwrap();
        put_all(&pool, &[("greeting", "welcome back")]).await.unwrap();

        let rows = all(&pool).await.unwrap();
        assert_eq!(
            rows,
            vec![
                ("greeting".to_string(), "welcome back".to_string()),
                ("name".to_string(), "Underground".to_string()),
            ]
        );
    }
}
