use sqlx::SqlitePool;

use crate::StorageError;

/// Durable state of an in-flight (resumable) upload. The server persists the
/// bitmap in batches (and when a connection lets go of the upload), so a
/// crash loses at most the last batch of chunks — the client simply resends
/// them on resume.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TransferRow {
    pub id: String,
    pub account_id: String,
    pub parent_id: String,
    pub name: String,
    pub size: i64,
    pub chunk_size: i64,
    pub sha256: Vec<u8>,
    pub bitmap: Vec<u8>,
    pub temp_path: String,
}

pub async fn create(pool: &SqlitePool, row: &TransferRow) -> Result<(), StorageError> {
    sqlx::query(
        "INSERT INTO transfer_state (id, account_id, parent_id, name, size, chunk_size, sha256,
                                     bitmap, temp_path)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&row.id)
    .bind(&row.account_id)
    .bind(&row.parent_id)
    .bind(&row.name)
    .bind(row.size)
    .bind(row.chunk_size)
    .bind(&row.sha256)
    .bind(&row.bitmap)
    .bind(&row.temp_path)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get(pool: &SqlitePool, id: &str) -> Result<Option<TransferRow>, StorageError> {
    let row = sqlx::query_as::<_, TransferRow>(
        "SELECT id, account_id, parent_id, name, size, chunk_size, sha256, bitmap, temp_path
         FROM transfer_state WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn update_bitmap(
    pool: &SqlitePool,
    id: &str,
    bitmap: &[u8],
) -> Result<(), StorageError> {
    sqlx::query(
        "UPDATE transfer_state SET bitmap = ?, updated_at = datetime('now') WHERE id = ?",
    )
    .bind(bitmap)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete(pool: &SqlitePool, id: &str) -> Result<(), StorageError> {
    sqlx::query("DELETE FROM transfer_state WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Mark a row as recently used (a resume), restarting its expiry clock.
pub async fn touch(pool: &SqlitePool, id: &str) -> Result<(), StorageError> {
    sqlx::query("UPDATE transfer_state SET updated_at = datetime('now') WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Just enough of a row to discard it: its id and partial file.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct PendingTransfer {
    pub id: String,
    pub temp_path: String,
}

/// An account's unfinished uploads, least recently used first.
pub async fn list_for_account(
    pool: &SqlitePool,
    account_id: &str,
) -> Result<Vec<PendingTransfer>, StorageError> {
    let rows = sqlx::query_as::<_, PendingTransfer>(
        "SELECT id, temp_path FROM transfer_state WHERE account_id = ?
         ORDER BY updated_at, rowid",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Unfinished uploads not touched for at least `older_than_secs` seconds
/// (0 = every row), least recently used first.
pub async fn list_stale(
    pool: &SqlitePool,
    older_than_secs: u64,
) -> Result<Vec<PendingTransfer>, StorageError> {
    let rows = sqlx::query_as::<_, PendingTransfer>(
        "SELECT id, temp_path FROM transfer_state WHERE updated_at <= datetime('now', ?)
         ORDER BY updated_at, rowid",
    )
    .bind(format!("-{older_than_secs} seconds"))
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, account: &str) -> TransferRow {
        TransferRow {
            id: id.into(),
            account_id: account.into(),
            parent_id: "root".into(),
            name: format!("{id}.bin"),
            size: 10,
            chunk_size: 4096,
            sha256: vec![0; 32],
            bitmap: vec![0],
            temp_path: format!("/tmp/{id}.part"),
        }
    }

    #[tokio::test]
    async fn list_for_account_and_stale() {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::connect(&dir.path().join("t.db")).await.unwrap();
        create(&pool, &row("a", "acct-1")).await.unwrap();
        create(&pool, &row("b", "acct-1")).await.unwrap();
        create(&pool, &row("c", "acct-2")).await.unwrap();
        // Age "a" by two days.
        sqlx::query(
            "UPDATE transfer_state SET updated_at = datetime('now', '-2 days') WHERE id = 'a'",
        )
        .execute(&pool)
        .await
        .unwrap();

        let mine: Vec<String> = list_for_account(&pool, "acct-1")
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.id)
            .collect();
        assert_eq!(mine, vec!["a", "b"], "oldest first");

        let stale = list_stale(&pool, 24 * 60 * 60).await.unwrap();
        assert_eq!(
            stale,
            vec![PendingTransfer {
                id: "a".into(),
                temp_path: "/tmp/a.part".into(),
            }]
        );
        assert_eq!(list_stale(&pool, 0).await.unwrap().len(), 3);

        // A touch makes it fresh again.
        touch(&pool, "a").await.unwrap();
        assert!(list_stale(&pool, 24 * 60 * 60).await.unwrap().is_empty());
    }
}
