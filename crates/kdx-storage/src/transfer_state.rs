use sqlx::SqlitePool;

use crate::StorageError;

/// Durable state of an in-flight (resumable) upload. The bitmap is updated
/// after every accepted chunk, so a crash or disconnect loses at most the
/// chunk in flight.
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
