use sqlx::SqlitePool;
use uuid::Uuid;

use crate::StorageError;

pub const ROOT_ID: &str = "root";

/// One row of `file_nodes`. Kind constants: 0 dir, 1 file, 2 dropbox,
/// 3 upload folder, 4 alias — semantics live in kdx-server-core.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FileNodeRow {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub kind: i64,
    pub size: i64,
    pub sha256: Option<Vec<u8>>,
    pub min_class_read: i64,
    pub min_class_write: i64,
    pub storage_path: Option<String>,
    /// For alias rows (`kind == 4`): the UUID of the pointed-to node.
    /// `None` for every other kind. The FK has `ON DELETE SET NULL`, so
    /// deleting a target leaves the alias as a dangling row that resolves
    /// to "not found" at runtime rather than silently disappearing.
    pub target_id: Option<String>,
    /// Optional owner login (dropboxes / [DB] folders): the owner may read
    /// and delete inside even though the folder is write-only to others.
    pub owner: Option<String>,
}

pub async fn all(pool: &SqlitePool) -> Result<Vec<FileNodeRow>, StorageError> {
    let rows = sqlx::query_as::<_, FileNodeRow>(
        "SELECT id, parent_id, name, kind, size, sha256, min_class_read, min_class_write,
                storage_path, target_id, owner
         FROM file_nodes",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Insert a folder-like node (directory, dropbox, or upload folder).
pub async fn create_folder(
    pool: &SqlitePool,
    parent_id: &str,
    name: &str,
    kind: i64,
    min_class_read: i64,
    min_class_write: i64,
    owner: Option<&str>,
) -> Result<FileNodeRow, StorageError> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO file_nodes (id, parent_id, name, kind, min_class_read, min_class_write, owner)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(parent_id)
    .bind(name)
    .bind(kind)
    .bind(min_class_read)
    .bind(min_class_write)
    .bind(owner)
    .execute(pool)
    .await?;
    Ok(FileNodeRow {
        id,
        parent_id: Some(parent_id.to_owned()),
        name: name.to_owned(),
        kind,
        size: 0,
        sha256: None,
        min_class_read,
        min_class_write,
        storage_path: None,
        target_id: None,
        owner: owner.map(str::to_owned),
    })
}

/// Insert a completed file node.
pub async fn create_file(
    pool: &SqlitePool,
    parent_id: &str,
    name: &str,
    size: i64,
    sha256: &[u8],
    storage_path: &str,
) -> Result<FileNodeRow, StorageError> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO file_nodes (id, parent_id, name, kind, size, sha256, storage_path)
         VALUES (?, ?, ?, 1, ?, ?, ?)",
    )
    .bind(&id)
    .bind(parent_id)
    .bind(name)
    .bind(size)
    .bind(sha256)
    .bind(storage_path)
    .execute(pool)
    .await?;
    Ok(FileNodeRow {
        id,
        parent_id: Some(parent_id.to_owned()),
        name: name.to_owned(),
        kind: 1,
        size,
        sha256: Some(sha256.to_vec()),
        min_class_read: 0,
        min_class_write: 2,
        storage_path: Some(storage_path.to_owned()),
        target_id: None,
        owner: None,
    })
}

/// Insert an alias node — kind = 4, points to `target_id`. The alias itself
/// carries no size or storage; those are resolved through to the target at
/// read time. The domain layer guards that `target_id` is a real, non-alias
/// node before calling this.
pub async fn create_alias(
    pool: &SqlitePool,
    parent_id: &str,
    name: &str,
    target_id: &str,
) -> Result<FileNodeRow, StorageError> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO file_nodes (id, parent_id, name, kind, target_id)
         VALUES (?, ?, ?, 4, ?)",
    )
    .bind(&id)
    .bind(parent_id)
    .bind(name)
    .bind(target_id)
    .execute(pool)
    .await?;
    Ok(FileNodeRow {
        id,
        parent_id: Some(parent_id.to_owned()),
        name: name.to_owned(),
        kind: 4,
        size: 0,
        sha256: None,
        min_class_read: 0,
        min_class_write: 2,
        storage_path: None,
        target_id: Some(target_id.to_owned()),
        owner: None,
    })
}

/// Delete a single node by id. The caller deletes children first — the
/// `parent_id` self-reference has no `ON DELETE CASCADE`, so with foreign keys
/// enforced a non-empty folder would otherwise fail.
pub async fn delete(pool: &SqlitePool, id: &str) -> Result<(), StorageError> {
    let result = sqlx::query("DELETE FROM file_nodes WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(StorageError::NotFound);
    }
    Ok(())
}

/// Re-parent a node (a virtual move — the name stays the same, only
/// `parent_id` changes). The caller has already checked for a name collision
/// under the new parent; the table's `UNIQUE(parent_id, name)` constraint is
/// the backstop.
pub async fn reparent(pool: &SqlitePool, id: &str, new_parent_id: &str) -> Result<(), StorageError> {
    let result = sqlx::query("UPDATE file_nodes SET parent_id = ? WHERE id = ?")
        .bind(new_parent_id)
        .bind(id)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(StorageError::NotFound);
    }
    Ok(())
}
