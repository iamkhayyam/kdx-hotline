use sqlx::SqlitePool;
use uuid::Uuid;

use crate::StorageError;

/// One row of the `roles` table. Privilege semantics (what the bits mean,
/// how roles combine with base class and per-account overrides) live in
/// kdx-server-core; storage only persists the raw values.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RoleRow {
    pub id: String,
    pub name: String,
    pub privileges: i64,
    pub rank: i64,
    pub color: Option<String>,
}

pub async fn create(
    pool: &SqlitePool,
    name: &str,
    privileges: i64,
    rank: i64,
    color: Option<&str>,
) -> Result<RoleRow, StorageError> {
    let id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO roles (id, name, privileges, rank, color) VALUES (?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(name)
        .bind(privileges)
        .bind(rank)
        .bind(color)
        .execute(pool)
        .await?;
    Ok(RoleRow {
        id,
        name: name.to_owned(),
        privileges,
        rank,
        color: color.map(str::to_owned),
    })
}

pub async fn all(pool: &SqlitePool) -> Result<Vec<RoleRow>, StorageError> {
    let rows = sqlx::query_as::<_, RoleRow>(
        "SELECT id, name, privileges, rank, color FROM roles ORDER BY rank DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Rename a role and/or change its privilege bits, rank, or color.
pub async fn update(
    pool: &SqlitePool,
    id: &str,
    name: &str,
    privileges: i64,
    rank: i64,
    color: Option<&str>,
) -> Result<(), StorageError> {
    let result = sqlx::query(
        "UPDATE roles SET name = ?, privileges = ?, rank = ?, color = ? WHERE id = ?",
    )
    .bind(name)
    .bind(privileges)
    .bind(rank)
    .bind(color)
    .bind(id)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(StorageError::NotFound);
    }
    Ok(())
}

/// Delete a role and any account assignments referencing it. SQLite doesn't
/// enforce the `ON DELETE CASCADE` in the schema without `PRAGMA foreign_keys`
/// (which this crate doesn't set — see `db.rs`), so we clean up explicitly.
pub async fn delete(pool: &SqlitePool, id: &str) -> Result<(), StorageError> {
    sqlx::query("DELETE FROM account_roles WHERE role_id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    let result = sqlx::query("DELETE FROM roles WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(StorageError::NotFound);
    }
    Ok(())
}

/// Assign a role to an account. Idempotent — assigning twice is a no-op.
pub async fn assign(pool: &SqlitePool, account_id: &str, role_id: &str) -> Result<(), StorageError> {
    sqlx::query("INSERT OR IGNORE INTO account_roles (account_id, role_id) VALUES (?, ?)")
        .bind(account_id)
        .bind(role_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn unassign(pool: &SqlitePool, account_id: &str, role_id: &str) -> Result<(), StorageError> {
    sqlx::query("DELETE FROM account_roles WHERE account_id = ? AND role_id = ?")
        .bind(account_id)
        .bind(role_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// All roles assigned to an account, in rank order (highest first).
pub async fn for_account(pool: &SqlitePool, account_id: &str) -> Result<Vec<RoleRow>, StorageError> {
    let rows = sqlx::query_as::<_, RoleRow>(
        "SELECT r.id, r.name, r.privileges, r.rank, r.color
         FROM roles r
         JOIN account_roles ar ON ar.role_id = r.id
         WHERE ar.account_id = ?
         ORDER BY r.rank DESC",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> SqlitePool {
        let pool = SqlitePool::connect(":memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn create_list_update_delete_round_trip() {
        let pool = pool().await;
        let role = create(&pool, "Moderator", 0b1010, 5, Some("#e11b1b"))
            .await
            .unwrap();
        assert_eq!(role.name, "Moderator");

        let roles = all(&pool).await.unwrap();
        assert_eq!(roles.len(), 1);

        update(&pool, &role.id, "Mod", 0b1110, 6, None).await.unwrap();
        let roles = all(&pool).await.unwrap();
        assert_eq!(roles[0].name, "Mod");
        assert_eq!(roles[0].privileges, 0b1110);

        delete(&pool, &role.id).await.unwrap();
        assert!(all(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn assign_unassign_and_lookup() {
        let pool = pool().await;
        let account = crate::accounts::create(&pool, "phraq", "phc", 1)
            .await
            .unwrap();
        let role = create(&pool, "VIP", 0b1, 1, None).await.unwrap();

        assign(&pool, &account.id, &role.id).await.unwrap();
        assign(&pool, &account.id, &role.id).await.unwrap(); // idempotent

        let assigned = for_account(&pool, &account.id).await.unwrap();
        assert_eq!(assigned.len(), 1);
        assert_eq!(assigned[0].name, "VIP");

        unassign(&pool, &account.id, &role.id).await.unwrap();
        assert!(for_account(&pool, &account.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_role_cascades_from_account() {
        let pool = pool().await;
        let account = crate::accounts::create(&pool, "acidburn", "phc", 1)
            .await
            .unwrap();
        let role = create(&pool, "VIP", 0b1, 1, None).await.unwrap();
        assign(&pool, &account.id, &role.id).await.unwrap();

        delete(&pool, &role.id).await.unwrap();
        assert!(for_account(&pool, &account.id).await.unwrap().is_empty());
    }
}
