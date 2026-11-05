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

/// One role by id.
pub async fn by_id(pool: &SqlitePool, id: &str) -> Result<Option<RoleRow>, StorageError> {
    let row = sqlx::query_as::<_, RoleRow>(
        "SELECT id, name, privileges, rank, color FROM roles WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// The privilege-relevant columns of one account (no credential material),
/// read for admin policy checks: who outranks whom, who holds a role.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AccountPrivilegeRow {
    pub id: String,
    pub username: String,
    pub base_class: i64,
    pub granted: i64,
    pub revoked: i64,
}

/// An account's class and overrides by username.
pub async fn account_privileges(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<AccountPrivilegeRow>, StorageError> {
    let row = sqlx::query_as::<_, AccountPrivilegeRow>(
        "SELECT id, username, base_class, granted, revoked FROM accounts WHERE username = ?",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Every account currently holding a role.
pub async fn holders(
    pool: &SqlitePool,
    role_id: &str,
) -> Result<Vec<AccountPrivilegeRow>, StorageError> {
    let rows = sqlx::query_as::<_, AccountPrivilegeRow>(
        "SELECT a.id, a.username, a.base_class, a.granted, a.revoked
         FROM accounts a
         JOIN account_roles ar ON ar.account_id = a.id
         WHERE ar.role_id = ?
         ORDER BY a.username",
    )
    .bind(role_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// How many accounts other than `excluding_username` are admin class (3)
/// with none of `admin_bits` revoked, i.e. can still administer the server.
pub async fn count_administrators(
    pool: &SqlitePool,
    admin_bits: i64,
    excluding_username: &str,
) -> Result<i64, StorageError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM accounts
         WHERE base_class >= 3 AND (revoked & ?) = 0 AND username <> ?",
    )
    .bind(admin_bits)
    .bind(excluding_username)
    .fetch_one(pool)
    .await?;
    Ok(count)
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

    #[tokio::test]
    async fn holders_and_administrator_count() {
        let pool = pool().await;
        let a = crate::accounts::create(&pool, "a", "phc", 1).await.unwrap();
        crate::accounts::create(&pool, "root1", "phc", 3).await.unwrap();
        crate::accounts::create(&pool, "root2", "phc", 3).await.unwrap();
        let role = create(&pool, "VIP", 0b1, 1, None).await.unwrap();
        assign(&pool, &a.id, &role.id).await.unwrap();

        let held = holders(&pool, &role.id).await.unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].username, "a");
        assert_eq!(by_id(&pool, &role.id).await.unwrap().unwrap().name, "VIP");
        assert!(by_id(&pool, "nope").await.unwrap().is_none());
        assert_eq!(
            account_privileges(&pool, "root1").await.unwrap().unwrap().base_class,
            3
        );

        let admin_bits = 0b11 << 18;
        assert_eq!(count_administrators(&pool, admin_bits, "root1").await.unwrap(), 1);
        // An admin with an admin bit revoked no longer counts.
        crate::accounts::set_overrides(&pool, "root2", 0, 1 << 18).await.unwrap();
        assert_eq!(count_administrators(&pool, admin_bits, "root1").await.unwrap(), 0);
    }
}
