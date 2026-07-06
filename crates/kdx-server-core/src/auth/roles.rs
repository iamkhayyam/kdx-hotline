//! Custom, named privilege bundles a SysOp can define and assign to
//! accounts on top of their base class — the Discord-style "roles" layer.
//! A role's privilege bits are unioned into the class's set at login (see
//! [`super::manager::AuthManager::complete`]); per-account grant/revoke
//! overrides still apply on top and revokes still win.

use kdx_storage::roles as storage;
use kdx_storage::SqlitePool;
use uuid::Uuid;

use super::classes::Privileges;

#[derive(Debug, thiserror::Error)]
pub enum RoleError {
    #[error("stored role id is not a valid uuid")]
    CorruptId,
    #[error("storage error: {0}")]
    Storage(#[from] kdx_storage::StorageError),
}

/// A role as seen by the rest of the server: privilege bits already decoded
/// into the bitflags type instead of a raw `i64`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub privileges: Privileges,
    pub rank: i32,
    pub color: Option<String>,
}

fn from_row(row: storage::RoleRow) -> Result<Role, RoleError> {
    Ok(Role {
        id: Uuid::parse_str(&row.id).map_err(|_| RoleError::CorruptId)?,
        name: row.name,
        privileges: Privileges::from_bits_truncate(row.privileges as u32),
        rank: row.rank as i32,
        color: row.color,
    })
}

pub struct RoleManager {
    pool: SqlitePool,
}

impl RoleManager {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        name: &str,
        privileges: Privileges,
        rank: i32,
        color: Option<&str>,
    ) -> Result<Role, RoleError> {
        let row = storage::create(&self.pool, name, privileges.bits() as i64, rank as i64, color).await?;
        from_row(row)
    }

    pub async fn list(&self) -> Result<Vec<Role>, RoleError> {
        storage::all(&self.pool)
            .await?
            .into_iter()
            .map(from_row)
            .collect()
    }

    pub async fn update(
        &self,
        id: Uuid,
        name: &str,
        privileges: Privileges,
        rank: i32,
        color: Option<&str>,
    ) -> Result<(), RoleError> {
        storage::update(
            &self.pool,
            &id.to_string(),
            name,
            privileges.bits() as i64,
            rank as i64,
            color,
        )
        .await?;
        Ok(())
    }

    pub async fn delete(&self, id: Uuid) -> Result<(), RoleError> {
        storage::delete(&self.pool, &id.to_string()).await?;
        Ok(())
    }

    pub async fn assign(&self, account_id: &str, role_id: Uuid) -> Result<(), RoleError> {
        storage::assign(&self.pool, account_id, &role_id.to_string()).await?;
        Ok(())
    }

    pub async fn unassign(&self, account_id: &str, role_id: Uuid) -> Result<(), RoleError> {
        storage::unassign(&self.pool, account_id, &role_id.to_string()).await?;
        Ok(())
    }

    pub async fn for_account(&self, account_id: &str) -> Result<Vec<Role>, RoleError> {
        storage::for_account(&self.pool, account_id)
            .await?
            .into_iter()
            .map(from_row)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> (SqlitePool, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = kdx_storage::connect(&dir.path().join("test.db"))
            .await
            .unwrap();
        (pool, dir)
    }

    #[tokio::test]
    async fn create_assign_and_read_back_privileges() {
        let (pool, _dir) = pool().await;
        let account = kdx_storage::accounts::create(&pool, "phraq", "phc", 1)
            .await
            .unwrap();
        let mgr = RoleManager::new(pool);

        let role = mgr
            .create("Moderator", Privileges::USER_KICK | Privileges::USER_BAN, 10, Some("#e11b1b"))
            .await
            .unwrap();
        mgr.assign(&account.id, role.id).await.unwrap();

        let assigned = mgr.for_account(&account.id).await.unwrap();
        assert_eq!(assigned.len(), 1);
        assert!(assigned[0].privileges.contains(Privileges::USER_KICK));
        assert!(assigned[0].privileges.contains(Privileges::USER_BAN));
    }

    #[tokio::test]
    async fn update_changes_privileges_and_rank() {
        let pool = pool().await;
        let mgr = RoleManager::new(pool);
        let role = mgr.create("VIP", Privileges::CHAT_PRIVATE, 1, None).await.unwrap();

        mgr.update(role.id, "VIP+", Privileges::CHAT_PRIVATE | Privileges::FILE_UPLOAD, 2, Some("#3df56e"))
            .await
            .unwrap();

        let roles = mgr.list().await.unwrap();
        assert_eq!(roles[0].name, "VIP+");
        assert!(roles[0].privileges.contains(Privileges::FILE_UPLOAD));
        assert_eq!(roles[0].rank, 2);
    }

    #[tokio::test]
    async fn unassign_removes_role_from_account() {
        let pool = pool().await;
        let account = kdx_storage::accounts::create(&pool, "acidburn", "phc", 1)
            .await
            .unwrap();
        let mgr = RoleManager::new(pool);
        let role = mgr.create("VIP", Privileges::CHAT_PRIVATE, 1, None).await.unwrap();

        mgr.assign(&account.id, role.id).await.unwrap();
        mgr.unassign(&account.id, role.id).await.unwrap();
        assert!(mgr.for_account(&account.id).await.unwrap().is_empty());
    }
}
