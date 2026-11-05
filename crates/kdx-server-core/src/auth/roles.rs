//! Custom, named privilege bundles a SysOp can define and assign to
//! accounts on top of their base class — the Discord-style "roles" layer.
//! A role's privilege bits are unioned into the class's set at login (see
//! [`super::manager::AuthManager::complete`]); per-account grant/revoke
//! overrides still apply on top and revokes still win.
//!
//! `RoleManager` also answers the stored-privilege questions the admin
//! policy ([`super::policy`]) needs — an account's current class and
//! effective privileges, who holds a role, how many administrators remain —
//! records ranked bans, and owns the lock that serializes privilege
//! mutations so those checks can't race each other.

use kdx_storage::roles as storage;
use kdx_storage::SqlitePool;
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

use super::classes::{BaseClass, Privileges};
use super::policy::{AccountState, ADMIN_CORE};

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

/// A stored class value as a `BaseClass`. Out-of-range values (which can't
/// log in anyway) read as Admin, the conservative choice for rank checks.
fn class_from_stored(value: i64) -> BaseClass {
    BaseClass::try_from(value.clamp(0, 3) as u8).unwrap_or(BaseClass::Admin)
}

/// A ban in force, with the class of whoever set it (who may lift it
/// depends on that; see [`super::policy::may_lift_ban`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanRecord {
    /// The banned account.
    pub username: String,
    /// Unix seconds; in force while `now < until`.
    pub until: i64,
    pub reason: String,
    pub banned_by: String,
    pub banned_by_class: BaseClass,
}

/// What [`RoleManager::remove_ban`] did. The record's `username` is the
/// account the caller named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanRemoval {
    /// The ban was in force and has been lifted.
    Removed(BanRecord),
    /// No ban in force on that account.
    NotBanned,
    /// The ban is in force but the rank check refused to lift it.
    Refused(BanRecord),
}

pub struct RoleManager {
    pool: SqlitePool,
    /// Held across check-then-write for every account/role/ban mutation.
    mutations: Mutex<()>,
}

impl RoleManager {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            mutations: Mutex::new(()),
        }
    }

    /// Serialize a privilege mutation: hold the guard from the policy checks
    /// through the write, so two admins can't each pass a check (say, "not
    /// the last admin") that their combined changes violate.
    pub async fn lock_mutations(&self) -> MutexGuard<'_, ()> {
        self.mutations.lock().await
    }

    /// One role by id, or `None`.
    pub async fn get(&self, id: Uuid) -> Result<Option<Role>, RoleError> {
        storage::by_id(&self.pool, &id.to_string())
            .await?
            .map(from_row)
            .transpose()
    }

    async fn account_state_from_row(
        &self,
        row: storage::AccountPrivilegeRow,
    ) -> Result<AccountState, RoleError> {
        let role_privileges = storage::for_account(&self.pool, &row.id)
            .await?
            .iter()
            .fold(Privileges::empty(), |acc, r| {
                acc | Privileges::from_bits_truncate(r.privileges as u32)
            });
        Ok(AccountState {
            account_id: row.id,
            username: row.username,
            class: class_from_stored(row.base_class),
            granted: row.granted as u32,
            revoked: row.revoked as u32,
            role_privileges,
        })
    }

    /// An account's stored class, overrides and role privileges, or `None`
    /// if there's no such account.
    pub async fn account_state(&self, username: &str) -> Result<Option<AccountState>, RoleError> {
        match storage::account_privileges(&self.pool, username).await? {
            Some(row) => Ok(Some(self.account_state_from_row(row).await?)),
            None => Ok(None),
        }
    }

    /// The current state of every account holding a role.
    pub async fn holders(&self, role_id: Uuid) -> Result<Vec<AccountState>, RoleError> {
        let rows = storage::holders(&self.pool, &role_id.to_string()).await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(self.account_state_from_row(row).await?);
        }
        Ok(out)
    }

    /// How many accounts other than `username` can still administer the
    /// server (Admin class with neither USER_ADMIN nor SERVER_ADMIN revoked).
    pub async fn other_administrators(&self, username: &str) -> Result<i64, RoleError> {
        Ok(storage::count_administrators(&self.pool, ADMIN_CORE.bits() as i64, username).await?)
    }

    /// Record a ban set by an account of class `banned_by`, keeping any
    /// longer ban a higher rank already set (see
    /// [`kdx_storage::bans::set_ranked`]). Returns the expiry now in force.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_ban(
        &self,
        account_id: &str,
        until: i64,
        reason: &str,
        banned_by: &str,
        banned_by_class: BaseClass,
        now: i64,
    ) -> Result<i64, RoleError> {
        Ok(kdx_storage::bans::set_ranked(
            &self.pool,
            account_id,
            until,
            reason,
            banned_by,
            banned_by_class as i64,
            now,
        )
        .await?)
    }

    /// The bans in force at `now`, longest-lasting first, at most `limit`
    /// of them, plus how many are in force altogether.
    pub async fn active_bans(&self, now: i64, limit: u32) -> Result<(Vec<BanRecord>, u64), RoleError> {
        let (rows, total) = kdx_storage::bans::list_active(&self.pool, now, limit as i64).await?;
        let bans = rows
            .into_iter()
            .map(|r| BanRecord {
                username: r.username,
                until: r.until,
                reason: r.reason,
                banned_by: r.banned_by,
                banned_by_class: class_from_stored(r.banned_by_class),
            })
            .collect();
        Ok((bans, total.max(0) as u64))
    }

    /// Lift the ban in force on `username`'s account (`account_id`) if
    /// `allow(banned_by, banned_by_class)` accepts it; the check and the
    /// delete are atomic (see [`kdx_storage::bans::remove_if`]).
    pub async fn remove_ban<F>(
        &self,
        account_id: &str,
        username: &str,
        now: i64,
        allow: F,
    ) -> Result<BanRemoval, RoleError>
    where
        F: FnOnce(&str, BaseClass) -> bool + Send,
    {
        use kdx_storage::bans::{RankedBan, Removal};
        let record = |ban: RankedBan| BanRecord {
            username: username.to_owned(),
            until: ban.until,
            reason: ban.reason,
            banned_by: ban.banned_by,
            banned_by_class: class_from_stored(ban.banned_by_class),
        };
        let removal = kdx_storage::bans::remove_if(&self.pool, account_id, now, |ban| {
            allow(&ban.banned_by, class_from_stored(ban.banned_by_class))
        })
        .await?;
        Ok(match removal {
            Removal::Removed(ban) => BanRemoval::Removed(record(ban)),
            Removal::NotBanned => BanRemoval::NotBanned,
            Removal::Refused(ban) => BanRemoval::Refused(record(ban)),
        })
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
        let account = kdx_storage::accounts::create(&pool, "phraq", "phc", 1, 0, 0)
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
        let (pool, _dir) = pool().await;
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
        let (pool, _dir) = pool().await;
        let account = kdx_storage::accounts::create(&pool, "acidburn", "phc", 1, 0, 0)
            .await
            .unwrap();
        let mgr = RoleManager::new(pool);
        let role = mgr.create("VIP", Privileges::CHAT_PRIVATE, 1, None).await.unwrap();

        mgr.assign(&account.id, role.id).await.unwrap();
        mgr.unassign(&account.id, role.id).await.unwrap();
        assert!(mgr.for_account(&account.id).await.unwrap().is_empty());
    }
}
