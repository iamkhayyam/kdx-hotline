//! Admin authorization policy: who may change whose class, privilege
//! overrides and roles (AUTH-1 / AUTHZ-1), and the glue that applies an
//! account or role mutation under that policy and then forces every affected
//! live session to reconnect with its new privileges (AUTHZ-2 / AUTH-5).
//!
//! The rules, for an actor holding USER_ADMIN:
//! - **Rank.** A non-Admin actor may only act on accounts of strictly lower
//!   class, and may only assign classes strictly below its own. An Admin may
//!   act on any account, Admins included. Either way the target's current
//!   effective privileges must be a subset of the actor's: nobody manages an
//!   account that can do things they can't.
//! - **No minting power.** Granted bits, the privileges an account ends up
//!   with from its class and overrides, and a role's privileges must all be a
//!   subset of the actor's own. (The actor picks the password on
//!   AccountCreate, so anything looser would let them mint a stronger puppet.)
//! - **No self-escalation.** Editing your own account may only take class or
//!   privileges away.
//! - **Roles.** A role may be created, edited, deleted, assigned or unassigned
//!   only if the actor could grant every privilege it carries (before and
//!   after the edit), and only when each account whose privileges would change
//!   (the target, or every holder) is one the actor may manage.
//! - **Last admin.** No change may leave the server without an Admin-class
//!   account that still holds both USER_ADMIN and SERVER_ADMIN.
//!
//! The actor's authority is the login snapshot narrowed by the stored account
//! (lower class, intersected privileges): a demotion bites these checks at
//! once, even before the demoted session is kicked, while a promotion waits
//! for a fresh login.

use std::fmt::Display;

use kdx_protocol::messages::{AccountCreate, AccountUpdate, RoleCreate, RoleUpdate};
use kdx_storage::StorageError;
use uuid::Uuid;

use super::classes::{effective_privileges, BaseClass, Privileges};
use super::manager::{AuthError, Session};
use super::roles::RoleError;
use crate::connection::ServerCtx;
use crate::limits;

/// The privileges that make an account an administrator for the last-admin
/// guard: without both, nobody could repair accounts or the server remotely.
pub const ADMIN_CORE: Privileges = Privileges::USER_ADMIN.union(Privileges::SERVER_ADMIN);

/// Disconnect reason sent to a live session whose privileges just changed.
pub const PRIVILEGES_CHANGED: &str = "your privileges changed — please reconnect";

/// Keep only privilege bits that are defined today, so junk bits stored in
/// an override can't silently become a grant when a new privilege is added.
pub fn known_bits(bits: u32) -> u32 {
    bits & Privileges::all().bits()
}

/// Why the policy refused a mutation. The text is safe to show the client.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Denied {
    #[error("missing {0} privilege")]
    Missing(&'static str),
    #[error("your account no longer exists")]
    ActorGone,
    #[error("invalid class (must be 0-3)")]
    InvalidClass,
    #[error("you can only assign classes below your own")]
    ClassTooHigh,
    #[error("you cannot grant privileges you do not hold yourself")]
    ExceedsOwnPrivileges,
    #[error("that account is at or above your rank, or has privileges you lack")]
    TargetOutranks,
    #[error("that role is held by an account at or above your rank, or with privileges you lack")]
    HolderOutranks,
    #[error("you cannot raise your own class or privileges")]
    SelfEscalation,
    #[error("refusing: this would leave the server without an administrator")]
    LastAdmin,
}

/// A failed admin request, split by what the client may see.
#[derive(Debug)]
pub enum Refusal {
    /// A message safe to send to the client as-is.
    Denied(String),
    /// An internal failure: log `detail` server-side and tell the client only
    /// that `what` failed (STORE-9: no SQL text or paths on the wire).
    Internal { what: &'static str, detail: String },
}

impl From<Denied> for Refusal {
    fn from(denied: Denied) -> Self {
        Refusal::Denied(denied.to_string())
    }
}

impl Refusal {
    pub fn denied(message: impl Into<String>) -> Self {
        Refusal::Denied(message.into())
    }

    pub fn internal(what: &'static str, err: impl Display) -> Self {
        Refusal::Internal {
            what,
            detail: err.to_string(),
        }
    }

    /// Map a storage error: a uniqueness violation becomes `exists`, a
    /// foreign-key violation or missing row becomes `missing`, anything else
    /// is internal.
    pub fn storage(what: &'static str, err: &StorageError, exists: &str, missing: &str) -> Self {
        match storage_fault(err) {
            StorageFault::AlreadyExists => Refusal::denied(exists),
            StorageFault::Missing => Refusal::denied(missing),
            StorageFault::Internal => Refusal::internal(what, err),
        }
    }

    pub fn role(what: &'static str, err: RoleError, exists: &str, missing: &str) -> Self {
        match err {
            RoleError::Storage(e) => Refusal::storage(what, &e, exists, missing),
            other => Refusal::internal(what, other),
        }
    }

    pub fn auth(what: &'static str, err: AuthError, missing: &str) -> Self {
        match err {
            AuthError::AccountExists => Refusal::denied(err.to_string()),
            AuthError::Storage(e) => Refusal::storage(
                what,
                &e,
                "an account with that name already exists",
                missing,
            ),
            other => Refusal::internal(what, other),
        }
    }

    /// The message to send the client.
    pub fn client_message(&self) -> String {
        match self {
            Refusal::Denied(message) => message.clone(),
            Refusal::Internal { what, .. } => format!("{what} failed: internal server error"),
        }
    }
}

/// How a storage error should surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageFault {
    AlreadyExists,
    Missing,
    Internal,
}

pub fn storage_fault(err: &StorageError) -> StorageFault {
    match err {
        StorageError::NotFound | StorageError::ForeignKey => StorageFault::Missing,
        StorageError::AlreadyExists => StorageFault::AlreadyExists,
        StorageError::Sqlx(e) => match e.as_database_error() {
            Some(db) if db.is_unique_violation() => StorageFault::AlreadyExists,
            Some(db) if db.is_foreign_key_violation() => StorageFault::Missing,
            _ => StorageFault::Internal,
        },
        _ => StorageFault::Internal,
    }
}

/// A class plus effective privileges: what an account can do, for rank
/// comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authority {
    pub class: BaseClass,
    pub privileges: Privileges,
}

impl Authority {
    /// Whether this authority may change `target`'s class, overrides or
    /// roles: Admins may act on anyone, others only on strictly lower
    /// classes, and never on an account holding privileges they lack.
    pub fn may_manage(&self, target: &Authority) -> bool {
        let rank_ok = self.class == BaseClass::Admin || target.class < self.class;
        rank_ok && self.privileges.contains(target.privileges)
    }
}

/// An account's stored, privilege-relevant state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountState {
    pub account_id: String,
    pub username: String,
    pub class: BaseClass,
    pub granted: u32,
    pub revoked: u32,
    /// Union of the privileges of every role the account holds.
    pub role_privileges: Privileges,
}

impl AccountState {
    pub fn effective(&self) -> Privileges {
        effective_privileges(self.class, self.role_privileges, self.granted, self.revoked)
    }

    pub fn authority(&self) -> Authority {
        Authority {
            class: self.class,
            privileges: self.effective(),
        }
    }

    /// Admin class and still holding every [`ADMIN_CORE`] privilege.
    pub fn administers(&self) -> bool {
        self.class == BaseClass::Admin && self.effective().contains(ADMIN_CORE)
    }

    /// This account with a new class and overrides (same roles).
    pub fn with_overrides(&self, class: BaseClass, granted: u32, revoked: u32) -> Self {
        AccountState {
            class,
            granted,
            revoked,
            ..self.clone()
        }
    }
}

/// The account performing an admin request.
#[derive(Debug, Clone)]
pub struct Actor {
    pub username: String,
    pub authority: Authority,
}

impl Actor {
    /// The login snapshot narrowed by the stored account: the lower class
    /// and the intersection of privileges.
    pub fn narrowed(session: &Session, stored: &AccountState) -> Self {
        Actor {
            username: session.username.clone(),
            authority: Authority {
                class: session.class.min(stored.class),
                privileges: session.privileges & stored.effective(),
            },
        }
    }
}

/// Validate a class the actor wants to give an account.
pub fn check_assignable_class(actor: &Authority, class: u8) -> Result<BaseClass, Denied> {
    let class = BaseClass::try_from(class).map_err(|_| Denied::InvalidClass)?;
    if actor.class != BaseClass::Admin && class >= actor.class {
        return Err(Denied::ClassTooHigh);
    }
    Ok(class)
}

/// The granted bits, and everything an account gets from `class` plus the
/// overrides, must be privileges the actor holds.
pub fn check_overrides(actor: &Authority, class: BaseClass, granted: u32, revoked: u32) -> Result<(), Denied> {
    let granted_bits = Privileges::from_bits_truncate(granted);
    let resulting = effective_privileges(class, Privileges::empty(), granted, revoked);
    if !actor.privileges.contains(granted_bits | resulting) {
        return Err(Denied::ExceedsOwnPrivileges);
    }
    Ok(())
}

/// AccountCreate: returns the validated class.
pub fn check_account_create(actor: &Authority, class: u8, granted: u32, revoked: u32) -> Result<BaseClass, Denied> {
    let class = check_assignable_class(actor, class)?;
    check_overrides(actor, class, granted, revoked)?;
    Ok(class)
}

/// AccountUpdate of `target` (its current stored state): returns the
/// validated class. The last-admin guard needs a database count and is
/// applied separately (see [`removes_administrator`]).
pub fn check_account_update(
    actor: &Actor,
    target: &AccountState,
    class: u8,
    granted: u32,
    revoked: u32,
) -> Result<BaseClass, Denied> {
    if !actor.authority.may_manage(&target.authority()) {
        return Err(Denied::TargetOutranks);
    }
    let class = check_assignable_class(&actor.authority, class)?;
    check_overrides(&actor.authority, class, granted, revoked)?;
    if target.username == actor.username {
        let after = target.with_overrides(class, granted, revoked);
        if class > target.class || !target.effective().contains(after.effective()) {
            return Err(Denied::SelfEscalation);
        }
    }
    Ok(class)
}

/// A role's privileges must all be ones the actor could grant.
pub fn check_role_privileges(actor: &Authority, role: Privileges) -> Result<(), Denied> {
    if actor.privileges.contains(role) {
        Ok(())
    } else {
        Err(Denied::ExceedsOwnPrivileges)
    }
}

/// Every account a role change would affect must be one the actor manages.
pub fn check_role_holders(actor: &Authority, holders: &[AccountState]) -> Result<(), Denied> {
    if holders.iter().all(|h| actor.may_manage(&h.authority())) {
        Ok(())
    } else {
        Err(Denied::HolderOutranks)
    }
}

/// Whether going from `before` to `after` takes away an administrator.
pub fn removes_administrator(before: &AccountState, after: &AccountState) -> bool {
    before.administers() && !after.administers()
}

/// Whether a live session of this account would now hold stale privileges.
pub fn privileges_changed(before: &AccountState, after: &AccountState) -> bool {
    before.class != after.class || before.effective() != after.effective()
}

/// Validate RoleCreate / RoleUpdate text fields.
pub fn validate_role_fields(name: &str, color: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("role name is required".into());
    }
    limits::check_len("role name", name, limits::MAX_NAME_LEN)?;
    if !color.is_empty() && !is_hex_color(color) {
        return Err("role color must be a hex value like #e11b1b".into());
    }
    Ok(())
}

fn is_hex_color(s: &str) -> bool {
    let Some(hex) = s.strip_prefix('#') else {
        return false;
    };
    matches!(hex.len(), 3 | 4 | 6 | 8) && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

fn privilege_name(required: Privileges) -> &'static str {
    required.iter_names().next().map(|(name, _)| name).unwrap_or("required")
}

/// Resolve the acting session's current authority (see the module docs)
/// and require `required` of it.
pub async fn resolve_actor(ctx: &ServerCtx, session: &Session, required: Privileges) -> Result<Actor, Refusal> {
    let missing = Denied::Missing(privilege_name(required));
    if !session.privileges.contains(required) {
        return Err(missing.into());
    }
    let stored = ctx
        .roles
        .account_state(&session.username)
        .await
        .map_err(|e| Refusal::internal("permission check", e))?
        .ok_or(Denied::ActorGone)?;
    let actor = Actor::narrowed(session, &stored);
    if !actor.authority.privileges.contains(required) {
        return Err(missing.into());
    }
    Ok(actor)
}

/// After a mutation, re-read each affected account and force off the live
/// sessions of every one whose class or effective privileges changed (or
/// that can no longer be read), so nobody keeps acting on stale privileges.
async fn kick_changed(ctx: &ServerCtx, before: Vec<AccountState>) {
    for old in before {
        let changed = match ctx.roles.account_state(&old.username).await {
            Ok(Some(new)) => privileges_changed(&old, &new),
            Ok(None) | Err(_) => true,
        };
        if changed {
            ctx.presence.disconnect(&old.username, PRIVILEGES_CHANGED).await;
        }
    }
}

/// Look up a role for a mutation, `Denied("no such role")` if absent.
async fn existing_role(ctx: &ServerCtx, what: &'static str, id: Uuid) -> Result<super::Role, Refusal> {
    ctx.roles
        .get(id)
        .await
        .map_err(|e| Refusal::role(what, e, "", "no such role"))?
        .ok_or_else(|| Refusal::denied("no such role"))
}

/// Look up an account for a mutation, `Denied("no such account")` if absent.
async fn existing_account(ctx: &ServerCtx, what: &'static str, username: &str) -> Result<AccountState, Refusal> {
    ctx.roles
        .account_state(username)
        .await
        .map_err(|e| Refusal::role(what, e, "", "no such account"))?
        .ok_or_else(|| Refusal::denied("no such account"))
}

fn role_exists_message(name: &str) -> String {
    format!("a role named \"{name}\" already exists")
}

/// AccountCreate under the policy.
pub async fn create_account(ctx: &ServerCtx, session: &Session, req: &AccountCreate) -> Result<(), Refusal> {
    const WHAT: &str = "account create";
    if req.username.is_empty() || req.password.is_empty() {
        return Err(Refusal::denied("username and password are required"));
    }
    limits::check_len("username", &req.username, limits::MAX_USERNAME_LEN).map_err(Refusal::denied)?;
    let _guard = ctx.roles.lock_mutations().await;
    let actor = resolve_actor(ctx, session, Privileges::USER_ADMIN).await?;
    let class = check_account_create(&actor.authority, req.base_class, req.granted, req.revoked)?;
    ctx.auth
        .create_account(
            &req.username,
            &req.password,
            class as i64,
            known_bits(req.granted) as i64,
            known_bits(req.revoked) as i64,
        )
        .await
        .map_err(|e| Refusal::auth(WHAT, e, "no such account"))
}

/// AccountUpdate under the policy; kicks the target's live sessions if its
/// class or privileges changed.
pub async fn update_account(ctx: &ServerCtx, session: &Session, req: &AccountUpdate) -> Result<(), Refusal> {
    const WHAT: &str = "account update";
    let _guard = ctx.roles.lock_mutations().await;
    let actor = resolve_actor(ctx, session, Privileges::USER_ADMIN).await?;
    let target = existing_account(ctx, WHAT, &req.username).await?;
    let class = check_account_update(&actor, &target, req.base_class, req.granted, req.revoked)?;
    let after = target.with_overrides(class, known_bits(req.granted), known_bits(req.revoked));
    if removes_administrator(&target, &after) {
        let others = ctx
            .roles
            .other_administrators(&target.username)
            .await
            .map_err(|e| Refusal::internal(WHAT, e))?;
        if others == 0 {
            return Err(Denied::LastAdmin.into());
        }
    }
    ctx.auth
        .update_account(
            &req.username,
            class as i64,
            after.granted as i64,
            after.revoked as i64,
        )
        .await
        .map_err(|e| Refusal::auth(WHAT, e, "no such account"))?;
    kick_changed(ctx, vec![target]).await;
    Ok(())
}

/// RoleCreate under the policy.
pub async fn create_role(ctx: &ServerCtx, session: &Session, req: &RoleCreate) -> Result<(), Refusal> {
    const WHAT: &str = "role create";
    validate_role_fields(&req.name, &req.color).map_err(Refusal::denied)?;
    let privileges = Privileges::from_bits_truncate(req.privileges);
    let _guard = ctx.roles.lock_mutations().await;
    let actor = resolve_actor(ctx, session, Privileges::USER_ADMIN).await?;
    check_role_privileges(&actor.authority, privileges)?;
    let color = (!req.color.is_empty()).then_some(req.color.as_str());
    ctx.roles
        .create(&req.name, privileges, req.rank, color)
        .await
        .map_err(|e| Refusal::role(WHAT, e, &role_exists_message(&req.name), "no such role"))?;
    Ok(())
}

/// RoleUpdate under the policy; kicks holders whose privileges changed.
pub async fn update_role(ctx: &ServerCtx, session: &Session, req: &RoleUpdate) -> Result<(), Refusal> {
    const WHAT: &str = "role update";
    validate_role_fields(&req.name, &req.color).map_err(Refusal::denied)?;
    let id = Uuid::from_bytes(req.id);
    let privileges = Privileges::from_bits_truncate(req.privileges);
    let _guard = ctx.roles.lock_mutations().await;
    let actor = resolve_actor(ctx, session, Privileges::USER_ADMIN).await?;
    let role = existing_role(ctx, WHAT, id).await?;
    check_role_privileges(&actor.authority, role.privileges | privileges)?;
    let holders = ctx
        .roles
        .holders(id)
        .await
        .map_err(|e| Refusal::internal(WHAT, e))?;
    check_role_holders(&actor.authority, &holders)?;
    let color = (!req.color.is_empty()).then_some(req.color.as_str());
    ctx.roles
        .update(id, &req.name, privileges, req.rank, color)
        .await
        .map_err(|e| Refusal::role(WHAT, e, &role_exists_message(&req.name), "no such role"))?;
    if role.privileges != privileges {
        kick_changed(ctx, holders).await;
    }
    Ok(())
}

/// RoleDelete under the policy; kicks holders whose privileges changed.
pub async fn delete_role(ctx: &ServerCtx, session: &Session, id: Uuid) -> Result<(), Refusal> {
    const WHAT: &str = "role delete";
    let _guard = ctx.roles.lock_mutations().await;
    let actor = resolve_actor(ctx, session, Privileges::USER_ADMIN).await?;
    let role = existing_role(ctx, WHAT, id).await?;
    check_role_privileges(&actor.authority, role.privileges)?;
    let holders = ctx
        .roles
        .holders(id)
        .await
        .map_err(|e| Refusal::internal(WHAT, e))?;
    check_role_holders(&actor.authority, &holders)?;
    ctx.roles
        .delete(id)
        .await
        .map_err(|e| Refusal::role(WHAT, e, "", "no such role"))?;
    kick_changed(ctx, holders).await;
    Ok(())
}

/// RoleAssign (`assign = true`) or RoleUnassign under the policy; kicks the
/// target if its privileges changed.
pub async fn set_role_assignment(
    ctx: &ServerCtx,
    session: &Session,
    username: &str,
    role_id: Uuid,
    assign: bool,
) -> Result<(), Refusal> {
    let what = if assign { "role assign" } else { "role unassign" };
    let _guard = ctx.roles.lock_mutations().await;
    let actor = resolve_actor(ctx, session, Privileges::USER_ADMIN).await?;
    let role = existing_role(ctx, what, role_id).await?;
    let target = existing_account(ctx, what, username).await?;
    check_role_privileges(&actor.authority, role.privileges)?;
    if !actor.authority.may_manage(&target.authority()) {
        return Err(Denied::TargetOutranks.into());
    }
    let result = if assign {
        ctx.roles.assign(&target.account_id, role_id).await
    } else {
        ctx.roles.unassign(&target.account_id, role_id).await
    };
    result.map_err(|e| Refusal::role(what, e, "", "no such role or account"))?;
    kick_changed(ctx, vec![target]).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(username: &str, class: BaseClass, granted: Privileges, revoked: Privileges) -> AccountState {
        AccountState {
            account_id: format!("id-{username}"),
            username: username.into(),
            class,
            granted: granted.bits(),
            revoked: revoked.bits(),
            role_privileges: Privileges::empty(),
        }
    }

    fn actor_of(s: &AccountState) -> Actor {
        Actor {
            username: s.username.clone(),
            authority: s.authority(),
        }
    }

    /// A PowerUser delegated USER_ADMIN.
    fn helpdesk() -> AccountState {
        state("helpdesk", BaseClass::PowerUser, Privileges::USER_ADMIN, Privileges::empty())
    }

    fn sysop() -> AccountState {
        state("sysop", BaseClass::Admin, Privileges::empty(), Privileges::empty())
    }

    #[test]
    fn delegated_admin_cannot_grant_itself_more() {
        let me = helpdesk();
        let all = Privileges::all().bits();
        // Self-edit at all is refused for non-admins (same rank)...
        assert_eq!(
            check_account_update(&actor_of(&me), &me, 2, all, 0),
            Err(Denied::TargetOutranks)
        );
    }

    #[test]
    fn admin_self_edit_may_only_remove() {
        let mut me = sysop();
        me.revoked = Privileges::FILE_DELETE.bits();
        let actor = actor_of(&me);
        // Un-revoking one's own bit is escalation (caught as exceeding own privileges).
        assert!(check_account_update(&actor, &me, 3, 0, 0).is_err());
        // Revoking more is fine.
        let more = (Privileges::FILE_DELETE | Privileges::FILE_UPLOAD).bits();
        assert_eq!(check_account_update(&actor, &me, 3, 0, more), Ok(BaseClass::Admin));
    }

    #[test]
    fn delegated_admin_cannot_touch_admins_or_peers() {
        let actor = actor_of(&helpdesk());
        assert_eq!(
            check_account_update(&actor, &sysop(), 0, 0, Privileges::all().bits()),
            Err(Denied::TargetOutranks)
        );
        let peer = state("peer", BaseClass::PowerUser, Privileges::empty(), Privileges::empty());
        assert_eq!(check_account_update(&actor, &peer, 1, 0, 0), Err(Denied::TargetOutranks));
    }

    #[test]
    fn delegated_admin_manages_lower_accounts_within_its_own_privileges() {
        let actor = actor_of(&helpdesk());
        let user = state("user", BaseClass::User, Privileges::empty(), Privileges::empty());
        // Demote / tweak within bounds: fine.
        assert_eq!(
            check_account_update(&actor, &user, 0, Privileges::CHAT_PRIVATE.bits(), 0),
            Ok(BaseClass::Guest)
        );
        // Raise to its own class or above: refused.
        assert_eq!(check_account_update(&actor, &user, 2, 0, 0), Err(Denied::ClassTooHigh));
        // Grant something it lacks: refused.
        assert_eq!(
            check_account_update(&actor, &user, 1, Privileges::SERVER_ADMIN.bits(), 0),
            Err(Denied::ExceedsOwnPrivileges)
        );
        // A lower-class account holding privileges the actor lacks is off limits.
        let kicker = state("kicker", BaseClass::User, Privileges::USER_KICK, Privileges::empty());
        assert_eq!(check_account_update(&actor, &kicker, 1, 0, 0), Err(Denied::TargetOutranks));
    }

    #[test]
    fn create_cannot_mint_a_stronger_puppet() {
        let mut me = helpdesk();
        me.revoked = Privileges::FILE_UPLOAD.bits();
        let actor = me.authority();
        assert_eq!(check_account_create(&actor, 3, 0, 0), Err(Denied::ClassTooHigh));
        assert_eq!(check_account_create(&actor, 9, 0, 0), Err(Denied::InvalidClass));
        assert_eq!(
            check_account_create(&actor, 1, Privileges::USER_BAN.bits(), 0),
            Err(Denied::ExceedsOwnPrivileges)
        );
        // A User gets FILE_UPLOAD from its class, which this actor lacks...
        assert_eq!(check_account_create(&actor, 1, 0, 0), Err(Denied::ExceedsOwnPrivileges));
        // ...unless it's revoked on the new account.
        assert_eq!(
            check_account_create(&actor, 1, 0, Privileges::FILE_UPLOAD.bits()),
            Ok(BaseClass::User)
        );
    }

    #[test]
    fn admins_may_manage_admins_unless_less_privileged() {
        let full = sysop();
        let other = state("other", BaseClass::Admin, Privileges::empty(), Privileges::empty());
        assert_eq!(check_account_update(&actor_of(&full), &other, 0, 0, 0), Ok(BaseClass::Guest));
        let mut limited = sysop();
        limited.revoked = Privileges::SERVER_ADMIN.bits();
        assert_eq!(
            check_account_update(&actor_of(&limited), &other, 0, 0, 0),
            Err(Denied::TargetOutranks)
        );
    }

    #[test]
    fn role_rules() {
        let actor = helpdesk().authority();
        assert!(check_role_privileges(&actor, Privileges::USER_ADMIN | Privileges::CHAT_SEND).is_ok());
        assert_eq!(
            check_role_privileges(&actor, Privileges::SERVER_ADMIN),
            Err(Denied::ExceedsOwnPrivileges)
        );
        let user = state("user", BaseClass::User, Privileges::empty(), Privileges::empty());
        assert!(check_role_holders(&actor, std::slice::from_ref(&user)).is_ok());
        assert_eq!(check_role_holders(&actor, &[user, sysop()]), Err(Denied::HolderOutranks));
    }

    #[test]
    fn administrator_detection() {
        let admin = sysop();
        assert!(admin.administers());
        let demoted = admin.with_overrides(BaseClass::PowerUser, 0, 0);
        assert!(removes_administrator(&admin, &demoted));
        let stripped = admin.with_overrides(BaseClass::Admin, 0, Privileges::USER_ADMIN.bits());
        assert!(removes_administrator(&admin, &stripped));
        let harmless = admin.with_overrides(BaseClass::Admin, 0, Privileges::FILE_DELETE.bits());
        assert!(!removes_administrator(&admin, &harmless));
        assert!(privileges_changed(&admin, &harmless));
        assert!(!privileges_changed(&admin, &admin.clone()));
    }

    #[test]
    fn role_field_validation() {
        assert!(validate_role_fields("Mod", "#e11b1b").is_ok());
        assert!(validate_role_fields("Mod", "").is_ok());
        assert!(validate_role_fields("Mod", "#abc").is_ok());
        assert!(validate_role_fields("", "").is_err());
        assert!(validate_role_fields("Mod", "red;background:url(x)").is_err());
        assert!(validate_role_fields(&"x".repeat(limits::MAX_NAME_LEN + 1), "").is_err());
    }
}
