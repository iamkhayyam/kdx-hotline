//! Folder access rules, converging on the original KDX access-item model.
//!
//! A folder can carry an **access item**, declared by a trailing name suffix
//! (`[db]`, `[ul]`, `[default]`, case-insensitive) — the authentic KDX
//! mechanism ("a folder opts in via `Name [item]`"):
//!
//! - `[default]` / no suffix — world-read, admin-write (class-gated).
//! - `[ul]` (uploads) — anyone with upload privilege may upload **and**
//!   download; only admins (`FILE_MANAGE_TREE`) may delete.
//! - `[db]` (dropbox) — write-only to everyone except the folder **owner**
//!   (optional owner login, P1-4) and admins; uploads are still allowed.
//!
//! Evaluation is privilege-aware: an account's effective privileges (base
//! class + roles + per-account granted/revoked overrides) are what matter,
//! so revoking `FILE_UPLOAD` on an account really does stop its uploads.

use super::tree::NodeKind;
use crate::auth::{BaseClass, Privileges};

/// The named access-item bundles a folder can opt into via its name suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessItem {
    /// No suffix (or explicit `[default]`): world-read, admin-write.
    #[default]
    Default,
    /// `[ul]`: anyone can upload+download; only admins can delete.
    Upload,
    /// `[db]`: write-only unless owner/admin; owner may read/delete.
    DropBox,
}

impl AccessItem {
    /// Parse the trailing `[tag]` suffix of a folder name. Anything else is
    /// [`AccessItem::Default`]. The suffix stays part of the displayed name
    /// (authentic KDX behavior — renaming the folder changes its item).
    pub fn parse(name: &str) -> AccessItem {
        let Some(open) = name.rfind('[') else {
            return AccessItem::Default;
        };
        if !name[open..].ends_with(']') {
            return AccessItem::Default;
        }
        let tag: String = name[open + 1..name.len() - 1].trim().to_ascii_lowercase();
        match tag.as_str() {
            "db" => AccessItem::DropBox,
            "ul" => AccessItem::Upload,
            "default" => AccessItem::Default,
            _ => AccessItem::Default,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AclError {
    #[error("drop boxes are write-only")]
    DropBoxIsWriteOnly,
    #[error("insufficient class for this folder")]
    ClassTooLow,
    #[error("missing {0} privilege")]
    PrivilegeRequired(&'static str),
    #[error("only the folder owner or an admin may do that")]
    OwnerOnly,
}

/// May `user` list/read the contents of a folder of `kind` with `item`
/// semantics? `min_read` is the class gate; `privs` the effective privileges.
pub fn check_read(
    kind: NodeKind,
    item: AccessItem,
    min_read: BaseClass,
    class: BaseClass,
    _privs: Privileges,
    owner: Option<&str>,
    user: &str,
) -> Result<(), AclError> {
    // Drop boxes are write-only structurally: kind DropBox or a [DB] folder.
    if kind == NodeKind::DropBox || item == AccessItem::DropBox {
        if class >= BaseClass::Admin {
            return Ok(()); // admins see everything
        }
        if owner.map_or(false, |o| o == user) {
            return Ok(()); // the owner may read their own drop box
        }
        return Err(AclError::DropBoxIsWriteOnly);
    }
    if class < min_read {
        return Err(AclError::ClassTooLow);
    }
    Ok(())
}

/// May `user` upload into a folder? Class gate + the `FILE_UPLOAD` privilege
/// (so account overrides actually bite on the file tree).
pub fn check_write(
    _kind: NodeKind,
    _item: AccessItem,
    min_write: BaseClass,
    class: BaseClass,
    privs: Privileges,
) -> Result<(), AclError> {
    if class < min_write {
        return Err(AclError::ClassTooLow);
    }
    if !privs.contains(Privileges::FILE_UPLOAD) {
        return Err(AclError::PrivilegeRequired("upload"));
    }
    Ok(())
}

/// May `user` delete a node in a folder with `item` semantics? `[ul]` limits
/// deletion to admins; `[db]` to the owner or an admin.
pub fn check_delete(
    kind: NodeKind,
    item: AccessItem,
    min_write: BaseClass,
    class: BaseClass,
    privs: Privileges,
    owner: Option<&str>,
    user: &str,
) -> Result<(), AclError> {
    if kind == NodeKind::DropBox || item == AccessItem::DropBox {
        // owner or an admin-class account may delete inside a drop box
        if class >= BaseClass::Admin {
            return Ok(());
        }
        if owner.map_or(false, |o| o == user) {
            return Ok(());
        }
        return Err(AclError::OwnerOnly);
    }
    if item == AccessItem::Upload && class < BaseClass::Admin {
        // [UL]: "only admin delete" — the admin class specifically, not
        // merely the FILE_MANAGE_TREE privilege (power users hold that too).
        return Err(AclError::ClassTooLow);
    }
    if class < min_write {
        return Err(AclError::ClassTooLow);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_items_from_name_suffix() {
        assert_eq!(AccessItem::parse("Files"), AccessItem::Default);
        assert_eq!(AccessItem::parse("Movies [UL]"), AccessItem::Upload);
        assert_eq!(AccessItem::parse("inbox [db]"), AccessItem::DropBox);
        assert_eq!(AccessItem::parse("Docs [Default]"), AccessItem::Default);
        assert_eq!(AccessItem::parse("bracket[ed]"), AccessItem::Default); // not a known tag
        assert_eq!(AccessItem::parse("Stray ["), AccessItem::Default); // unterminated
    }

    #[test]
    fn default_folder_is_class_gated() {
        let ok = check_read(
            NodeKind::Directory,
            AccessItem::Default,
            BaseClass::User,
            BaseClass::User,
            Privileges::empty(),
            None,
            "alice",
        );
        assert!(ok.is_ok());
        let denied = check_read(
            NodeKind::Directory,
            AccessItem::Default,
            BaseClass::PowerUser,
            BaseClass::User,
            Privileges::empty(),
            None,
            "alice",
        );
        assert_eq!(denied, Err(AclError::ClassTooLow));
    }

    #[test]
    fn ul_folder_reads_anyone_but_delete_is_admin() {
        let user = BaseClass::User;
        let admin_privs = Privileges::FILE_MANAGE_TREE;
        // read ok for a user
        assert!(check_read(
            NodeKind::Directory,
            AccessItem::Upload,
            BaseClass::Guest,
            user,
            Privileges::empty(),
            None,
            "alice"
        )
        .is_ok());
        // upload ok (class gate + FILE_UPLOAD)
        assert!(check_write(
            NodeKind::Directory,
            AccessItem::Upload,
            BaseClass::Guest,
            user,
            Privileges::FILE_UPLOAD
        )
        .is_ok());
        // delete: power user denied (only the admin class may delete in [UL])
        assert_eq!(
            check_delete(
                NodeKind::Directory,
                AccessItem::Upload,
                BaseClass::Guest,
                BaseClass::PowerUser,
                Privileges::FILE_MANAGE_TREE,
                None,
                "alice"
            ),
            Err(AclError::ClassTooLow)
        );
        // admin ok
        assert!(check_delete(
            NodeKind::Directory,
            AccessItem::Upload,
            BaseClass::Guest,
            BaseClass::Admin,
            admin_privs,
            None,
            "alice"
        )
        .is_ok());
    }

    #[test]
    fn db_folder_is_write_only_except_owner_or_admin() {
        let guest = BaseClass::Guest;
        // stranger: denied
        assert_eq!(
            check_read(
                NodeKind::Directory,
                AccessItem::DropBox,
                BaseClass::Guest,
                guest,
                Privileges::empty(),
                Some("bob"),
                "alice"
            ),
            Err(AclError::DropBoxIsWriteOnly)
        );
        // owner: allowed
        assert!(check_read(
            NodeKind::Directory,
            AccessItem::DropBox,
            BaseClass::Guest,
            guest,
            Privileges::empty(),
            Some("bob"),
            "bob"
        )
        .is_ok());
        // admin: allowed
        assert!(check_read(
            NodeKind::Directory,
            AccessItem::DropBox,
            BaseClass::Guest,
            BaseClass::Admin,
            Privileges::empty(),
            Some("bob"),
            "alice"
        )
        .is_ok());
        // delete by owner ok, by stranger denied
        assert!(check_delete(
            NodeKind::Directory,
            AccessItem::DropBox,
            BaseClass::Guest,
            guest,
            Privileges::empty(),
            Some("bob"),
            "bob"
        )
        .is_ok());
        assert_eq!(
            check_delete(
                NodeKind::Directory,
                AccessItem::DropBox,
                BaseClass::Guest,
                guest,
                Privileges::empty(),
                Some("bob"),
                "alice"
            ),
            Err(AclError::OwnerOnly)
        );
    }

    #[test]
    fn revoked_upload_privilege_blocks_upload() {
        // power user class passes the class gate, but a revoked FILE_UPLOAD
        // override must stop the upload.
        let power = BaseClass::PowerUser;
        let privs = Privileges::all() - Privileges::FILE_UPLOAD;
        assert_eq!(
            check_write(
                NodeKind::Directory,
                AccessItem::Default,
                BaseClass::Guest,
                power,
                privs
            ),
            Err(AclError::PrivilegeRequired("upload"))
        );
    }
}
