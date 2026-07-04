//! Folder access rules. DropBox write-only semantics are enforced here,
//! structurally, so no caller can accidentally list one.

use super::tree::NodeKind;
use crate::auth::BaseClass;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AclError {
    #[error("drop boxes are write-only")]
    DropBoxIsWriteOnly,
    #[error("insufficient class for this folder")]
    ClassTooLow,
}

/// May `class` list/read the contents of a folder?
pub fn check_list(kind: NodeKind, min_read: BaseClass, class: BaseClass) -> Result<(), AclError> {
    if kind == NodeKind::DropBox {
        return Err(AclError::DropBoxIsWriteOnly);
    }
    if class < min_read {
        return Err(AclError::ClassTooLow);
    }
    Ok(())
}

/// May `class` upload into a folder?
pub fn check_write(_kind: NodeKind, min_write: BaseClass, class: BaseClass) -> Result<(), AclError> {
    if class < min_write {
        return Err(AclError::ClassTooLow);
    }
    Ok(())
}
