//! User classes and privileges. An account's effective privileges are its
//! base class's set, plus per-account granted bits, minus per-account
//! revoked bits — overrides need both directions to match the original KDX
//! semantics ("custom privileges" that can exceed or restrict the class).

use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Privileges: u32 {
        const CHAT_SEND        = 1 << 0;
        const CHAT_PRIVATE     = 1 << 1;
        const CHAT_CREATE_ROOM = 1 << 2;
        const CHAT_SET_TOPIC   = 1 << 3;
        const FILE_LIST        = 1 << 4;
        const FILE_DOWNLOAD    = 1 << 5;
        const FILE_UPLOAD      = 1 << 6;
        const FILE_DELETE      = 1 << 7;
        const FILE_MANAGE_TREE = 1 << 8;  // create/remove folders, dropboxes
        const USER_KICK        = 1 << 16;
        const USER_BAN         = 1 << 17;
        const USER_ADMIN       = 1 << 18; // create/edit accounts
        const SERVER_ADMIN     = 1 << 19; // config, shutdown
    }
}

/// The four KDX user classes.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BaseClass {
    Guest = 0,
    User = 1,
    PowerUser = 2,
    Admin = 3,
}

impl BaseClass {
    pub fn privileges(self) -> Privileges {
        match self {
            BaseClass::Guest => Privileges::CHAT_SEND | Privileges::FILE_LIST,
            BaseClass::User => {
                BaseClass::Guest.privileges()
                    | Privileges::CHAT_PRIVATE
                    | Privileges::FILE_DOWNLOAD
                    | Privileges::FILE_UPLOAD
            }
            BaseClass::PowerUser => {
                BaseClass::User.privileges()
                    | Privileges::CHAT_CREATE_ROOM
                    | Privileges::CHAT_SET_TOPIC
                    | Privileges::FILE_DELETE
                    | Privileges::FILE_MANAGE_TREE
            }
            BaseClass::Admin => Privileges::all(),
        }
    }
}

impl TryFrom<u8> for BaseClass {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, ()> {
        Ok(match value {
            0 => BaseClass::Guest,
            1 => BaseClass::User,
            2 => BaseClass::PowerUser,
            3 => BaseClass::Admin,
            _ => return Err(()),
        })
    }
}

/// Combine a base class with per-account override bits.
pub fn effective_privileges(base: BaseClass, granted: u32, revoked: u32) -> Privileges {
    let granted = Privileges::from_bits_truncate(granted);
    let revoked = Privileges::from_bits_truncate(revoked);
    (base.privileges() | granted) - revoked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_are_strictly_increasing() {
        let guest = BaseClass::Guest.privileges();
        let user = BaseClass::User.privileges();
        let power = BaseClass::PowerUser.privileges();
        let admin = BaseClass::Admin.privileges();
        assert!(user.contains(guest) && user != guest);
        assert!(power.contains(user) && power != user);
        assert!(admin.contains(power) && admin != power);
    }

    #[test]
    fn grants_extend_class() {
        let effective = effective_privileges(
            BaseClass::User,
            Privileges::CHAT_SET_TOPIC.bits(),
            0,
        );
        assert!(effective.contains(Privileges::CHAT_SET_TOPIC));
        assert!(effective.contains(Privileges::CHAT_SEND));
    }

    #[test]
    fn revokes_restrict_class() {
        let effective = effective_privileges(
            BaseClass::PowerUser,
            0,
            Privileges::FILE_UPLOAD.bits(),
        );
        assert!(!effective.contains(Privileges::FILE_UPLOAD));
        assert!(effective.contains(Privileges::FILE_DOWNLOAD));
    }

    #[test]
    fn revoke_beats_grant() {
        let bits = Privileges::FILE_DELETE.bits();
        let effective = effective_privileges(BaseClass::User, bits, bits);
        assert!(!effective.contains(Privileges::FILE_DELETE));
    }
}
