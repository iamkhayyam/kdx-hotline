use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::wire::{expect_end, get_str, put_str};
use crate::ProtocolError;

/// Client → server: forcibly disconnect a user by username, optionally banning
/// their account for `ban_secs` seconds. Requires `USER_KICK`; a non-zero
/// `ban_secs` additionally requires `USER_BAN`.
///
/// The server closes every live connection of the target (pushing a
/// `Disconnect` frame carrying `reason` first) and, when `ban_secs > 0`,
/// records an expiring ban that refuses that account's logins until it lapses.
/// The server acknowledges with an `Info` frame (or an `Error` on failure —
/// e.g. missing privilege, target outranks the caller, or target offline for a
/// pure kick).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminDisconnect {
    pub username: String,
    pub reason: String,
    /// Ban duration in seconds. `0` = kick only, no ban recorded.
    pub ban_secs: u32,
}

impl AdminDisconnect {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(8 + self.username.len() + self.reason.len());
        put_str(&mut buf, &self.username);
        put_str(&mut buf, &self.reason);
        buf.put_u32(self.ban_secs);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let username = get_str(&mut payload, "AdminDisconnect")?;
        let reason = get_str(&mut payload, "AdminDisconnect")?;
        if payload.remaining() < 4 {
            return Err(ProtocolError::MalformedPayload("AdminDisconnect"));
        }
        let ban_secs = payload.get_u32();
        expect_end(payload, "AdminDisconnect")?;
        Ok(Self {
            username,
            reason,
            ban_secs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let kick = AdminDisconnect {
            username: "crash_override".into(),
            reason: "flooding the boards".into(),
            ban_secs: 3600,
        };
        assert_eq!(AdminDisconnect::decode(&kick.encode()).unwrap(), kick);

        let bare = AdminDisconnect {
            username: "zero".into(),
            reason: String::new(),
            ban_secs: 0,
        };
        assert_eq!(AdminDisconnect::decode(&bare.encode()).unwrap(), bare);
    }

    #[test]
    fn rejects_truncated() {
        assert!(AdminDisconnect::decode(&[0]).is_err());
        // username present, but the ban_secs u32 is short.
        let mut buf = BytesMut::new();
        put_str(&mut buf, "u");
        put_str(&mut buf, "r");
        buf.put_u8(0); // only 1 of 4 ban_secs bytes
        assert!(AdminDisconnect::decode(&buf).is_err());
    }
}
