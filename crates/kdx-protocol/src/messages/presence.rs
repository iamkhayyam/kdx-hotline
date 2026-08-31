use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::wire::{expect_end, get_str, put_str};
use crate::ProtocolError;

/// One user's presence snapshot, as seen in the server-wide roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceEntry {
    pub username: String,
    pub class: u8,
    pub login_at: u64,  // unix seconds
    pub idle_secs: u32, // seconds since last observed activity
    pub address: String,
    /// Display name set via `/name` (empty = none, fall back to username).
    pub name: String,
    /// Description set via `/desc` (empty = none).
    pub description: String,
}

/// Client → server: request the full roster. Empty payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresenceListRequest;

/// Server → client: full roster snapshot, in reply to `PresenceListRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceListResponse {
    pub users: Vec<PresenceEntry>,
}

/// Server → client: one user came online or went offline. Pushed to every
/// authenticated connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceChange {
    pub entry: PresenceEntry,
    pub online: bool,
}

/// Client → server: set your own display name / description (`/name`, `/desc`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetIdentity {
    pub name: String,
    pub description: String,
}

impl SetIdentity {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.name);
        put_str(&mut buf, &self.description);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let name = get_str(&mut payload, "SetIdentity")?;
        let description = get_str(&mut payload, "SetIdentity")?;
        expect_end(payload, "SetIdentity")?;
        Ok(Self { name, description })
    }
}

/// Client → server: ask for one user's detail (User Info window).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfoRequest {
    pub username: String,
}

/// Server → client: reply to `UserInfoRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfoResponse {
    pub entry: PresenceEntry,
}

fn encode_entry(buf: &mut BytesMut, e: &PresenceEntry) {
    put_str(buf, &e.username);
    buf.put_u8(e.class);
    buf.put_u64(e.login_at);
    buf.put_u32(e.idle_secs);
    put_str(buf, &e.address);
    put_str(buf, &e.name);
    put_str(buf, &e.description);
}

fn decode_entry(payload: &mut &[u8]) -> Result<PresenceEntry, ProtocolError> {
    let username = get_str(payload, "PresenceEntry")?;
    if payload.remaining() < 1 + 8 + 4 {
        return Err(ProtocolError::MalformedPayload("PresenceEntry"));
    }
    let class = payload.get_u8();
    let login_at = payload.get_u64();
    let idle_secs = payload.get_u32();
    let address = get_str(payload, "PresenceEntry")?;
    let name = get_str(payload, "PresenceEntry")?;
    let description = get_str(payload, "PresenceEntry")?;
    Ok(PresenceEntry {
        username,
        class,
        login_at,
        idle_secs,
        address,
        name,
        description,
    })
}

impl PresenceListRequest {
    pub fn encode(&self) -> Bytes {
        Bytes::new()
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        expect_end(payload, "PresenceListRequest")?;
        Ok(Self)
    }
}

impl PresenceListResponse {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u16(self.users.len() as u16);
        for entry in &self.users {
            encode_entry(&mut buf, entry);
        }
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 2 {
            return Err(ProtocolError::MalformedPayload("PresenceListResponse"));
        }
        let count = payload.get_u16() as usize;
        let mut users = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            users.push(decode_entry(&mut payload)?);
        }
        expect_end(payload, "PresenceListResponse")?;
        Ok(Self { users })
    }
}

impl PresenceChange {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u8(self.online as u8);
        encode_entry(&mut buf, &self.entry);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 1 {
            return Err(ProtocolError::MalformedPayload("PresenceChange"));
        }
        let online = payload.get_u8() != 0;
        let entry = decode_entry(&mut payload)?;
        expect_end(payload, "PresenceChange")?;
        Ok(Self { entry, online })
    }
}

impl UserInfoRequest {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(2 + self.username.len());
        put_str(&mut buf, &self.username);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let username = get_str(&mut payload, "UserInfoRequest")?;
        expect_end(payload, "UserInfoRequest")?;
        Ok(Self { username })
    }
}

impl UserInfoResponse {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        encode_entry(&mut buf, &self.entry);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let entry = decode_entry(&mut payload)?;
        expect_end(payload, "UserInfoResponse")?;
        Ok(Self { entry })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> PresenceEntry {
        PresenceEntry {
            username: "phraq".into(),
            class: 2,
            login_at: 1_751_600_000,
            idle_secs: 42,
            address: "127.0.0.1:55123".into(),
            name: String::new(),
            description: String::new(),
        }
    }

    #[test]
    fn all_round_trip() {
        let req = PresenceListRequest;
        assert_eq!(PresenceListRequest::decode(&req.encode()).unwrap(), req);

        let list = PresenceListResponse {
            users: vec![sample_entry(), {
                let mut e = sample_entry();
                e.username = "acidburn".into();
                e.class = 3;
                e
            }],
        };
        assert_eq!(PresenceListResponse::decode(&list.encode()).unwrap(), list);

        let change = PresenceChange {
            entry: sample_entry(),
            online: true,
        };
        assert_eq!(PresenceChange::decode(&change.encode()).unwrap(), change);

        let info_req = UserInfoRequest {
            username: "phraq".into(),
        };
        assert_eq!(UserInfoRequest::decode(&info_req.encode()).unwrap(), info_req);

        let info_resp = UserInfoResponse {
            entry: sample_entry(),
        };
        assert_eq!(UserInfoResponse::decode(&info_resp.encode()).unwrap(), info_resp);

        let identity = SetIdentity {
            name: "Captain Phraq".into(),
            description: "just visiting".into(),
        };
        assert_eq!(SetIdentity::decode(&identity.encode()).unwrap(), identity);
    }

    #[test]
    fn empty_roster_round_trips() {
        let list = PresenceListResponse { users: vec![] };
        assert_eq!(PresenceListResponse::decode(&list.encode()).unwrap(), list);
    }

    #[test]
    fn rejects_malformed() {
        assert!(PresenceListResponse::decode(&[0]).is_err());
        assert!(PresenceChange::decode(&[1]).is_err());
        assert!(UserInfoRequest::decode(&[0, 5]).is_err());
    }
}
