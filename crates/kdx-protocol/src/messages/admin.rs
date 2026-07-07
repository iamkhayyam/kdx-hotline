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

/// Client → server: fetch the live server settings. Requires `SERVER_ADMIN`.
/// Empty payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerSettingsRequest;

/// Server → client: current settings, in reply to `ServerSettingsRequest` or
/// after a successful `ServerSettingsUpdate`. `port`, `max_upload_bytes_per_sec`,
/// and `max_download_bytes_per_sec` are informational — they take effect at
/// process start and are not remotely editable; only `name`/`description`/
/// `greeting`/`max_users` are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSettingsResponse {
    pub name: String,
    pub description: String,
    pub greeting: String,
    pub max_users: u32,
    pub port: u16,
    pub max_upload_bytes_per_sec: u64,
    pub max_download_bytes_per_sec: u64,
}

/// Client → server: replace the live-editable settings wholesale. Requires
/// `SERVER_ADMIN`. The server replies with a `ServerSettingsResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSettingsUpdate {
    pub name: String,
    pub description: String,
    pub greeting: String,
    pub max_users: u32,
}

/// Client → server: send `text` to every currently-connected session
/// (regardless of chat-room membership), as a system `Info` frame. Requires
/// `SERVER_ADMIN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminBroadcast {
    pub text: String,
}

/// Client → server: gracefully stop the server — broadcast `message`,
/// disconnect every session (including the caller's), and stop accepting new
/// connections. Requires `SERVER_ADMIN`. This is "Exit" only: it never
/// touches the host OS (no restart/shutdown-computer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminShutdown {
    pub message: String,
}

impl ServerSettingsRequest {
    pub fn encode(&self) -> Bytes {
        Bytes::new()
    }
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        expect_end(payload, "ServerSettingsRequest")?;
        Ok(Self)
    }
}

impl ServerSettingsResponse {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.name);
        put_str(&mut buf, &self.description);
        put_str(&mut buf, &self.greeting);
        buf.put_u32(self.max_users);
        buf.put_u16(self.port);
        buf.put_u64(self.max_upload_bytes_per_sec);
        buf.put_u64(self.max_download_bytes_per_sec);
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let name = get_str(&mut payload, "ServerSettingsResponse")?;
        let description = get_str(&mut payload, "ServerSettingsResponse")?;
        let greeting = get_str(&mut payload, "ServerSettingsResponse")?;
        if payload.remaining() < 4 + 2 + 8 + 8 {
            return Err(ProtocolError::MalformedPayload("ServerSettingsResponse"));
        }
        let max_users = payload.get_u32();
        let port = payload.get_u16();
        let max_upload_bytes_per_sec = payload.get_u64();
        let max_download_bytes_per_sec = payload.get_u64();
        expect_end(payload, "ServerSettingsResponse")?;
        Ok(Self {
            name,
            description,
            greeting,
            max_users,
            port,
            max_upload_bytes_per_sec,
            max_download_bytes_per_sec,
        })
    }
}

impl ServerSettingsUpdate {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.name);
        put_str(&mut buf, &self.description);
        put_str(&mut buf, &self.greeting);
        buf.put_u32(self.max_users);
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let name = get_str(&mut payload, "ServerSettingsUpdate")?;
        let description = get_str(&mut payload, "ServerSettingsUpdate")?;
        let greeting = get_str(&mut payload, "ServerSettingsUpdate")?;
        if payload.remaining() < 4 {
            return Err(ProtocolError::MalformedPayload("ServerSettingsUpdate"));
        }
        let max_users = payload.get_u32();
        expect_end(payload, "ServerSettingsUpdate")?;
        Ok(Self {
            name,
            description,
            greeting,
            max_users,
        })
    }
}

impl AdminBroadcast {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.text);
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let text = get_str(&mut payload, "AdminBroadcast")?;
        expect_end(payload, "AdminBroadcast")?;
        Ok(Self { text })
    }
}

impl AdminShutdown {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.message);
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let message = get_str(&mut payload, "AdminShutdown")?;
        expect_end(payload, "AdminShutdown")?;
        Ok(Self { message })
    }
}

/// Client → server: fetch the most recent server-history entries. Requires
/// `SERVER_ADMIN`. `limit` is capped server-side (see the dispatch handler).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryListRequest {
    pub limit: u32,
}

/// One audit-log entry. `actor` empty means no single user was responsible
/// (there's no wire-level `Option`, matching the convention used elsewhere).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    pub timestamp: u64,
    pub actor: String,
    pub action: String,
    pub detail: String,
}

/// Server → client: reply to `HistoryListRequest`, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryListResponse {
    pub entries: Vec<HistoryEntry>,
}

impl HistoryListRequest {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u32(self.limit);
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 4 {
            return Err(ProtocolError::MalformedPayload("HistoryListRequest"));
        }
        let limit = payload.get_u32();
        expect_end(payload, "HistoryListRequest")?;
        Ok(Self { limit })
    }
}

impl HistoryListResponse {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u32(self.entries.len() as u32);
        for e in &self.entries {
            buf.put_u64(e.timestamp);
            put_str(&mut buf, &e.actor);
            put_str(&mut buf, &e.action);
            put_str(&mut buf, &e.detail);
        }
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 4 {
            return Err(ProtocolError::MalformedPayload("HistoryListResponse"));
        }
        let count = payload.get_u32() as usize;
        let mut entries = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            if payload.remaining() < 8 {
                return Err(ProtocolError::MalformedPayload("HistoryListResponse"));
            }
            let timestamp = payload.get_u64();
            let actor = get_str(&mut payload, "HistoryListResponse")?;
            let action = get_str(&mut payload, "HistoryListResponse")?;
            let detail = get_str(&mut payload, "HistoryListResponse")?;
            entries.push(HistoryEntry {
                timestamp,
                actor,
                action,
                detail,
            });
        }
        expect_end(payload, "HistoryListResponse")?;
        Ok(Self { entries })
    }
}

/// Client → server: list current Allow-Deny IP rules in priority order.
/// Requires `SERVER_ADMIN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRuleListRequest;

/// One IP rule, as shown in the IP Rules window. `action` is "allow" or
/// "deny" as a plain string (the enum lives server-side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpRuleEntry {
    pub id: String,
    pub position: i32,
    pub action: String,
    pub cidr: String,
    pub note: String,
    pub created_by: String,
    pub created_at: u64,
}

/// Server → client: reply to `IpRuleListRequest`, priority order (lowest
/// `position` first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpRuleListResponse {
    pub rules: Vec<IpRuleEntry>,
}

/// Client → server: create a new allow/deny rule. `action` must be exactly
/// "allow" or "deny"; `cidr` must parse as an `ipnet::IpNet`. Rejected with
/// an `Error` if either is invalid, or if the caller lacks `SERVER_ADMIN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpRuleCreate {
    pub position: i32,
    pub action: String,
    pub cidr: String,
    pub note: String,
}

/// Client → server: delete a rule by id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpRuleDelete {
    pub id: String,
}

impl IpRuleListRequest {
    pub fn encode(&self) -> Bytes {
        Bytes::new()
    }
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        expect_end(payload, "IpRuleListRequest")?;
        Ok(Self)
    }
}

impl IpRuleListResponse {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u32(self.rules.len() as u32);
        for r in &self.rules {
            put_str(&mut buf, &r.id);
            buf.put_i32(r.position);
            put_str(&mut buf, &r.action);
            put_str(&mut buf, &r.cidr);
            put_str(&mut buf, &r.note);
            put_str(&mut buf, &r.created_by);
            buf.put_u64(r.created_at);
        }
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 4 {
            return Err(ProtocolError::MalformedPayload("IpRuleListResponse"));
        }
        let count = payload.get_u32() as usize;
        let mut rules = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            let id = get_str(&mut payload, "IpRuleListResponse")?;
            if payload.remaining() < 4 {
                return Err(ProtocolError::MalformedPayload("IpRuleListResponse"));
            }
            let position = payload.get_i32();
            let action = get_str(&mut payload, "IpRuleListResponse")?;
            let cidr = get_str(&mut payload, "IpRuleListResponse")?;
            let note = get_str(&mut payload, "IpRuleListResponse")?;
            let created_by = get_str(&mut payload, "IpRuleListResponse")?;
            if payload.remaining() < 8 {
                return Err(ProtocolError::MalformedPayload("IpRuleListResponse"));
            }
            let created_at = payload.get_u64();
            rules.push(IpRuleEntry {
                id,
                position,
                action,
                cidr,
                note,
                created_by,
                created_at,
            });
        }
        expect_end(payload, "IpRuleListResponse")?;
        Ok(Self { rules })
    }
}

impl IpRuleCreate {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_i32(self.position);
        put_str(&mut buf, &self.action);
        put_str(&mut buf, &self.cidr);
        put_str(&mut buf, &self.note);
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 4 {
            return Err(ProtocolError::MalformedPayload("IpRuleCreate"));
        }
        let position = payload.get_i32();
        let action = get_str(&mut payload, "IpRuleCreate")?;
        let cidr = get_str(&mut payload, "IpRuleCreate")?;
        let note = get_str(&mut payload, "IpRuleCreate")?;
        expect_end(payload, "IpRuleCreate")?;
        Ok(Self { position, action, cidr, note })
    }
}

impl IpRuleDelete {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.id);
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let id = get_str(&mut payload, "IpRuleDelete")?;
        expect_end(payload, "IpRuleDelete")?;
        Ok(Self { id })
    }
}

/// Client → server: request the live-connection roster (the Connection
/// Monitor window). Same information as `PresenceListRequest`, but gated
/// on `USER_KICK` so plain users cannot enumerate everyone's IP/idle
/// details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionListRequest;

/// Server → client: full connection snapshot in reply to
/// `ConnectionListRequest`. Reuses the `PresenceEntry` shape from
/// `presence.rs` — nothing structural differs between the User List and
/// the Connection Monitor except *who* is allowed to see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionListResponse {
    pub connections: Vec<super::presence::PresenceEntry>,
}

impl ConnectionListRequest {
    pub fn encode(&self) -> Bytes {
        Bytes::new()
    }
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        expect_end(payload, "ConnectionListRequest")?;
        Ok(Self)
    }
}

impl ConnectionListResponse {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u16(self.connections.len() as u16);
        for e in &self.connections {
            put_str(&mut buf, &e.username);
            buf.put_u8(e.class);
            buf.put_u64(e.login_at);
            buf.put_u32(e.idle_secs);
            put_str(&mut buf, &e.address);
        }
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 2 {
            return Err(ProtocolError::MalformedPayload("ConnectionListResponse"));
        }
        let count = payload.get_u16() as usize;
        let mut connections = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            let username = get_str(&mut payload, "ConnectionListResponse")?;
            if payload.remaining() < 1 + 8 + 4 {
                return Err(ProtocolError::MalformedPayload("ConnectionListResponse"));
            }
            let class = payload.get_u8();
            let login_at = payload.get_u64();
            let idle_secs = payload.get_u32();
            let address = get_str(&mut payload, "ConnectionListResponse")?;
            connections.push(super::presence::PresenceEntry {
                username,
                class,
                login_at,
                idle_secs,
                address,
            });
        }
        expect_end(payload, "ConnectionListResponse")?;
        Ok(Self { connections })
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

    #[test]
    fn server_settings_round_trip() {
        assert!(ServerSettingsRequest::decode(&ServerSettingsRequest.encode()).is_ok());

        let resp = ServerSettingsResponse {
            name: "The Underground".into(),
            description: "warez & wares".into(),
            greeting: "welcome back".into(),
            max_users: 256,
            port: 10700,
            max_upload_bytes_per_sec: 0,
            max_download_bytes_per_sec: 1_000_000,
        };
        assert_eq!(ServerSettingsResponse::decode(&resp.encode()).unwrap(), resp);

        let update = ServerSettingsUpdate {
            name: "Renamed".into(),
            description: "".into(),
            greeting: "".into(),
            max_users: 10,
        };
        assert_eq!(ServerSettingsUpdate::decode(&update.encode()).unwrap(), update);

        assert!(ServerSettingsResponse::decode(&[0, 0]).is_err());
        assert!(ServerSettingsUpdate::decode(&[0, 0]).is_err());
    }

    #[test]
    fn broadcast_and_shutdown_round_trip() {
        let b = AdminBroadcast { text: "server restarting in 5 minutes".into() };
        assert_eq!(AdminBroadcast::decode(&b.encode()).unwrap(), b);

        let s = AdminShutdown { message: "goodnight".into() };
        assert_eq!(AdminShutdown::decode(&s.encode()).unwrap(), s);

        // Length prefix declares 5 bytes but only 1 follows.
        assert!(AdminBroadcast::decode(&[0, 5, 65]).is_err());
        assert!(AdminShutdown::decode(&[0, 5, 65]).is_err());
    }

    #[test]
    fn history_round_trip() {
        let req = HistoryListRequest { limit: 50 };
        assert_eq!(HistoryListRequest::decode(&req.encode()).unwrap(), req);

        let resp = HistoryListResponse {
            entries: vec![
                HistoryEntry {
                    timestamp: 1_751_600_000,
                    actor: "sysop".into(),
                    action: "kicked".into(),
                    detail: "target=lamer".into(),
                },
                HistoryEntry {
                    timestamp: 1_751_600_100,
                    actor: String::new(),
                    action: "server_started".into(),
                    detail: "".into(),
                },
            ],
        };
        assert_eq!(HistoryListResponse::decode(&resp.encode()).unwrap(), resp);

        let empty = HistoryListResponse { entries: vec![] };
        assert_eq!(HistoryListResponse::decode(&empty.encode()).unwrap(), empty);

        assert!(HistoryListRequest::decode(&[0]).is_err());
        assert!(HistoryListResponse::decode(&[0, 0]).is_err());
    }

    #[test]
    fn connection_list_round_trip() {
        assert!(ConnectionListRequest::decode(&ConnectionListRequest.encode()).is_ok());

        let resp = ConnectionListResponse {
            connections: vec![super::super::presence::PresenceEntry {
                username: "phraq".into(),
                class: 2,
                login_at: 1_700_000_000,
                idle_secs: 12,
                address: "10.0.0.5:52341".into(),
            }],
        };
        assert_eq!(ConnectionListResponse::decode(&resp.encode()).unwrap(), resp);

        let empty = ConnectionListResponse { connections: vec![] };
        assert_eq!(ConnectionListResponse::decode(&empty.encode()).unwrap(), empty);

        assert!(ConnectionListResponse::decode(&[0]).is_err());
    }

    #[test]
    fn ip_rule_round_trip() {
        assert!(IpRuleListRequest::decode(&IpRuleListRequest.encode()).is_ok());

        let resp = IpRuleListResponse {
            rules: vec![
                IpRuleEntry {
                    id: "aaaa".into(),
                    position: 10,
                    action: "deny".into(),
                    cidr: "1.2.3.0/24".into(),
                    note: "spammy /24".into(),
                    created_by: "sysop".into(),
                    created_at: 1_700_000_000,
                },
                IpRuleEntry {
                    id: "bbbb".into(),
                    position: 5,
                    action: "allow".into(),
                    cidr: "1.2.3.4/32".into(),
                    note: "our office".into(),
                    created_by: "sysop".into(),
                    created_at: 1_700_000_100,
                },
            ],
        };
        assert_eq!(IpRuleListResponse::decode(&resp.encode()).unwrap(), resp);

        let empty = IpRuleListResponse { rules: vec![] };
        assert_eq!(IpRuleListResponse::decode(&empty.encode()).unwrap(), empty);

        let create = IpRuleCreate {
            position: 42,
            action: "deny".into(),
            cidr: "10.0.0.0/8".into(),
            note: "".into(),
        };
        assert_eq!(IpRuleCreate::decode(&create.encode()).unwrap(), create);

        let del = IpRuleDelete { id: "some-uuid".into() };
        assert_eq!(IpRuleDelete::decode(&del.encode()).unwrap(), del);

        // Truncation guards.
        assert!(IpRuleCreate::decode(&[0, 0]).is_err());
        assert!(IpRuleListResponse::decode(&[0, 0]).is_err());
    }
}
