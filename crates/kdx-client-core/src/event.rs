use serde::Serialize;
use uuid::Uuid;

/// Transfer direction, as reported in progress events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Upload,
    Download,
}

/// One user's presence snapshot, as shown in the global User List / User Info
/// windows. Mirrors `kdx_protocol::messages::PresenceEntry`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PresenceUser {
    pub username: String,
    pub class: u8,
    pub login_at: u64,
    pub idle_secs: u32,
    pub address: String,
}

impl From<kdx_protocol::messages::PresenceEntry> for PresenceUser {
    fn from(e: kdx_protocol::messages::PresenceEntry) -> Self {
        Self {
            username: e.username,
            class: e.class,
            login_at: e.login_at,
            idle_secs: e.idle_secs,
            address: e.address,
        }
    }
}

/// A custom, named privilege bundle a SysOp can assign to accounts on top of
/// their base class — the Discord-style "roles" layer for the Roles window.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RoleInfo {
    pub id: String,
    pub name: String,
    pub privileges: u32,
    pub rank: i32,
    /// Empty string means "no color set".
    pub color: String,
}

impl From<kdx_protocol::messages::RoleInfo> for RoleInfo {
    fn from(r: kdx_protocol::messages::RoleInfo) -> Self {
        Self {
            id: Uuid::from_bytes(r.id).to_string(),
            name: r.name,
            privileges: r.privileges,
            rank: r.rank,
            color: r.color,
        }
    }
}

/// One account as shown in the Accounts window (Administration). Mirrors
/// `kdx_protocol::messages::AccountSummary`; no password material.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AccountSummary {
    pub username: String,
    pub base_class: u8,
    pub granted: u32,
    pub revoked: u32,
}

impl From<kdx_protocol::messages::AccountSummary> for AccountSummary {
    fn from(a: kdx_protocol::messages::AccountSummary) -> Self {
        Self {
            username: a.username,
            base_class: a.base_class,
            granted: a.granted,
            revoked: a.revoked,
        }
    }
}

/// A newsgroup as shown in the News window. Mirrors
/// `kdx_protocol::messages::NewsgroupInfo`; ids are stringified UUIDs.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NewsgroupInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub min_read_class: u8,
    pub min_post_class: u8,
}

impl From<kdx_protocol::messages::NewsgroupInfo> for NewsgroupInfo {
    fn from(g: kdx_protocol::messages::NewsgroupInfo) -> Self {
        Self {
            id: Uuid::from_bytes(g.id).to_string(),
            name: g.name,
            description: g.description,
            min_read_class: g.min_read_class,
            min_post_class: g.min_post_class,
        }
    }
}

/// One post in a newsgroup thread. `parent_id` is an empty string for a thread
/// root (matching the all-zeros wire sentinel).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NewsPost {
    pub id: String,
    pub newsgroup_id: String,
    pub parent_id: String,
    pub author: String,
    pub subject: String,
    pub body: String,
    pub timestamp: u64,
}

impl From<kdx_protocol::messages::NewsPost> for NewsPost {
    fn from(p: kdx_protocol::messages::NewsPost) -> Self {
        let parent_id = if p.parent_id == [0u8; 16] {
            String::new()
        } else {
            Uuid::from_bytes(p.parent_id).to_string()
        };
        Self {
            id: Uuid::from_bytes(p.id).to_string(),
            newsgroup_id: Uuid::from_bytes(p.newsgroup_id).to_string(),
            parent_id,
            author: p.author,
            subject: p.subject,
            body: p.body,
            timestamp: p.timestamp,
        }
    }
}

/// One server in the tracker directory (the Tracker window). Mirrors
/// `kdx_protocol::messages::TrackerServer`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TrackerServer {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub users: u32,
    pub max_users: u32,
    pub description: String,
}

impl From<kdx_protocol::messages::TrackerServer> for TrackerServer {
    fn from(s: kdx_protocol::messages::TrackerServer) -> Self {
        Self {
            name: s.name,
            host: s.host,
            port: s.port,
            users: s.users,
            max_users: s.max_users,
            description: s.description,
        }
    }
}

/// One catalog search hit (the Files → Search results). Mirrors
/// `kdx_protocol::messages::FileSearchEntry`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FileSearchEntry {
    pub path: String,
    pub name: String,
    pub kind: u8,
    pub size: u64,
}

impl From<kdx_protocol::messages::FileSearchEntry> for FileSearchEntry {
    fn from(e: kdx_protocol::messages::FileSearchEntry) -> Self {
        Self {
            path: e.path,
            name: e.name,
            kind: e.kind,
            size: e.size,
        }
    }
}

/// One audit-log entry (the Server History window). Mirrors
/// `kdx_protocol::messages::HistoryEntry`. `actor` is empty when the event had
/// no acting user (none currently do, but the wire format allows it).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HistoryEntry {
    pub timestamp: u64,
    pub actor: String,
    pub action: String,
    pub detail: String,
}

impl From<kdx_protocol::messages::HistoryEntry> for HistoryEntry {
    fn from(e: kdx_protocol::messages::HistoryEntry) -> Self {
        Self {
            timestamp: e.timestamp,
            actor: e.actor,
            action: e.action,
            detail: e.detail,
        }
    }
}

/// Current server settings (the Server Settings window). Mirrors
/// `kdx_protocol::messages::ServerSettingsResponse`. `port`,
/// `max_upload_bytes_per_sec`, and `max_download_bytes_per_sec` are
/// informational — set at process start, not remotely editable.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ServerSettings {
    pub name: String,
    pub description: String,
    pub greeting: String,
    pub max_users: u32,
    pub port: u16,
    pub max_upload_bytes_per_sec: u64,
    pub max_download_bytes_per_sec: u64,
}

impl From<kdx_protocol::messages::ServerSettingsResponse> for ServerSettings {
    fn from(s: kdx_protocol::messages::ServerSettingsResponse) -> Self {
        Self {
            name: s.name,
            description: s.description,
            greeting: s.greeting,
            max_users: s.max_users,
            port: s.port,
            max_upload_bytes_per_sec: s.max_upload_bytes_per_sec,
            max_download_bytes_per_sec: s.max_download_bytes_per_sec,
        }
    }
}

/// Events pushed from the connection actor to the application. The serde
/// representation (`{ "type": "chat", ... }`) is the exact contract the
/// webview consumes, so its shape is covered by a test.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// TLS + KDX handshake completed; carries the server's pinned fingerprint.
    Connected { fingerprint: String },
    /// Login succeeded; `class` is the account's base class (0..=3).
    Authenticated { class: u8 },
    /// A chat message (system messages have the system flag set in `flags`).
    Chat {
        room: String,
        sender: String,
        timestamp: u64,
        flags: u8,
        text: String,
    },
    /// Full member list for a room.
    UserList { room: String, users: Vec<String> },
    /// A room's topic was set or announced.
    Topic { room: String, topic: String },
    /// A user came online or went offline (global roster, not room-scoped).
    /// Never sent for your own connection's join.
    Presence { user: PresenceUser, online: bool },
    /// A private (direct) message. `from` is the sender, `to` the recipient
    /// (which is also echoed to the sender's own sessions so the sent line
    /// slots into the right conversation).
    PrivateMessage {
        from: String,
        to: String,
        timestamp: u64,
        text: String,
    },
    /// `from` has invited you into `room`, a private chat. Accepting is just
    /// an ordinary `join(room)`; ignoring needs no server round-trip.
    ChatInvited { from: String, room: String },
    /// Progress on an active transfer. `bitmap` is the LSB-first set of
    /// completed chunks, for the chunk-grid visualization.
    TransferProgress {
        id: String,
        direction: Direction,
        done: u32,
        total: u32,
        bitmap: Vec<u8>,
    },
    /// A transfer finished. `status` mirrors the wire TRANSFER_* codes.
    TransferComplete {
        id: String,
        direction: Direction,
        status: u8,
        message: String,
    },
    /// Server flood-control or advisory warning.
    ServerWarning { text: String },
    /// Server error frame.
    ServerError { text: String },
    /// Server informational frame.
    ServerInfo { text: String },
    /// The connection ended.
    Disconnected { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_event_json_shape() {
        let ev = Event::Chat {
            room: "lobby".into(),
            sender: "phraq".into(),
            timestamp: 1_751_600_000,
            flags: 1,
            text: "hi".into(),
        };
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["type"], "chat");
        assert_eq!(json["room"], "lobby");
        assert_eq!(json["sender"], "phraq");
        assert_eq!(json["text"], "hi");
    }

    #[test]
    fn transfer_progress_json_shape() {
        let ev = Event::TransferProgress {
            id: "abc".into(),
            direction: Direction::Download,
            done: 3,
            total: 8,
            bitmap: vec![0b0000_0111],
        };
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["type"], "transfer_progress");
        assert_eq!(json["direction"], "download");
        assert_eq!(json["done"], 3);
        assert_eq!(json["bitmap"][0], 7);
    }

    #[test]
    fn presence_event_json_shape() {
        let ev = Event::Presence {
            user: PresenceUser {
                username: "phraq".into(),
                class: 2,
                login_at: 1_751_600_000,
                idle_secs: 5,
                address: "127.0.0.1:1234".into(),
            },
            online: true,
        };
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["type"], "presence");
        assert_eq!(json["online"], true);
        assert_eq!(json["user"]["username"], "phraq");
        assert_eq!(json["user"]["class"], 2);
    }

    #[test]
    fn untagged_variants_carry_type() {
        assert_eq!(
            serde_json::to_value(Event::Disconnected { reason: "eof".into() }).unwrap()["type"],
            "disconnected"
        );
        assert_eq!(
            serde_json::to_value(Event::Authenticated { class: 2 }).unwrap()["type"],
            "authenticated"
        );
    }

    #[test]
    fn chat_invited_json_shape() {
        let ev = Event::ChatInvited {
            from: "phraq".into(),
            room: "priv-3f9c".into(),
        };
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["type"], "chat_invited");
        assert_eq!(json["from"], "phraq");
        assert_eq!(json["room"], "priv-3f9c");
    }
}
