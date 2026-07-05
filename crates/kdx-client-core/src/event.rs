use serde::Serialize;

/// Transfer direction, as reported in progress events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Upload,
    Download,
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
}
