use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::wire::{expect_end, get_str, put_str};
use crate::ProtocolError;

/// Message-level flags carried in chat payloads (distinct from packet-level
/// [`crate::PacketFlags`]).
pub const CHAT_ACTION: u8 = 1 << 0; // "/me"-style action message
pub const CHAT_SYSTEM: u8 = 1 << 1; // server-originated notice

/// Client → server: send a message to a room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatSend {
    pub room: String,
    pub flags: u8,
    pub text: String,
}

/// Server → clients: a message delivered to room members. Carries what the
/// receiving client needs to render: sender and server-assigned timestamp
/// (unix seconds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatEvent {
    pub room: String,
    pub sender: String,
    pub timestamp: u64,
    pub flags: u8,
    pub text: String,
}

/// Client → server: join a room (created on demand if the caller holds
/// CHAT_CREATE_ROOM).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatJoin {
    pub room: String,
}

/// Client → server: leave a room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatLeave {
    pub room: String,
}

/// Server → clients: full member list for a room, sent on join and on
/// membership changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatUserList {
    pub room: String,
    pub users: Vec<String>,
}

/// Both directions: set (client) or announce (server) a room topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatTopic {
    pub room: String,
    pub topic: String,
}

/// Client → server: invite `to` into a fresh private chat. The server
/// generates the room, joins the inviter to it immediately, and — if `to` is
/// online — delivers a `ChatInvited`. Requires `CHAT_PRIVATE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatInvite {
    pub to: String,
}

/// Server → client: `from` has invited you into `room`, a private chat.
/// Accepting is just an ordinary `ChatJoin` on `room`; ignoring is purely
/// client-local (no wire message) — the inviter's copy of the room simply
/// stays at one member until they give up and leave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatInvited {
    pub from: String,
    pub room: String,
}

impl ChatSend {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(5 + self.room.len() + self.text.len());
        put_str(&mut buf, &self.room);
        buf.put_u8(self.flags);
        put_str(&mut buf, &self.text);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let room = get_str(&mut payload, "ChatSend")?;
        if payload.remaining() < 1 {
            return Err(ProtocolError::MalformedPayload("ChatSend"));
        }
        let flags = payload.get_u8();
        let text = get_str(&mut payload, "ChatSend")?;
        expect_end(payload, "ChatSend")?;
        Ok(Self { room, flags, text })
    }
}

impl ChatEvent {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(
            13 + self.room.len() + self.sender.len() + self.text.len(),
        );
        put_str(&mut buf, &self.room);
        put_str(&mut buf, &self.sender);
        buf.put_u64(self.timestamp);
        buf.put_u8(self.flags);
        put_str(&mut buf, &self.text);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let room = get_str(&mut payload, "ChatEvent")?;
        let sender = get_str(&mut payload, "ChatEvent")?;
        if payload.remaining() < 9 {
            return Err(ProtocolError::MalformedPayload("ChatEvent"));
        }
        let timestamp = payload.get_u64();
        let flags = payload.get_u8();
        let text = get_str(&mut payload, "ChatEvent")?;
        expect_end(payload, "ChatEvent")?;
        Ok(Self {
            room,
            sender,
            timestamp,
            flags,
            text,
        })
    }
}

impl ChatJoin {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(2 + self.room.len());
        put_str(&mut buf, &self.room);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let room = get_str(&mut payload, "ChatJoin")?;
        expect_end(payload, "ChatJoin")?;
        Ok(Self { room })
    }
}

impl ChatLeave {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(2 + self.room.len());
        put_str(&mut buf, &self.room);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let room = get_str(&mut payload, "ChatLeave")?;
        expect_end(payload, "ChatLeave")?;
        Ok(Self { room })
    }
}

impl ChatUserList {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.room);
        buf.put_u16(self.users.len() as u16);
        for user in &self.users {
            put_str(&mut buf, user);
        }
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let room = get_str(&mut payload, "ChatUserList")?;
        if payload.remaining() < 2 {
            return Err(ProtocolError::MalformedPayload("ChatUserList"));
        }
        let count = payload.get_u16() as usize;
        let mut users = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            users.push(get_str(&mut payload, "ChatUserList")?);
        }
        expect_end(payload, "ChatUserList")?;
        Ok(Self { room, users })
    }
}

impl ChatTopic {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(4 + self.room.len() + self.topic.len());
        put_str(&mut buf, &self.room);
        put_str(&mut buf, &self.topic);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let room = get_str(&mut payload, "ChatTopic")?;
        let topic = get_str(&mut payload, "ChatTopic")?;
        expect_end(payload, "ChatTopic")?;
        Ok(Self { room, topic })
    }
}

impl ChatInvite {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.to);
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let to = get_str(&mut payload, "ChatInvite")?;
        expect_end(payload, "ChatInvite")?;
        Ok(Self { to })
    }
}

impl ChatInvited {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.from);
        put_str(&mut buf, &self.room);
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let from = get_str(&mut payload, "ChatInvited")?;
        let room = get_str(&mut payload, "ChatInvited")?;
        expect_end(payload, "ChatInvited")?;
        Ok(Self { from, room })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_round_trip() {
        let send = ChatSend {
            room: "lobby".into(),
            flags: CHAT_ACTION,
            text: "waves".into(),
        };
        assert_eq!(ChatSend::decode(&send.encode()).unwrap(), send);

        let event = ChatEvent {
            room: "lobby".into(),
            sender: "phraq".into(),
            timestamp: 1_751_600_000,
            flags: 0,
            text: "hello".into(),
        };
        assert_eq!(ChatEvent::decode(&event.encode()).unwrap(), event);

        let join = ChatJoin {
            room: "lobby".into(),
        };
        assert_eq!(ChatJoin::decode(&join.encode()).unwrap(), join);

        let leave = ChatLeave {
            room: "lobby".into(),
        };
        assert_eq!(ChatLeave::decode(&leave.encode()).unwrap(), leave);

        let list = ChatUserList {
            room: "lobby".into(),
            users: vec!["a".into(), "b".into(), "c".into()],
        };
        assert_eq!(ChatUserList::decode(&list.encode()).unwrap(), list);

        let topic = ChatTopic {
            room: "lobby".into(),
            topic: "digital freedom".into(),
        };
        assert_eq!(ChatTopic::decode(&topic.encode()).unwrap(), topic);
    }

    #[test]
    fn rejects_malformed() {
        assert!(ChatSend::decode(&[0]).is_err());
        assert!(ChatEvent::decode(&[0, 1, 65]).is_err());
        assert!(ChatUserList::decode(&[0, 0, 0, 5]).is_err());
    }

    #[test]
    fn invite_round_trip() {
        let invite = ChatInvite { to: "acidburn".into() };
        assert_eq!(ChatInvite::decode(&invite.encode()).unwrap(), invite);

        let invited = ChatInvited {
            from: "phraq".into(),
            room: "priv-3f9c".into(),
        };
        assert_eq!(ChatInvited::decode(&invited.encode()).unwrap(), invited);

        assert!(ChatInvite::decode(&[0, 5, 65]).is_err());
        assert!(ChatInvited::decode(&[0, 1, 65]).is_err());
    }
}
