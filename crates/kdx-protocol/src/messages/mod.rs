//! Typed payloads carried inside [`crate::KdxFrame`]s, one module per
//! opcode range. Each type provides `encode() -> Bytes` and
//! `decode(&[u8]) -> Result<Self, ProtocolError>`.

mod auth;
mod chat;
mod handshake;
mod wire;

pub use auth::{AuthChallenge, AuthRequest, AuthResponse, AuthResult};
pub use chat::{
    ChatEvent, ChatJoin, ChatLeave, ChatSend, ChatTopic, ChatUserList, CHAT_ACTION, CHAT_SYSTEM,
};
pub use handshake::{HandshakeInit, HandshakeResp};
