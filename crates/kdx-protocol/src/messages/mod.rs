//! Typed payloads carried inside [`crate::KdxFrame`]s, one module per
//! opcode range. Each type provides `encode() -> Bytes` and
//! `decode(&[u8]) -> Result<Self, ProtocolError>`.

mod auth;
mod chat;
mod file;
mod handshake;
mod presence;
mod wire;

pub use auth::{AuthChallenge, AuthRequest, AuthResponse, AuthResult};
pub use chat::{
    ChatEvent, ChatJoin, ChatLeave, ChatSend, ChatTopic, ChatUserList, CHAT_ACTION, CHAT_SYSTEM,
};
pub use file::{
    FileEntry, FileListRequest, FileListResponse, TransferAccept, TransferData, TransferEnd,
    TransferRequest, DIRECTION_DOWNLOAD, DIRECTION_UPLOAD, KIND_DIR, KIND_DROPBOX, KIND_FILE,
    KIND_UPLOAD, TRANSFER_ABORTED, TRANSFER_HASH_MISMATCH, TRANSFER_VERIFIED,
};
pub use handshake::{HandshakeInit, HandshakeResp};
pub use presence::{
    PresenceChange, PresenceEntry, PresenceListRequest, PresenceListResponse, UserInfoRequest,
    UserInfoResponse,
};
