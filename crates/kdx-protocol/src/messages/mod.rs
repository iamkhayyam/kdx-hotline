//! Typed payloads carried inside [`crate::KdxFrame`]s, one module per
//! opcode range. Each type provides `encode() -> Bytes` and
//! `decode(&[u8]) -> Result<Self, ProtocolError>`.

mod account;
mod admin;
mod auth;
mod chat;
mod file;
mod handshake;
mod news;
mod presence;
mod private;
mod roles;
mod tracker;
mod wire;

pub use account::{
    AccountCreate, AccountListRequest, AccountListResponse, AccountSummary, AccountUpdate,
};
pub use admin::{
    AdminBroadcast, AdminDisconnect, AdminShutdown, ConnectionListRequest,
    ConnectionListResponse, HistoryEntry, HistoryListRequest, HistoryListResponse, IpRuleCreate,
    IpRuleDelete, IpRuleEntry, IpRuleListRequest, IpRuleListResponse, ServerSettingsRequest,
    ServerSettingsResponse, ServerSettingsUpdate,
};
pub use auth::{AuthChallenge, AuthRequest, AuthResponse, AuthResult};
pub use chat::{
    ChatEvent, ChatInvite, ChatInvited, ChatJoin, ChatLeave, ChatRoomFlags, ChatSend, ChatTopic,
    ChatUserList, CHAT_ACTION, CHAT_SYSTEM,
};
pub use file::{
    FileAlias, FileCatalogGenerated, FileCreateFolder, FileDelete, FileEntry,
    FileGenerateCatalog, FileListRequest, FileListResponse, FileMove, FileSearchEntry,
    FileSearchRequest, FileSearchResponse, TransferAccept, TransferData, TransferEnd,
    TransferRequest, DIRECTION_DOWNLOAD, DIRECTION_UPLOAD, KIND_ALIAS, KIND_DIR, KIND_DROPBOX,
    KIND_FILE, KIND_UPLOAD, TRANSFER_ABORTED, TRANSFER_HASH_MISMATCH, TRANSFER_VERIFIED,
};
pub use handshake::{HandshakeInit, HandshakeResp};
pub use news::{
    NewsPost, NewsPostCreate, NewsPostDelete, NewsThreadListRequest, NewsThreadListResponse,
    NewsgroupCreate, NewsgroupInfo, NewsgroupListRequest, NewsgroupListResponse,
};
pub use presence::{
    PresenceChange, PresenceEntry, PresenceListRequest, PresenceListResponse, UserInfoRequest,
    UserInfoResponse,
};
pub use private::{PrivateMessage, PrivateSend};
pub use roles::{
    AccountRolesRequest, AccountRolesResponse, RoleAssign, RoleCreate, RoleDelete, RoleInfo,
    RoleListRequest, RoleListResponse, RoleUnassign, RoleUpdate,
};
pub use tracker::{TrackerListRequest, TrackerListResponse, TrackerServer};
