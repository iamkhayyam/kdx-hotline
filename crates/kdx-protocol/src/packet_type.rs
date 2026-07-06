/// Canonical KDX packet types, grouped by opcode range.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketType {
    // Connection management (0x00-0x0F)
    HandshakeInit = 0x01,
    HandshakeResp = 0x02,
    Ping = 0x03,
    Pong = 0x04,
    Disconnect = 0x0F,

    // Authentication (0x10-0x1F)
    AuthRequest = 0x10,
    AuthChallenge = 0x11,
    AuthResponse = 0x12,
    AuthResult = 0x13,

    // File operations (0x20-0x2F)
    FileListRequest = 0x20,
    FileListResponse = 0x21,
    FileTransferStart = 0x22,
    FileTransferData = 0x23,
    FileTransferEnd = 0x24,

    // Chat (0x30-0x3F)
    ChatMessage = 0x30,
    ChatJoin = 0x31,
    ChatLeave = 0x32,
    ChatUserList = 0x33,
    ChatTopicSet = 0x34,

    // Presence (0x35-0x39)
    PresenceListRequest = 0x35,
    PresenceListResponse = 0x36,
    PresenceChange = 0x37,
    UserInfoRequest = 0x38,
    UserInfoResponse = 0x39,

    // Private messages (0x40-0x41)
    PrivateSend = 0x40,
    PrivateMessage = 0x41,

    // Roles / account admin (0x50-0x58)
    RoleListRequest = 0x50,
    RoleListResponse = 0x51,
    RoleCreate = 0x52,
    RoleUpdate = 0x53,
    RoleDelete = 0x54,
    RoleAssign = 0x55,
    RoleUnassign = 0x56,
    AccountRolesRequest = 0x57,
    AccountRolesResponse = 0x58,

    // System (0xF0-0xFF)
    Error = 0xF0,
    Warning = 0xF1,
    Info = 0xF2,
}

impl PacketType {
    pub const ALL: [PacketType; 38] = [
        PacketType::HandshakeInit,
        PacketType::HandshakeResp,
        PacketType::Ping,
        PacketType::Pong,
        PacketType::Disconnect,
        PacketType::AuthRequest,
        PacketType::AuthChallenge,
        PacketType::AuthResponse,
        PacketType::AuthResult,
        PacketType::FileListRequest,
        PacketType::FileListResponse,
        PacketType::FileTransferStart,
        PacketType::FileTransferData,
        PacketType::FileTransferEnd,
        PacketType::ChatMessage,
        PacketType::ChatJoin,
        PacketType::ChatLeave,
        PacketType::ChatUserList,
        PacketType::ChatTopicSet,
        PacketType::PresenceListRequest,
        PacketType::PresenceListResponse,
        PacketType::PresenceChange,
        PacketType::UserInfoRequest,
        PacketType::UserInfoResponse,
        PacketType::PrivateSend,
        PacketType::PrivateMessage,
        PacketType::RoleListRequest,
        PacketType::RoleListResponse,
        PacketType::RoleCreate,
        PacketType::RoleUpdate,
        PacketType::RoleDelete,
        PacketType::RoleAssign,
        PacketType::RoleUnassign,
        PacketType::AccountRolesRequest,
        PacketType::AccountRolesResponse,
        PacketType::Error,
        PacketType::Warning,
        PacketType::Info,
    ];
}

impl TryFrom<u8> for PacketType {
    type Error = crate::ProtocolError;

    fn try_from(value: u8) -> Result<Self, crate::ProtocolError> {
        use PacketType::*;
        Ok(match value {
            0x01 => HandshakeInit,
            0x02 => HandshakeResp,
            0x03 => Ping,
            0x04 => Pong,
            0x0F => Disconnect,
            0x10 => AuthRequest,
            0x11 => AuthChallenge,
            0x12 => AuthResponse,
            0x13 => AuthResult,
            0x20 => FileListRequest,
            0x21 => FileListResponse,
            0x22 => FileTransferStart,
            0x23 => FileTransferData,
            0x24 => FileTransferEnd,
            0x30 => ChatMessage,
            0x31 => ChatJoin,
            0x32 => ChatLeave,
            0x33 => ChatUserList,
            0x34 => ChatTopicSet,
            0x35 => PresenceListRequest,
            0x36 => PresenceListResponse,
            0x37 => PresenceChange,
            0x38 => UserInfoRequest,
            0x39 => UserInfoResponse,
            0x40 => PrivateSend,
            0x41 => PrivateMessage,
            0x50 => RoleListRequest,
            0x51 => RoleListResponse,
            0x52 => RoleCreate,
            0x53 => RoleUpdate,
            0x54 => RoleDelete,
            0x55 => RoleAssign,
            0x56 => RoleUnassign,
            0x57 => AccountRolesRequest,
            0x58 => AccountRolesResponse,
            0xF0 => Error,
            0xF1 => Warning,
            0xF2 => Info,
            other => return Err(crate::ProtocolError::UnknownPacketType(other)),
        })
    }
}
