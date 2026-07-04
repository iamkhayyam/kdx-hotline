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

    // System (0xF0-0xFF)
    Error = 0xF0,
    Warning = 0xF1,
    Info = 0xF2,
}

impl PacketType {
    pub const ALL: [PacketType; 22] = [
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
            0xF0 => Error,
            0xF1 => Warning,
            0xF2 => Info,
            other => return Err(crate::ProtocolError::UnknownPacketType(other)),
        })
    }
}
