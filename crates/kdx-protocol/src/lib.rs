//! KDX wire protocol: packet header, types, flags, framing codec, and
//! fragmentation. This crate is shared between the server and future clients
//! and must stay free of server-only concerns.

mod codec;
mod flags;
mod fragment;
mod header;
pub mod messages;
mod packet_type;

pub use codec::{KdxCodec, KdxFrame, DEFAULT_MAX_FRAME_PAYLOAD};
pub use flags::{PacketFlags, Priority};
pub use fragment::{fragment, Reassembler};
pub use header::{PacketHeader, HEADER_LEN, MAGIC, PROTOCOL_VERSION};
pub use packet_type::PacketType;

/// Errors arising from framing, parsing, or fragment reassembly.
///
/// All of these are connection-fatal: a byte stream that produced one cannot
/// be resynchronized and must be closed.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("bad magic (not a KDX stream)")]
    BadMagic,
    #[error("header checksum mismatch")]
    BadChecksum,
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown packet type 0x{0:02X}")]
    UnknownPacketType(u8),
    #[error("frame payload of {length} bytes exceeds maximum {max}")]
    PayloadTooLarge { length: u32, max: u32 },
    #[error("fragment sequence out of order: expected {expected}, got {got}")]
    FragmentOutOfOrder { expected: u32, got: u32 },
    #[error("frame interleaved into an open fragment group")]
    FragmentInterleaved,
    #[error("reassembled payload exceeds maximum {max} bytes")]
    ReassemblyTooLarge { max: usize },
    #[error("malformed {0} payload")]
    MalformedPayload(&'static str),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}
