use bytes::{Buf, BufMut};

use crate::{PacketFlags, PacketType, ProtocolError};

/// Wire magic identifying a KDX packet.
pub const MAGIC: [u8; 4] = *b"KDX\0";
/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 1;
/// Fixed header size on the wire.
pub const HEADER_LEN: usize = 20;

/// The 20-byte KDX packet header. All multi-byte fields are big-endian.
///
/// Layout: magic(4) version(1) type(1) flags(2) sequence(4) length(4)
/// reserved(2) checksum(2). The checksum is CRC32C of the preceding 18 bytes
/// folded to 16 bits — a framing-corruption guard only, NOT a security
/// control (integrity and authenticity come from TLS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    pub version: u8,
    pub packet_type: PacketType,
    pub flags: PacketFlags,
    pub sequence: u32,
    pub length: u32,
}

impl PacketHeader {
    /// Serialize the header, computing the trailing checksum.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        let mut head = [0u8; HEADER_LEN - 2];
        head[0..4].copy_from_slice(&MAGIC);
        head[4] = self.version;
        head[5] = self.packet_type as u8;
        head[6..8].copy_from_slice(&self.flags.bits().to_be_bytes());
        head[8..12].copy_from_slice(&self.sequence.to_be_bytes());
        head[12..16].copy_from_slice(&self.length.to_be_bytes());
        // head[16..18] reserved, already zero
        buf.put_slice(&head);
        buf.put_u16(fold_crc(&head));
    }

    /// Parse and validate a header from exactly [`HEADER_LEN`] buffered bytes.
    ///
    /// Advances `buf` by [`HEADER_LEN`]. Errors are connection-fatal: once
    /// framing is desynchronized there is no way to resynchronize the stream.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, ProtocolError> {
        debug_assert!(buf.remaining() >= HEADER_LEN);
        let mut head = [0u8; HEADER_LEN - 2];
        buf.copy_to_slice(&mut head);
        let stored_checksum = buf.get_u16();

        if head[0..4] != MAGIC {
            return Err(ProtocolError::BadMagic);
        }
        if fold_crc(&head) != stored_checksum {
            return Err(ProtocolError::BadChecksum);
        }
        let version = head[4];
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }

        Ok(PacketHeader {
            version,
            packet_type: PacketType::try_from(head[5])?,
            flags: PacketFlags::from_bits_retain(u16::from_be_bytes([head[6], head[7]])),
            sequence: u32::from_be_bytes([head[8], head[9], head[10], head[11]]),
            length: u32::from_be_bytes([head[12], head[13], head[14], head[15]]),
        })
    }
}

/// CRC32C of `data`, folded to 16 bits by XORing the halves.
fn fold_crc(data: &[u8]) -> u16 {
    let crc = crc32fast::hash(data);
    (crc >> 16) as u16 ^ (crc & 0xFFFF) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    fn sample_header() -> PacketHeader {
        PacketHeader {
            version: PROTOCOL_VERSION,
            packet_type: PacketType::ChatMessage,
            flags: PacketFlags::REQUIRES_ACK,
            sequence: 42,
            length: 13,
        }
    }

    #[test]
    fn encode_is_exactly_header_len() {
        let mut buf = BytesMut::new();
        sample_header().encode(&mut buf);
        assert_eq!(buf.len(), HEADER_LEN);
    }

    #[test]
    fn round_trip() {
        let header = sample_header();
        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        let decoded = PacketHeader::decode(&mut buf).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = BytesMut::new();
        sample_header().encode(&mut buf);
        buf[0] = b'X';
        assert!(matches!(
            PacketHeader::decode(&mut buf),
            Err(ProtocolError::BadMagic)
        ));
    }

    #[test]
    fn rejects_corrupted_field() {
        let mut buf = BytesMut::new();
        sample_header().encode(&mut buf);
        buf[9] ^= 0xFF; // flip bits inside the sequence field
        assert!(matches!(
            PacketHeader::decode(&mut buf),
            Err(ProtocolError::BadChecksum)
        ));
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut buf = BytesMut::new();
        // Build a header with a bogus version but a *valid* checksum, so the
        // version check itself is what fires.
        let mut head = [0u8; HEADER_LEN - 2];
        head[0..4].copy_from_slice(&MAGIC);
        head[4] = 99;
        head[5] = PacketType::Ping as u8;
        let crc = super::fold_crc(&head);
        buf.extend_from_slice(&head);
        buf.extend_from_slice(&crc.to_be_bytes());
        assert!(matches!(
            PacketHeader::decode(&mut buf),
            Err(ProtocolError::UnsupportedVersion(99))
        ));
    }
}
