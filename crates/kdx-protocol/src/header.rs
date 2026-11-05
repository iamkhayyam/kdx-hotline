use bytes::{Buf, BufMut};

use crate::{PacketFlags, PacketType, ProtocolError};

/// Wire magic identifying a KDX packet.
pub const MAGIC: [u8; 4] = *b"KDX\0";
/// Current protocol version. v2: SCRAM-style, TLS-channel-bound login proof
/// (`AuthResponse` semantics changed, `AuthResult` gained a server
/// signature); v1 peers are rejected at the frame header.
pub const PROTOCOL_VERSION: u8 = 2;
/// Fixed header size on the wire.
pub const HEADER_LEN: usize = 20;

/// The 20-byte KDX packet header. All multi-byte fields are big-endian.
///
/// Layout: magic(4) version(1) type(1) flags(2) sequence(4) length(4)
/// reserved(2) checksum(2). The reserved bytes must be zero. The checksum is
/// CRC-32 (IEEE 802.3, the zlib/PNG/Ethernet polynomial — NOT CRC-32C) of the
/// preceding 18 bytes folded to 16 bits — a framing-corruption guard only,
/// NOT a security control (integrity and authenticity come from TLS).
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
    /// Fewer than [`HEADER_LEN`] buffered bytes is an `UnexpectedEof` error.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, ProtocolError> {
        if buf.remaining() < HEADER_LEN {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
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
        // Checked after the version so a future version is free to give these
        // bytes a meaning; in this version a nonzero value is non-canonical.
        if head[16..18] != [0, 0] {
            return Err(ProtocolError::NonZeroReserved);
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

/// CRC-32 (IEEE 802.3; reflected polynomial 0xEDB88320, init and xorout
/// 0xFFFFFFFF — what `crc32fast` and zlib compute) of `data`, folded to 16
/// bits by XORing the halves.
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

    #[test]
    fn checksum_is_crc32_ieee_not_crc32c() {
        // Standard check input "123456789": CRC-32/IEEE = 0xCBF43926,
        // whereas CRC-32C (Castagnoli) would be 0xE3069283.
        assert_eq!(crc32fast::hash(b"123456789"), 0xCBF4_3926);
        assert_eq!(fold_crc(b"123456789"), 0xCBF4 ^ 0x3926);
        assert_ne!(fold_crc(b"123456789"), 0xE306 ^ 0x9283);
    }

    #[test]
    fn spec_example_header_bytes() {
        // The worked example in docs/spec.html ("Wire representation"):
        // ChatMessage, REQUIRES_ACK, sequence 42, 13-byte payload. The
        // checksum was computed independently with zlib's crc32.
        let mut buf = BytesMut::new();
        sample_header().encode(&mut buf);
        let expected: [u8; HEADER_LEN] = [
            b'K', b'D', b'X', 0, // magic
            0x02, // version (PROTOCOL_VERSION)
            0x30, // type = ChatMessage
            0x00, 0x08, // flags = REQUIRES_ACK
            0x00, 0x00, 0x00, 0x2A, // sequence = 42
            0x00, 0x00, 0x00, 0x0D, // length = 13
            0x00, 0x00, // reserved
            0x6E, 0x91, // folded CRC-32 (0x8A84E415 -> 0x8A84 ^ 0xE415)
        ];
        assert_eq!(&buf[..], &expected[..]);
    }

    #[test]
    fn encoder_writes_zero_reserved_bytes() {
        let mut buf = BytesMut::new();
        PacketHeader {
            version: PROTOCOL_VERSION,
            packet_type: PacketType::Info,
            flags: PacketFlags::from_bits_retain(0xFFFF),
            sequence: u32::MAX,
            length: u32::MAX,
        }
        .encode(&mut buf);
        assert_eq!(&buf[16..18], &[0, 0]);
    }

    #[test]
    fn rejects_nonzero_reserved_bytes() {
        for reserved in [[0x00, 0x01], [0x80, 0x00], [0xFF, 0xFF]] {
            // Valid checksum over the nonzero reserved bytes, so the reserved
            // check itself is what fires.
            let mut head = [0u8; HEADER_LEN - 2];
            head[0..4].copy_from_slice(&MAGIC);
            head[4] = PROTOCOL_VERSION;
            head[5] = PacketType::Ping as u8;
            head[16..18].copy_from_slice(&reserved);
            let mut buf = BytesMut::new();
            buf.extend_from_slice(&head);
            buf.extend_from_slice(&fold_crc(&head).to_be_bytes());
            assert!(matches!(
                PacketHeader::decode(&mut buf),
                Err(ProtocolError::NonZeroReserved)
            ));
        }
    }

    #[test]
    fn short_buffer_is_an_error_not_a_panic() {
        let mut buf = BytesMut::new();
        sample_header().encode(&mut buf);
        for len in 0..HEADER_LEN {
            let mut short = &buf[..len];
            assert!(PacketHeader::decode(&mut short).is_err());
        }
    }
}
