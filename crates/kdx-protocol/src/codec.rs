use bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::{PacketHeader, ProtocolError, HEADER_LEN};

/// Default cap on a single frame's payload. Larger logical payloads must be
/// fragmented by the sender (see [`crate::fragment`]).
pub const DEFAULT_MAX_FRAME_PAYLOAD: u32 = 16 * 1024;

/// One decoded wire frame: a validated header plus its raw payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdxFrame {
    pub header: PacketHeader,
    pub payload: Bytes,
}

/// Length-delimited codec for KDX frames over any byte stream.
#[derive(Debug)]
pub struct KdxCodec {
    /// Maximum payload length this side will accept in one frame. Frames
    /// claiming more are rejected before buffering (DoS guard).
    max_payload: u32,
    /// Header decoded while waiting for the rest of its payload to arrive.
    pending: Option<PacketHeader>,
}

impl KdxCodec {
    pub fn new(max_payload: u32) -> Self {
        Self {
            max_payload,
            pending: None,
        }
    }
}

impl Default for KdxCodec {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FRAME_PAYLOAD)
    }
}

impl Decoder for KdxCodec {
    type Item = KdxFrame;
    type Error = ProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<KdxFrame>, ProtocolError> {
        let header = match self.pending.take() {
            Some(h) => h,
            None => {
                if src.len() < HEADER_LEN {
                    return Ok(None);
                }
                let header = PacketHeader::decode(src)?;
                if header.length > self.max_payload {
                    return Err(ProtocolError::PayloadTooLarge {
                        length: header.length,
                        max: self.max_payload,
                    });
                }
                header
            }
        };

        if src.len() < header.length as usize {
            // Ask for exactly what's missing and park the parsed header.
            src.reserve(header.length as usize - src.len());
            self.pending = Some(header);
            return Ok(None);
        }

        let payload = src.split_to(header.length as usize).freeze();
        Ok(Some(KdxFrame { header, payload }))
    }
}

impl Encoder<KdxFrame> for KdxCodec {
    type Error = ProtocolError;

    fn encode(&mut self, frame: KdxFrame, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        debug_assert_eq!(frame.header.length as usize, frame.payload.len());
        if frame.header.length > self.max_payload {
            return Err(ProtocolError::PayloadTooLarge {
                length: frame.header.length,
                max: self.max_payload,
            });
        }
        dst.reserve(HEADER_LEN + frame.payload.len());
        frame.header.encode(dst);
        dst.extend_from_slice(&frame.payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PacketFlags, PacketType, PROTOCOL_VERSION};

    fn frame(packet_type: PacketType, sequence: u32, payload: &[u8]) -> KdxFrame {
        KdxFrame {
            header: PacketHeader {
                version: PROTOCOL_VERSION,
                packet_type,
                flags: PacketFlags::empty(),
                sequence,
                length: payload.len() as u32,
            },
            payload: Bytes::copy_from_slice(payload),
        }
    }

    #[test]
    fn round_trips_every_packet_type() {
        for (i, packet_type) in PacketType::ALL.into_iter().enumerate() {
            let mut codec = KdxCodec::default();
            let original = frame(packet_type, i as u32, b"payload");
            let mut buf = BytesMut::new();
            codec.encode(original.clone(), &mut buf).unwrap();
            let decoded = codec.decode(&mut buf).unwrap().unwrap();
            assert_eq!(decoded, original);
            assert!(buf.is_empty());
        }
    }

    #[test]
    fn round_trips_empty_payload() {
        let mut codec = KdxCodec::default();
        let original = frame(PacketType::Ping, 0, b"");
        let mut buf = BytesMut::new();
        codec.encode(original.clone(), &mut buf).unwrap();
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap(), original);
    }

    #[test]
    fn decodes_across_partial_reads() {
        let mut codec = KdxCodec::default();
        let original = frame(PacketType::ChatMessage, 7, b"hello, underground");
        let mut wire = BytesMut::new();
        codec.encode(original.clone(), &mut wire).unwrap();

        // Feed one byte at a time; must yield nothing until complete.
        let mut buf = BytesMut::new();
        let mut result = None;
        for byte in wire.iter() {
            buf.extend_from_slice(&[*byte]);
            if let Some(f) = codec.decode(&mut buf).unwrap() {
                result = Some(f);
            }
        }
        assert_eq!(result.unwrap(), original);
    }

    #[test]
    fn decodes_multiple_frames_from_one_buffer() {
        let mut codec = KdxCodec::default();
        let a = frame(PacketType::Ping, 1, b"a");
        let b = frame(PacketType::Pong, 2, b"bb");
        let mut buf = BytesMut::new();
        codec.encode(a.clone(), &mut buf).unwrap();
        codec.encode(b.clone(), &mut buf).unwrap();
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap(), a);
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap(), b);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn rejects_oversized_frame_before_buffering() {
        let mut codec = KdxCodec::new(64);
        let original = frame(PacketType::FileTransferData, 0, &[0u8; 65]);
        let mut buf = BytesMut::new();
        assert!(matches!(
            codec.encode(original, &mut buf),
            Err(ProtocolError::PayloadTooLarge { .. })
        ));

        // Decoder side: hand-craft a header claiming a huge payload.
        let header = PacketHeader {
            version: PROTOCOL_VERSION,
            packet_type: PacketType::FileTransferData,
            flags: PacketFlags::empty(),
            sequence: 0,
            length: 1_000_000,
        };
        let mut wire = BytesMut::new();
        header.encode(&mut wire);
        assert!(matches!(
            codec.decode(&mut wire),
            Err(ProtocolError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn corrupted_header_is_fatal() {
        let mut codec = KdxCodec::default();
        let original = frame(PacketType::Ping, 0, b"x");
        let mut buf = BytesMut::new();
        codec.encode(original, &mut buf).unwrap();
        buf[8] ^= 0xFF;
        assert!(codec.decode(&mut buf).is_err());
    }
}
