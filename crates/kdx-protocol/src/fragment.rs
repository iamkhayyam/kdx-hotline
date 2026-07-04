//! Splitting oversized payloads across frames and reassembling them.
//!
//! A logical payload larger than the negotiated max frame size is split into
//! N frames sharing consecutive sequence numbers. Every fragment carries
//! `FRAGMENTED`; all but the last also carry `MORE_FRAGMENTS`. The receiver
//! buffers fragments per connection until the terminal one arrives, then
//! yields the reassembled payload for normal dispatch.

use bytes::{Bytes, BytesMut};

use crate::{KdxFrame, PacketFlags, PacketHeader, PacketType, ProtocolError, PROTOCOL_VERSION};

/// Split `payload` into frames of at most `max_payload` bytes each.
///
/// `next_sequence` supplies consecutive sequence numbers (one per frame),
/// mirroring how a connection's monotonic counter is consumed. A payload
/// that fits in one frame is returned unfragmented.
pub fn fragment(
    packet_type: PacketType,
    flags: PacketFlags,
    payload: Bytes,
    max_payload: u32,
    mut next_sequence: impl FnMut() -> u32,
) -> Vec<KdxFrame> {
    let max = max_payload as usize;
    if payload.len() <= max {
        return vec![KdxFrame {
            header: PacketHeader {
                version: PROTOCOL_VERSION,
                packet_type,
                flags,
                sequence: next_sequence(),
                length: payload.len() as u32,
            },
            payload,
        }];
    }

    let mut frames = Vec::with_capacity(payload.len().div_ceil(max));
    let mut remaining = payload;
    while !remaining.is_empty() {
        let take = remaining.len().min(max);
        let chunk = remaining.split_to(take);
        let more = !remaining.is_empty();
        let mut frame_flags = flags | PacketFlags::FRAGMENTED;
        if more {
            frame_flags |= PacketFlags::MORE_FRAGMENTS;
        }
        frames.push(KdxFrame {
            header: PacketHeader {
                version: PROTOCOL_VERSION,
                packet_type,
                flags: frame_flags,
                sequence: next_sequence(),
                length: chunk.len() as u32,
            },
            payload: chunk,
        });
    }
    frames
}

/// Per-connection reassembly state for one in-flight fragmented payload.
///
/// KDX frames arrive in order within a TCP/TLS stream, so only one fragment
/// group can be open at a time; an unfragmented frame or a new group while
/// one is open is a protocol violation.
#[derive(Debug, Default)]
pub struct Reassembler {
    buffer: BytesMut,
    in_progress: Option<GroupState>,
}

#[derive(Debug)]
struct GroupState {
    packet_type: PacketType,
    next_sequence: u32,
    max_total: usize,
}

impl Reassembler {
    /// Feed one frame. Returns a complete logical frame when available:
    /// either the input itself (unfragmented) or the reassembled whole
    /// (terminal fragment). Mid-group fragments return `Ok(None)`.
    ///
    /// `max_total` caps the reassembled payload size (memory-exhaustion
    /// guard); exceeding it is a fatal protocol error.
    pub fn push(&mut self, frame: KdxFrame, max_total: usize) -> Result<Option<KdxFrame>, ProtocolError> {
        let flags = frame.header.flags;
        if !flags.contains(PacketFlags::FRAGMENTED) {
            if self.in_progress.is_some() {
                return Err(ProtocolError::FragmentInterleaved);
            }
            return Ok(Some(frame));
        }

        match &mut self.in_progress {
            None => {
                self.buffer.clear();
                self.buffer.extend_from_slice(&frame.payload);
                if self.buffer.len() > max_total {
                    return Err(ProtocolError::ReassemblyTooLarge { max: max_total });
                }
                let state = GroupState {
                    packet_type: frame.header.packet_type,
                    next_sequence: frame.header.sequence.wrapping_add(1),
                    max_total,
                };
                if flags.contains(PacketFlags::MORE_FRAGMENTS) {
                    self.in_progress = Some(state);
                    Ok(None)
                } else {
                    // Single-fragment group: degenerate but legal.
                    Ok(Some(self.finish(frame.header)))
                }
            }
            Some(state) => {
                if frame.header.packet_type != state.packet_type {
                    return Err(ProtocolError::FragmentInterleaved);
                }
                if frame.header.sequence != state.next_sequence {
                    return Err(ProtocolError::FragmentOutOfOrder {
                        expected: state.next_sequence,
                        got: frame.header.sequence,
                    });
                }
                state.next_sequence = state.next_sequence.wrapping_add(1);
                self.buffer.extend_from_slice(&frame.payload);
                if self.buffer.len() > state.max_total {
                    let max = state.max_total;
                    self.in_progress = None;
                    return Err(ProtocolError::ReassemblyTooLarge { max });
                }
                if flags.contains(PacketFlags::MORE_FRAGMENTS) {
                    Ok(None)
                } else {
                    self.in_progress = None;
                    Ok(Some(self.finish(frame.header)))
                }
            }
        }
    }

    /// True if a fragment group is currently open (used by connection tasks
    /// to enforce a reassembly timeout).
    pub fn is_reassembling(&self) -> bool {
        self.in_progress.is_some()
    }

    /// Drop any partially-reassembled state (e.g. on timeout).
    pub fn abort(&mut self) {
        self.in_progress = None;
        self.buffer.clear();
    }

    fn finish(&mut self, last_header: PacketHeader) -> KdxFrame {
        let payload = self.buffer.split().freeze();
        KdxFrame {
            header: PacketHeader {
                length: payload.len() as u32,
                flags: last_header.flags & !(PacketFlags::FRAGMENTED | PacketFlags::MORE_FRAGMENTS),
                ..last_header
            },
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_TOTAL: usize = 1024 * 1024;

    fn seq_counter() -> impl FnMut() -> u32 {
        let mut next = 0u32;
        move || {
            let s = next;
            next += 1;
            s
        }
    }

    #[test]
    fn small_payload_is_not_fragmented() {
        let frames = fragment(
            PacketType::ChatMessage,
            PacketFlags::empty(),
            Bytes::from_static(b"short"),
            16,
            seq_counter(),
        );
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].header.flags.contains(PacketFlags::FRAGMENTED));
    }

    #[test]
    fn fragments_and_reassembles_three_plus_frames() {
        let payload: Vec<u8> = (0..100u8).collect();
        let frames = fragment(
            PacketType::FileTransferData,
            PacketFlags::empty(),
            Bytes::from(payload.clone()),
            30,
            seq_counter(),
        );
        assert_eq!(frames.len(), 4); // 30+30+30+10
        assert!(frames[..3]
            .iter()
            .all(|f| f.header.flags.contains(PacketFlags::MORE_FRAGMENTS)));
        assert!(!frames[3].header.flags.contains(PacketFlags::MORE_FRAGMENTS));

        let mut reassembler = Reassembler::default();
        let mut out = None;
        for f in frames {
            out = reassembler.push(f, MAX_TOTAL).unwrap();
        }
        let whole = out.expect("terminal fragment must yield the whole");
        assert_eq!(&whole.payload[..], &payload[..]);
        assert_eq!(whole.header.length as usize, payload.len());
        assert!(!whole.header.flags.contains(PacketFlags::FRAGMENTED));
    }

    #[test]
    fn unfragmented_passes_through() {
        let mut reassembler = Reassembler::default();
        let frames = fragment(
            PacketType::Ping,
            PacketFlags::empty(),
            Bytes::from_static(b"hi"),
            16,
            seq_counter(),
        );
        let out = reassembler.push(frames[0].clone(), MAX_TOTAL).unwrap();
        assert_eq!(out.unwrap().payload, Bytes::from_static(b"hi"));
    }

    #[test]
    fn out_of_order_fragment_is_fatal() {
        let payload: Vec<u8> = (0..100u8).collect();
        let frames = fragment(
            PacketType::FileTransferData,
            PacketFlags::empty(),
            Bytes::from(payload),
            30,
            seq_counter(),
        );
        let mut reassembler = Reassembler::default();
        reassembler.push(frames[0].clone(), MAX_TOTAL).unwrap();
        // Skip frames[1], feed frames[2].
        assert!(matches!(
            reassembler.push(frames[2].clone(), MAX_TOTAL),
            Err(ProtocolError::FragmentOutOfOrder { .. })
        ));
    }

    #[test]
    fn interleaved_unfragmented_frame_is_fatal() {
        let payload: Vec<u8> = (0..100u8).collect();
        let frames = fragment(
            PacketType::FileTransferData,
            PacketFlags::empty(),
            Bytes::from(payload),
            30,
            seq_counter(),
        );
        let mut reassembler = Reassembler::default();
        reassembler.push(frames[0].clone(), MAX_TOTAL).unwrap();
        let stray = fragment(
            PacketType::Ping,
            PacketFlags::empty(),
            Bytes::from_static(b"hi"),
            16,
            seq_counter(),
        );
        assert!(matches!(
            reassembler.push(stray[0].clone(), MAX_TOTAL),
            Err(ProtocolError::FragmentInterleaved)
        ));
    }

    #[test]
    fn reassembly_size_guard_trips() {
        let payload: Vec<u8> = vec![0; 100];
        let frames = fragment(
            PacketType::FileTransferData,
            PacketFlags::empty(),
            Bytes::from(payload),
            30,
            seq_counter(),
        );
        let mut reassembler = Reassembler::default();
        let mut tripped = false;
        for f in frames {
            match reassembler.push(f, 50) {
                Err(ProtocolError::ReassemblyTooLarge { max: 50 }) => {
                    tripped = true;
                    break;
                }
                Err(e) => panic!("unexpected error: {e}"),
                Ok(_) => {}
            }
        }
        assert!(tripped);
    }

    #[test]
    fn abort_clears_state() {
        let payload: Vec<u8> = (0..100u8).collect();
        let frames = fragment(
            PacketType::FileTransferData,
            PacketFlags::empty(),
            Bytes::from(payload),
            30,
            seq_counter(),
        );
        let mut reassembler = Reassembler::default();
        reassembler.push(frames[0].clone(), MAX_TOTAL).unwrap();
        assert!(reassembler.is_reassembling());
        reassembler.abort();
        assert!(!reassembler.is_reassembling());
        // A fresh unfragmented frame is accepted after abort.
        let ping = fragment(
            PacketType::Ping,
            PacketFlags::empty(),
            Bytes::from_static(b"hi"),
            16,
            seq_counter(),
        );
        assert!(reassembler.push(ping[0].clone(), MAX_TOTAL).unwrap().is_some());
    }
}
