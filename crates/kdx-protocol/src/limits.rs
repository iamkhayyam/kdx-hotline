//! Size caps on reassembled (logical) messages, shared by both peers so a
//! client never sends something the server is bound to reject.
//!
//! Fragmentation lets a logical message span many 16 KiB frames; the
//! receiver caps how much it will buffer per message. The server caps
//! client requests by type (small for control traffic, larger only where a
//! message legitimately carries bulk data); clients accept server messages
//! up to [`MAX_REASSEMBLED_PAYLOAD`].

use crate::PacketType;

/// Largest logical message either peer sends or reassembles.
pub const MAX_REASSEMBLED_PAYLOAD: usize = 4 * 1024 * 1024;
/// Server cap on a client control message (anything but transfer traffic).
pub const MAX_CONTROL_PAYLOAD: usize = 64 * 1024;
/// Server cap on a client `FileTransferStart`, which carries a resume bitmap
/// that can outgrow [`MAX_CONTROL_PAYLOAD`] for large files.
pub const MAX_TRANSFER_START_PAYLOAD: usize = 1024 * 1024;

/// The largest logical payload the server accepts from a client for
/// `packet_type`. Clients must refuse to send anything larger (the server
/// treats an over-cap message as a protocol violation).
pub fn max_request_payload(packet_type: PacketType) -> usize {
    match packet_type {
        PacketType::FileTransferData => MAX_REASSEMBLED_PAYLOAD,
        PacketType::FileTransferStart => MAX_TRANSFER_START_PAYLOAD,
        _ => MAX_CONTROL_PAYLOAD,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_traffic_gets_the_bigger_caps() {
        assert_eq!(max_request_payload(PacketType::FileTransferData), MAX_REASSEMBLED_PAYLOAD);
        assert_eq!(max_request_payload(PacketType::FileTransferStart), MAX_TRANSFER_START_PAYLOAD);
        assert_eq!(max_request_payload(PacketType::ChatSend), MAX_CONTROL_PAYLOAD);
        assert!(MAX_CONTROL_PAYLOAD < MAX_TRANSFER_START_PAYLOAD);
        assert!(MAX_TRANSFER_START_PAYLOAD < MAX_REASSEMBLED_PAYLOAD);
    }
}
