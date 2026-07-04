//! Per-connection state machine. Generic over the byte stream so tests can
//! drive it with `tokio::io::duplex` instead of a real TLS socket; `kdxd`
//! hands it a `TlsStream<TcpStream>`.

use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use kdx_protocol::messages::{HandshakeInit, HandshakeResp};
use kdx_protocol::{
    KdxCodec, KdxFrame, PacketFlags, PacketHeader, PacketType, ProtocolError, Reassembler,
    PROTOCOL_VERSION,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_util::codec::Framed;
use tracing::{debug, warn};

/// How long the client has to send `HandshakeInit` after connecting.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long an open fragment group may sit incomplete before the connection
/// is dropped (memory-exhaustion guard, paired with the size cap below).
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap on a reassembled logical payload.
pub const MAX_REASSEMBLED_PAYLOAD: usize = 4 * 1024 * 1024;
/// Feature bits the server currently supports (none defined yet).
pub const SERVER_FEATURES: u16 = 0;

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("client did not complete handshake in time")]
    HandshakeTimeout,
    #[error("expected HandshakeInit, got {0:?}")]
    UnexpectedPacket(PacketType),
    #[error("fragment group left incomplete past reassembly timeout")]
    ReassemblyTimeout,
    #[error("peer closed the connection")]
    PeerClosed,
}

/// Drives one client connection from handshake through active dispatch.
pub struct Connection<S> {
    framed: Framed<S, KdxCodec>,
    reassembler: Reassembler,
    /// Monotonic sequence counter for server-sent frames.
    next_sequence: u32,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    pub fn new(stream: S) -> Self {
        Self {
            framed: Framed::new(stream, KdxCodec::default()),
            reassembler: Reassembler::default(),
            next_sequence: 0,
        }
    }

    /// Run the connection to completion: handshake, then dispatch loop.
    pub async fn run(mut self) -> Result<(), ConnectionError> {
        self.handshake().await?;
        self.dispatch_loop().await
    }

    /// Wait for `HandshakeInit`, validate the version, reply with
    /// `HandshakeResp` carrying the feature intersection.
    async fn handshake(&mut self) -> Result<(), ConnectionError> {
        let frame = timeout(HANDSHAKE_TIMEOUT, self.framed.next())
            .await
            .map_err(|_| ConnectionError::HandshakeTimeout)?
            .ok_or(ConnectionError::PeerClosed)??;

        if frame.header.packet_type != PacketType::HandshakeInit {
            return Err(ConnectionError::UnexpectedPacket(frame.header.packet_type));
        }
        let init = HandshakeInit::decode(&frame.payload)?;
        debug!(version = init.version, features = init.features, "handshake init");

        // The codec already rejected mismatched header versions, but the
        // payload restates the client's version; trust the stricter check.
        let resp = HandshakeResp {
            version: PROTOCOL_VERSION,
            features: init.features & SERVER_FEATURES,
        };
        self.send(PacketType::HandshakeResp, PacketFlags::empty(), resp.encode())
            .await?;
        Ok(())
    }

    async fn dispatch_loop(&mut self) -> Result<(), ConnectionError> {
        loop {
            let next = if self.reassembler.is_reassembling() {
                // A fragment group is open: the peer must finish it promptly.
                match timeout(REASSEMBLY_TIMEOUT, self.framed.next()).await {
                    Err(_) => {
                        self.reassembler.abort();
                        return Err(ConnectionError::ReassemblyTimeout);
                    }
                    Ok(item) => item,
                }
            } else {
                self.framed.next().await
            };

            let Some(frame) = next.transpose()? else {
                return Ok(()); // clean EOF
            };

            let Some(frame) = self
                .reassembler
                .push(frame, MAX_REASSEMBLED_PAYLOAD)?
            else {
                continue; // mid-group fragment
            };

            match frame.header.packet_type {
                PacketType::Ping => {
                    self.send(PacketType::Pong, PacketFlags::empty(), frame.payload)
                        .await?;
                }
                PacketType::Disconnect => {
                    debug!("client disconnected cleanly");
                    return Ok(());
                }
                other => {
                    // Later milestones route auth/chat/file packets here.
                    warn!(packet_type = ?other, "unhandled packet type");
                    self.send(
                        PacketType::Error,
                        PacketFlags::SYSTEM_MESSAGE,
                        Bytes::from_static(b"unhandled packet type"),
                    )
                    .await?;
                }
            }
        }
    }

    async fn send(
        &mut self,
        packet_type: PacketType,
        flags: PacketFlags,
        payload: Bytes,
    ) -> Result<(), ProtocolError> {
        let header = PacketHeader {
            version: PROTOCOL_VERSION,
            packet_type,
            flags,
            sequence: self.next_sequence,
            length: payload.len() as u32,
        };
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.framed.send(KdxFrame { header, payload }).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// Client-side helper: framed codec over the test end of the pipe.
    fn client_framed(
        stream: tokio::io::DuplexStream,
    ) -> Framed<tokio::io::DuplexStream, KdxCodec> {
        Framed::new(stream, KdxCodec::default())
    }

    fn client_frame(packet_type: PacketType, sequence: u32, payload: Bytes) -> KdxFrame {
        KdxFrame {
            header: PacketHeader {
                version: PROTOCOL_VERSION,
                packet_type,
                flags: PacketFlags::empty(),
                sequence,
                length: payload.len() as u32,
            },
            payload,
        }
    }

    #[tokio::test]
    async fn handshake_then_ping_pong() {
        let (client, server) = duplex(4096);
        let conn = tokio::spawn(Connection::new(server).run());
        let mut client = client_framed(client);

        let init = HandshakeInit {
            version: PROTOCOL_VERSION,
            features: 0xFFFF,
        };
        client
            .send(client_frame(PacketType::HandshakeInit, 0, init.encode()))
            .await
            .unwrap();

        let resp_frame = client.next().await.unwrap().unwrap();
        assert_eq!(resp_frame.header.packet_type, PacketType::HandshakeResp);
        let resp = HandshakeResp::decode(&resp_frame.payload).unwrap();
        assert_eq!(resp.version, PROTOCOL_VERSION);
        assert_eq!(resp.features, 0); // no server features yet

        client
            .send(client_frame(
                PacketType::Ping,
                1,
                Bytes::from_static(b"echo me"),
            ))
            .await
            .unwrap();
        let pong = client.next().await.unwrap().unwrap();
        assert_eq!(pong.header.packet_type, PacketType::Pong);
        assert_eq!(&pong.payload[..], b"echo me");

        client
            .send(client_frame(PacketType::Disconnect, 2, Bytes::new()))
            .await
            .unwrap();
        conn.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rejects_non_handshake_first_packet() {
        let (client, server) = duplex(4096);
        let conn = tokio::spawn(Connection::new(server).run());
        let mut client = client_framed(client);

        client
            .send(client_frame(
                PacketType::ChatMessage,
                0,
                Bytes::from_static(b"too eager"),
            ))
            .await
            .unwrap();

        let err = conn.await.unwrap().unwrap_err();
        assert!(matches!(
            err,
            ConnectionError::UnexpectedPacket(PacketType::ChatMessage)
        ));
    }

    #[tokio::test]
    async fn peer_close_before_handshake_is_reported() {
        let (client, server) = duplex(4096);
        let conn = tokio::spawn(Connection::new(server).run());
        drop(client);
        assert!(matches!(
            conn.await.unwrap().unwrap_err(),
            ConnectionError::PeerClosed
        ));
    }
}
