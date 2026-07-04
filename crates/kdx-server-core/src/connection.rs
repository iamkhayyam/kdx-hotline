//! Per-connection state machine. Generic over the byte stream so tests can
//! drive it with `tokio::io::duplex` instead of a real TLS socket; `kdxd`
//! hands it a `TlsStream<TcpStream>`.
//!
//! Lifecycle: KDX handshake → authentication (challenge-response) → active
//! dispatch. Ping/Pong and Disconnect work in every phase after the
//! handshake; everything else requires a live session.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use kdx_protocol::messages::{
    AuthChallenge, AuthRequest, AuthResponse, AuthResult, HandshakeInit, HandshakeResp,
};
use kdx_protocol::{
    KdxCodec, KdxFrame, PacketFlags, PacketHeader, PacketType, ProtocolError, Reassembler,
    PROTOCOL_VERSION,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_util::codec::Framed;
use tracing::{debug, warn};

use crate::auth::{AuthManager, Session};

/// How long the client has to send `HandshakeInit` after connecting.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the client has to complete authentication after the handshake.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(60);
/// How long an open fragment group may sit incomplete before the connection
/// is dropped (memory-exhaustion guard, paired with the size cap below).
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap on a reassembled logical payload.
pub const MAX_REASSEMBLED_PAYLOAD: usize = 4 * 1024 * 1024;
/// Feature bits the server currently supports (none defined yet).
pub const SERVER_FEATURES: u16 = 0;
/// Failed login attempts allowed before the connection is dropped.
pub const MAX_AUTH_ATTEMPTS: u8 = 3;

/// Shared server-wide services handed to every connection.
pub struct ServerCtx {
    pub auth: AuthManager,
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("client did not complete handshake in time")]
    HandshakeTimeout,
    #[error("client did not authenticate in time")]
    AuthTimeout,
    #[error("too many failed login attempts")]
    TooManyAuthAttempts,
    #[error("expected {expected}, got {got:?}")]
    UnexpectedPacket {
        expected: &'static str,
        got: PacketType,
    },
    #[error("fragment group left incomplete past reassembly timeout")]
    ReassemblyTimeout,
    #[error("peer closed the connection")]
    PeerClosed,
    #[error("auth backend failure: {0}")]
    Auth(#[from] crate::auth::AuthError),
}

/// Drives one client connection from handshake through active dispatch.
pub struct Connection<S> {
    framed: Framed<S, KdxCodec>,
    ctx: Arc<ServerCtx>,
    reassembler: Reassembler,
    session: Option<Session>,
    /// Monotonic sequence counter for server-sent frames.
    next_sequence: u32,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    pub fn new(stream: S, ctx: Arc<ServerCtx>) -> Self {
        Self {
            framed: Framed::new(stream, KdxCodec::default()),
            ctx,
            reassembler: Reassembler::default(),
            session: None,
            next_sequence: 0,
        }
    }

    /// Run the connection to completion.
    pub async fn run(mut self) -> Result<(), ConnectionError> {
        self.handshake().await?;
        if !self.authenticate().await? {
            return Ok(()); // clean disconnect during auth
        }
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
            return Err(ConnectionError::UnexpectedPacket {
                expected: "HandshakeInit",
                got: frame.header.packet_type,
            });
        }
        let init = HandshakeInit::decode(&frame.payload)?;
        debug!(version = init.version, features = init.features, "handshake init");

        let resp = HandshakeResp {
            version: PROTOCOL_VERSION,
            features: init.features & SERVER_FEATURES,
        };
        self.send(PacketType::HandshakeResp, PacketFlags::empty(), resp.encode())
            .await?;
        Ok(())
    }

    /// Challenge-response login. Returns `false` on clean disconnect,
    /// `true` once a session is established. Ping/Pong stays available so
    /// clients can keep the connection warm at a login prompt.
    async fn authenticate(&mut self) -> Result<bool, ConnectionError> {
        let deadline = tokio::time::Instant::now() + AUTH_TIMEOUT;
        let mut failures: u8 = 0;

        loop {
            let frame = timeout_at(deadline, self.framed.next())
                .await
                .map_err(|_| ConnectionError::AuthTimeout)?
                .ok_or(ConnectionError::PeerClosed)??;

            match frame.header.packet_type {
                PacketType::Ping => {
                    self.send(PacketType::Pong, PacketFlags::empty(), frame.payload)
                        .await?;
                }
                PacketType::Disconnect => return Ok(false),
                PacketType::AuthRequest => {
                    let request = AuthRequest::decode(&frame.payload)?;
                    let (data, pending) = self.ctx.auth.begin(&request.username).await?;
                    let challenge_msg = AuthChallenge {
                        challenge: data.challenge,
                        salt: data.salt,
                        m_cost: data.params.m_cost,
                        t_cost: data.params.t_cost,
                        p_cost: data.params.p_cost,
                    };
                    self.send(
                        PacketType::AuthChallenge,
                        PacketFlags::empty(),
                        challenge_msg.encode(),
                    )
                    .await?;

                    // The very next auth packet must be the response.
                    let response_frame = timeout_at(deadline, self.framed.next())
                        .await
                        .map_err(|_| ConnectionError::AuthTimeout)?
                        .ok_or(ConnectionError::PeerClosed)??;
                    if response_frame.header.packet_type != PacketType::AuthResponse {
                        return Err(ConnectionError::UnexpectedPacket {
                            expected: "AuthResponse",
                            got: response_frame.header.packet_type,
                        });
                    }
                    let response = AuthResponse::decode(&response_frame.payload)?;

                    match self.ctx.auth.complete(pending, &response.response) {
                        Ok(session) => {
                            let result = AuthResult {
                                success: true,
                                session_id: *session.id.as_bytes(),
                                class: session.class as u8,
                                message: format!("welcome, {}", session.username),
                            };
                            self.send(PacketType::AuthResult, PacketFlags::empty(), result.encode())
                                .await?;
                            debug!(user = %session.username, "authenticated");
                            self.session = Some(session);
                            return Ok(true);
                        }
                        Err(crate::auth::AuthError::InvalidCredentials) => {
                            failures += 1;
                            let result = AuthResult {
                                success: false,
                                session_id: [0u8; 16],
                                class: 0,
                                message: "invalid credentials".into(),
                            };
                            self.send(PacketType::AuthResult, PacketFlags::empty(), result.encode())
                                .await?;
                            if failures >= MAX_AUTH_ATTEMPTS {
                                return Err(ConnectionError::TooManyAuthAttempts);
                            }
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                got => {
                    return Err(ConnectionError::UnexpectedPacket {
                        expected: "AuthRequest",
                        got,
                    })
                }
            }
        }
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
                    if let Some(session) = &self.session {
                        self.ctx.auth.end_session(session.id);
                    }
                    debug!("client disconnected cleanly");
                    return Ok(());
                }
                other => {
                    // Later milestones route chat/file packets here.
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

async fn timeout_at<F: std::future::Future>(
    deadline: tokio::time::Instant,
    future: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    tokio::time::timeout_at(deadline, future).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Privileges;
    use kdx_crypto::{client_response, hash_password};
    use kdx_storage::accounts;

    async fn test_ctx() -> (Arc<ServerCtx>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = kdx_storage::connect(&dir.path().join("test.db"))
            .await
            .unwrap();
        let phc = hash_password("s3cret").unwrap();
        accounts::create(&pool, "phraq", &phc, 2).await.unwrap();
        let ctx = Arc::new(ServerCtx {
            auth: AuthManager::new(pool, Duration::from_secs(60)),
        });
        (ctx, dir)
    }

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

    async fn do_handshake(client: &mut Framed<tokio::io::DuplexStream, KdxCodec>, seq: &mut u32) {
        let init = HandshakeInit {
            version: PROTOCOL_VERSION,
            features: 0,
        };
        client
            .send(client_frame(PacketType::HandshakeInit, bump(seq), init.encode()))
            .await
            .unwrap();
        let resp = client.next().await.unwrap().unwrap();
        assert_eq!(resp.header.packet_type, PacketType::HandshakeResp);
    }

    /// Run one login round; returns the AuthResult.
    async fn do_login(
        client: &mut Framed<tokio::io::DuplexStream, KdxCodec>,
        seq: &mut u32,
        username: &str,
        password: &str,
    ) -> AuthResult {
        let request = AuthRequest {
            username: username.into(),
        };
        client
            .send(client_frame(PacketType::AuthRequest, bump(seq), request.encode()))
            .await
            .unwrap();
        let challenge_frame = client.next().await.unwrap().unwrap();
        assert_eq!(challenge_frame.header.packet_type, PacketType::AuthChallenge);
        let challenge = AuthChallenge::decode(&challenge_frame.payload).unwrap();

        let response = client_response(
            password,
            &challenge.salt,
            &kdx_crypto::KdfParams {
                m_cost: challenge.m_cost,
                t_cost: challenge.t_cost,
                p_cost: challenge.p_cost,
            },
            &challenge.challenge,
        )
        .unwrap();
        client
            .send(client_frame(
                PacketType::AuthResponse,
                bump(seq),
                AuthResponse { response }.encode(),
            ))
            .await
            .unwrap();

        let result_frame = client.next().await.unwrap().unwrap();
        assert_eq!(result_frame.header.packet_type, PacketType::AuthResult);
        AuthResult::decode(&result_frame.payload).unwrap()
    }

    fn bump(seq: &mut u32) -> u32 {
        let s = *seq;
        *seq += 1;
        s
    }

    #[tokio::test]
    async fn successful_login_reaches_active_state() {
        let (ctx, _dir) = test_ctx().await;
        let (client, server) = tokio::io::duplex(4096);
        let conn = tokio::spawn(Connection::new(server, ctx.clone()).run());
        let mut client = client_framed(client);
        let mut seq = 0;

        do_handshake(&mut client, &mut seq).await;
        let result = do_login(&mut client, &mut seq, "phraq", "s3cret").await;
        assert!(result.success);
        assert_eq!(result.class, 2); // PowerUser
        assert_ne!(result.session_id, [0u8; 16]);

        // Session is registered with correct effective privileges.
        let session_id = uuid::Uuid::from_bytes(result.session_id);
        let session = ctx.auth.validate(session_id).unwrap();
        assert!(session.privileges.contains(Privileges::CHAT_CREATE_ROOM));

        // Post-auth Ping still works (Active state reached).
        client
            .send(client_frame(PacketType::Ping, bump(&mut seq), Bytes::from_static(b"hi")))
            .await
            .unwrap();
        let pong = client.next().await.unwrap().unwrap();
        assert_eq!(pong.header.packet_type, PacketType::Pong);

        client
            .send(client_frame(PacketType::Disconnect, bump(&mut seq), Bytes::new()))
            .await
            .unwrap();
        conn.await.unwrap().unwrap();

        // Disconnect ended the session.
        assert!(ctx.auth.validate(session_id).is_none());
    }

    #[tokio::test]
    async fn wrong_password_then_retry_succeeds() {
        let (ctx, _dir) = test_ctx().await;
        let (client, server) = tokio::io::duplex(4096);
        let conn = tokio::spawn(Connection::new(server, ctx).run());
        let mut client = client_framed(client);
        let mut seq = 0;

        do_handshake(&mut client, &mut seq).await;
        let first = do_login(&mut client, &mut seq, "phraq", "wrong").await;
        assert!(!first.success);
        let second = do_login(&mut client, &mut seq, "phraq", "s3cret").await;
        assert!(second.success);

        client
            .send(client_frame(PacketType::Disconnect, bump(&mut seq), Bytes::new()))
            .await
            .unwrap();
        conn.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn three_failures_drop_the_connection() {
        let (ctx, _dir) = test_ctx().await;
        let (client, server) = tokio::io::duplex(4096);
        let conn = tokio::spawn(Connection::new(server, ctx).run());
        let mut client = client_framed(client);
        let mut seq = 0;

        do_handshake(&mut client, &mut seq).await;
        for _ in 0..3 {
            let result = do_login(&mut client, &mut seq, "phraq", "wrong").await;
            assert!(!result.success);
        }
        assert!(matches!(
            conn.await.unwrap().unwrap_err(),
            ConnectionError::TooManyAuthAttempts
        ));
    }

    #[tokio::test]
    async fn chat_before_auth_is_rejected() {
        let (ctx, _dir) = test_ctx().await;
        let (client, server) = tokio::io::duplex(4096);
        let conn = tokio::spawn(Connection::new(server, ctx).run());
        let mut client = client_framed(client);
        let mut seq = 0;

        do_handshake(&mut client, &mut seq).await;
        client
            .send(client_frame(
                PacketType::ChatMessage,
                bump(&mut seq),
                Bytes::from_static(b"sneaky"),
            ))
            .await
            .unwrap();
        assert!(matches!(
            conn.await.unwrap().unwrap_err(),
            ConnectionError::UnexpectedPacket { .. }
        ));
    }

    #[tokio::test]
    async fn rejects_non_handshake_first_packet() {
        let (ctx, _dir) = test_ctx().await;
        let (client, server) = tokio::io::duplex(4096);
        let conn = tokio::spawn(Connection::new(server, ctx).run());
        let mut client = client_framed(client);

        client
            .send(client_frame(
                PacketType::ChatMessage,
                0,
                Bytes::from_static(b"too eager"),
            ))
            .await
            .unwrap();
        assert!(matches!(
            conn.await.unwrap().unwrap_err(),
            ConnectionError::UnexpectedPacket { .. }
        ));
    }

    #[tokio::test]
    async fn peer_close_before_handshake_is_reported() {
        let (ctx, _dir) = test_ctx().await;
        let (client, server) = tokio::io::duplex(4096);
        let conn = tokio::spawn(Connection::new(server, ctx).run());
        drop(client);
        assert!(matches!(
            conn.await.unwrap().unwrap_err(),
            ConnectionError::PeerClosed
        ));
    }
}
