//! The connection actor: one task owning the TLS socket. It is the sole
//! reader and writer of the stream, owns the sequence counter, correlates
//! request/response pairs (the wire has no request IDs, so correlation is
//! FIFO-per-response-type), and turns unsolicited server frames into events.

use std::collections::VecDeque;
use std::io;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use kdx_protocol::messages::{
    AuthChallenge, AuthRequest, AuthResponse, AuthResult, ChatJoin, ChatLeave, ChatSend, ChatTopic,
    ChatUserList, FileListRequest, FileListResponse,
};
use kdx_protocol::{
    KdxCodec, KdxFrame, PacketFlags, PacketHeader, PacketType, PROTOCOL_VERSION,
};
use kdx_crypto::KdfParams;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, Duration};
use tokio_util::codec::Framed;
use tracing::{debug, warn};

use crate::error::ClientError;
use crate::event::Event;
use crate::handle::{Command, Session};

const KEEPALIVE: Duration = Duration::from_secs(30);

/// A login in flight: which step we're waiting for and who to answer.
struct PendingLogin {
    password: String,
    phase: LoginPhase,
    reply: oneshot::Sender<Result<Session, ClientError>>,
}

enum LoginPhase {
    AwaitingChallenge,
    AwaitingResult,
}

pub(crate) struct Actor<S> {
    framed: Framed<S, KdxCodec>,
    commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
    seq: u32,
    login: Option<PendingLogin>,
    /// FIFO of pending file-list requests awaiting a response.
    list_waiters: VecDeque<oneshot::Sender<Result<FileListResponse, ClientError>>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Actor<S> {
    pub(crate) fn new(
        framed: Framed<S, KdxCodec>,
        commands: mpsc::Receiver<Command>,
        events: mpsc::Sender<Event>,
    ) -> Self {
        Self {
            framed,
            commands,
            events,
            seq: 0,
            login: None,
            list_waiters: VecDeque::new(),
        }
    }

    pub(crate) async fn run(mut self) {
        let mut keepalive = interval(KEEPALIVE);
        keepalive.tick().await; // consume the immediate first tick

        let reason = loop {
            tokio::select! {
                cmd = self.commands.recv() => {
                    match cmd {
                        Some(Command::Disconnect) | None => {
                            let _ = self.send(PacketType::Disconnect, Bytes::new()).await;
                            break "disconnected".to_string();
                        }
                        Some(cmd) => {
                            if let Err(e) = self.handle_command(cmd).await {
                                break format!("write failed: {e}");
                            }
                        }
                    }
                }
                frame = self.framed.next() => {
                    match frame {
                        Some(Ok(frame)) => {
                            if let Err(e) = self.handle_frame(frame).await {
                                break format!("protocol error: {e}");
                            }
                        }
                        Some(Err(e)) => break format!("stream error: {e}"),
                        None => break "connection closed by server".to_string(),
                    }
                }
                _ = keepalive.tick() => {
                    if self.send(PacketType::Ping, Bytes::new()).await.is_err() {
                        break "keepalive write failed".to_string();
                    }
                }
            }
        };

        // Fail any outstanding waiters, then announce the disconnect.
        if let Some(login) = self.login.take() {
            let _ = login.reply.send(Err(ClientError::Disconnected));
        }
        for waiter in self.list_waiters.drain(..) {
            let _ = waiter.send(Err(ClientError::Disconnected));
        }
        let _ = self.events.send(Event::Disconnected { reason }).await;
    }

    async fn handle_command(&mut self, cmd: Command) -> io::Result<()> {
        match cmd {
            Command::Login {
                username,
                password,
                reply,
            } => {
                if self.login.is_some() {
                    let _ = reply.send(Err(ClientError::AuthFailed("login already in progress".into())));
                    return Ok(());
                }
                self.send(PacketType::AuthRequest, AuthRequest { username }.encode())
                    .await?;
                self.login = Some(PendingLogin {
                    password,
                    phase: LoginPhase::AwaitingChallenge,
                    reply,
                });
            }
            Command::Join { room, reply } => {
                let r = self
                    .send(PacketType::ChatJoin, ChatJoin { room }.encode())
                    .await;
                let _ = reply.send(r.map_err(Into::into));
            }
            Command::Leave { room, reply } => {
                let r = self
                    .send(PacketType::ChatLeave, ChatLeave { room }.encode())
                    .await;
                let _ = reply.send(r.map_err(Into::into));
            }
            Command::SendChat {
                room,
                flags,
                text,
                reply,
            } => {
                let r = self
                    .send(PacketType::ChatMessage, ChatSend { room, flags, text }.encode())
                    .await;
                let _ = reply.send(r.map_err(Into::into));
            }
            Command::SetTopic { room, topic, reply } => {
                let r = self
                    .send(PacketType::ChatTopicSet, ChatTopic { room, topic }.encode())
                    .await;
                let _ = reply.send(r.map_err(Into::into));
            }
            Command::ListFiles { path, reply } => {
                match self
                    .send(PacketType::FileListRequest, FileListRequest { path }.encode())
                    .await
                {
                    Ok(()) => self.list_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
            }
            Command::Disconnect => unreachable!("handled in run loop"),
        }
        Ok(())
    }

    async fn handle_frame(&mut self, frame: KdxFrame) -> Result<(), ClientError> {
        match frame.header.packet_type {
            PacketType::AuthChallenge => self.on_auth_challenge(&frame.payload).await?,
            PacketType::AuthResult => self.on_auth_result(&frame.payload)?,
            PacketType::ChatMessage => {
                let ev = kdx_protocol::messages::ChatEvent::decode(&frame.payload)?;
                self.emit(Event::Chat {
                    room: ev.room,
                    sender: ev.sender,
                    timestamp: ev.timestamp,
                    flags: ev.flags,
                    text: ev.text,
                })
                .await;
            }
            PacketType::ChatUserList => {
                let list = ChatUserList::decode(&frame.payload)?;
                self.emit(Event::UserList {
                    room: list.room,
                    users: list.users,
                })
                .await;
            }
            PacketType::ChatTopicSet => {
                let topic = ChatTopic::decode(&frame.payload)?;
                self.emit(Event::Topic {
                    room: topic.room,
                    topic: topic.topic,
                })
                .await;
            }
            PacketType::FileListResponse => {
                let response = FileListResponse::decode(&frame.payload)?;
                if let Some(waiter) = self.list_waiters.pop_front() {
                    let _ = waiter.send(Ok(response));
                }
            }
            PacketType::Warning => {
                self.emit(Event::ServerWarning {
                    text: String::from_utf8_lossy(&frame.payload).into_owned(),
                })
                .await;
            }
            PacketType::Error => {
                self.emit(Event::ServerError {
                    text: String::from_utf8_lossy(&frame.payload).into_owned(),
                })
                .await;
            }
            PacketType::Info => {
                self.emit(Event::ServerInfo {
                    text: String::from_utf8_lossy(&frame.payload).into_owned(),
                })
                .await;
            }
            PacketType::Pong => { /* keepalive echo */ }
            other => {
                // FileTransfer* handled in C2; ignore for now.
                debug!(packet_type = ?other, "unhandled inbound packet");
            }
        }
        Ok(())
    }

    async fn on_auth_challenge(&mut self, payload: &[u8]) -> Result<(), ClientError> {
        let Some(login) = self.login.as_mut() else {
            warn!("unexpected AuthChallenge with no login in flight");
            return Ok(());
        };
        if !matches!(login.phase, LoginPhase::AwaitingChallenge) {
            return Ok(());
        }
        let challenge = AuthChallenge::decode(payload)?;
        let response = kdx_crypto::client_response(
            &login.password,
            &challenge.salt,
            &KdfParams {
                m_cost: challenge.m_cost,
                t_cost: challenge.t_cost,
                p_cost: challenge.p_cost,
            },
            &challenge.challenge,
        )?;
        login.phase = LoginPhase::AwaitingResult;
        self.send(PacketType::AuthResponse, AuthResponse { response }.encode())
            .await?;
        Ok(())
    }

    fn on_auth_result(&mut self, payload: &[u8]) -> Result<(), ClientError> {
        let Some(login) = self.login.take() else {
            warn!("unexpected AuthResult with no login in flight");
            return Ok(());
        };
        let result = AuthResult::decode(payload)?;
        if result.success {
            let _ = login.reply.send(Ok(Session {
                session_id: result.session_id,
                class: result.class,
            }));
        } else {
            // Login state is already cleared (take()), so a retry can begin.
            let _ = login.reply.send(Err(ClientError::AuthFailed(result.message)));
        }
        Ok(())
    }

    async fn emit(&self, event: Event) {
        let _ = self.events.send(event).await;
    }

    async fn send(&mut self, packet_type: PacketType, payload: Bytes) -> io::Result<()> {
        let header = PacketHeader {
            version: PROTOCOL_VERSION,
            packet_type,
            flags: PacketFlags::empty(),
            sequence: self.seq,
            length: payload.len() as u32,
        };
        self.seq = self.seq.wrapping_add(1);
        self.framed
            .send(KdxFrame { header, payload })
            .await
            .map_err(|e| match e {
                kdx_protocol::ProtocolError::Io(e) => e,
                other => io::Error::other(other),
            })
    }
}
