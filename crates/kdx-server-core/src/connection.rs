//! Per-connection state machine. Generic over the byte stream so tests can
//! drive it with `tokio::io::duplex` instead of a real TLS socket; `kdxd`
//! hands it a `TlsStream<TcpStream>`.
//!
//! Lifecycle: KDX handshake → authentication (challenge-response) → active
//! dispatch. Ping/Pong and Disconnect work in every phase after the
//! handshake; everything else requires a live session.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use kdx_protocol::messages::{
    AccountCreate, AccountListRequest, AccountListResponse, AccountRolesRequest,
    AccountRolesResponse, AccountSummary, AccountUpdate, AdminBroadcast, AdminDisconnect,
    AdminShutdown, AuthChallenge, AuthRequest, AuthResponse, AuthResult, ChatInvite, ChatInvited,
    ChatJoin, ChatLeave, ChatRoomFlags as WireChatRoomFlags, ChatSend, ChatTopic,
    ConnectionListRequest, ConnectionListResponse, FileCatalogGenerated, FileCreateFolder,
    FileDelete,
    FileEntry,
    FileAlias, FileGenerateCatalog, FileInfoRequest, FileInfoResponse, FileListRequest,
    FileListResponse, FileMove, FileSearchEntry, FileSearchRequest, FileSearchResponse,
    HandshakeInit, HandshakeResp, HistoryEntry as WireHistoryEntry,
    HistoryListRequest, HistoryListResponse, IpRuleCreate, IpRuleDelete,
    IpRuleEntry as WireIpRule, IpRuleListRequest, IpRuleListResponse, NewsPost as WireNewsPost,
    NewsPostCreate, NewsPostDelete, NewsThreadListRequest, NewsThreadListResponse, NewsgroupCreate,
    NewsgroupInfo, NewsgroupListRequest, NewsgroupListResponse, PresenceListRequest,
    PresenceListResponse, PrivateMessage, PrivateSend, RoleAssign, RoleCreate, RoleDelete, RoleInfo,
    SetIdentity,
    RoleListRequest, RoleListResponse, RoleUnassign, RoleUpdate, ServerSettingsRequest,
    ServerSettingsResponse, ServerSettingsUpdate, TrackerListRequest, TrackerListResponse,
    TrackerServer, TransferAccept, TransferData, TransferEnd, TransferRequest, UserInfoRequest,
    UserInfoResponse, TRANSFER_HASH_MISMATCH, TRANSFER_VERIFIED,
};
use kdx_protocol::{
    KdxCodec, KdxFrame, PacketFlags, PacketHeader, PacketType, ProtocolError, Reassembler,
    PROTOCOL_VERSION,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::timeout;
use tokio_util::codec::Framed;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::auth::{AuthManager, BaseClass, Privileges, Role, RoleManager, Session};
use crate::auth::policy::{self, Refusal};
use crate::chat::{Member, Outbound, RoomCommand, RoomManager};
use crate::files::{FileTree, NodeKind};
use crate::news::{NewsManager, Post as NewsPostDomain};
use crate::history::HistoryLog;
use crate::presence::{unix_now, Presence};
use crate::settings::ServerSettings;
use crate::tracker::Tracker;
use crate::transfer::{resume_id_from_wire, ActiveUpload, TransferError, TransferManager};

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

/// Depth of a connection's outbound event queue. Room broadcasts to a full
/// queue are dropped for that member rather than stalling the room.
pub const OUTBOUND_QUEUE: usize = 128;

/// Cap on search results returned in one `FileSearchResponse`.
const FILE_SEARCH_LIMIT: usize = 200;

/// Cap on entries returned in one `HistoryListResponse`, regardless of the
/// `limit` a client requests.
const HISTORY_LIST_LIMIT: u32 = 500;

/// Shared server-wide services handed to every connection.
pub struct ServerCtx {
    pub auth: AuthManager,
    pub roles: RoleManager,
    pub news: NewsManager,
    pub rooms: RoomManager,
    pub tree: FileTree,
    pub transfers: TransferManager,
    pub presence: Presence,
    pub tracker: Tracker,
    pub settings: ServerSettings,
    pub history: HistoryLog,
    pub ip_rules: crate::ip_rules::IpRuleManager,
    /// The bound listen port — immutable, informational only (shown in the
    /// Server Settings window; not itself part of `ServerSettings`, which
    /// covers just the live-editable fields).
    pub bind_port: u16,
    /// Notified by `AdminShutdown` to make the accept loop stop taking new
    /// connections and let the server task wind down. Not touched anywhere
    /// else in the request path.
    pub shutdown: Arc<Notify>,
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
    #[error("transfer failure: {0}")]
    Transfer(#[from] TransferError),
}

/// Drives one client connection from handshake through active dispatch.
pub struct Connection<S> {
    framed: Framed<S, KdxCodec>,
    ctx: Arc<ServerCtx>,
    reassembler: Reassembler,
    session: Option<Session>,
    /// Monotonic sequence counter for server-sent frames.
    next_sequence: u32,
    /// Best-effort "host:port" for this connection's peer, used for presence
    /// and User Info. `"unknown"` for streams that don't have a real
    /// network peer (e.g. tests over `tokio::io::duplex`).
    peer_addr: String,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    pub fn new(stream: S, ctx: Arc<ServerCtx>) -> Self {
        Self::new_with_peer(stream, ctx, "unknown".to_string())
    }

    /// Like [`Connection::new`], but records the peer's network address for
    /// presence/User Info. `kdxd`'s real listener uses this; tests generally
    /// don't need to.
    pub fn new_with_peer(stream: S, ctx: Arc<ServerCtx>, peer_addr: String) -> Self {
        Self {
            framed: Framed::new(stream, KdxCodec::default()),
            ctx,
            reassembler: Reassembler::default(),
            session: None,
            next_sequence: 0,
            peer_addr,
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

                    match self.ctx.auth.complete(pending, &response.response).await {
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
                            self.record_history(Some(session.username.clone()), "login", String::new());
                            self.session = Some(session);
                            let greeting = self.ctx.settings.greeting().await;
                            if !greeting.is_empty() {
                                self.send(
                                    PacketType::Info,
                                    PacketFlags::SYSTEM_MESSAGE,
                                    Bytes::copy_from_slice(greeting.as_bytes()),
                                )
                                .await?;
                            }
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
                            self.record_history(
                                Some(request.username.clone()),
                                "login_failed",
                                String::new(),
                            );
                            if failures >= MAX_AUTH_ATTEMPTS {
                                return Err(ConnectionError::TooManyAuthAttempts);
                            }
                        }
                        // Correct password but the account is banned: refuse
                        // the login outright (no retry budget spent — retrying
                        // won't help until the ban lapses).
                        Err(crate::auth::AuthError::Banned { until, reason }) => {
                            let message = if reason.is_empty() {
                                format!("banned until {until}")
                            } else {
                                format!("banned until {until}: {reason}")
                            };
                            let result = AuthResult {
                                success: false,
                                session_id: [0u8; 16],
                                class: 0,
                                message,
                            };
                            self.send(PacketType::AuthResult, PacketFlags::empty(), result.encode())
                                .await?;
                            self.record_history(
                                Some(request.username.clone()),
                                "login_banned",
                                reason.clone(),
                            );
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
        // Outbound events (room broadcasts etc.) flow through this channel;
        // its sender is what we hand to room actors on join.
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Outbound>(OUTBOUND_QUEUE);
        let mut joined: HashMap<String, mpsc::Sender<RoomCommand>> = HashMap::new();
        // One upload at a time per connection; the chunk stream is inherently
        // serialized on the socket anyway.
        let mut upload: Option<ActiveUpload> = None;

        // Join the server-wide presence roster for the User List / User Info
        // windows; every authenticated connection is visible here regardless
        // of which chat rooms it's in.
        {
            let session = self.session.as_ref().expect("authed in dispatch");
            self.ctx
                .presence
                .join(
                    session.id,
                    session.username.clone(),
                    session.class as u8,
                    self.peer_addr.clone(),
                    outbound_tx.clone(),
                )
                .await;
        }

        enum Next {
            Event(Outbound),
            Frame(Option<Result<KdxFrame, ProtocolError>>),
            ReassemblyTimedOut,
        }

        let result = loop {
            let next = {
                let reassembling = self.reassembler.is_reassembling();
                let framed = &mut self.framed;
                tokio::select! {
                    biased;
                    // Senders never all drop while we hold outbound_tx.
                    event = outbound_rx.recv() => Next::Event(event.expect("outbound channel open")),
                    next = async {
                        if reassembling {
                            // A fragment group is open: the peer must finish
                            // it promptly.
                            match timeout(REASSEMBLY_TIMEOUT, framed.next()).await {
                                Ok(item) => Next::Frame(item),
                                Err(_) => Next::ReassemblyTimedOut,
                            }
                        } else {
                            Next::Frame(framed.next().await)
                        }
                    } => next,
                }
            };

            let frame_or_eof = match next {
                Next::Event(event) => {
                    // A `Disconnect` event is the presence actor kicking this
                    // connection (admin disconnect / ban): send the reason,
                    // then close so the normal cleanup path runs.
                    let closing = event.packet_type == PacketType::Disconnect;
                    self.send(event.packet_type, event.flags, event.payload).await?;
                    if closing {
                        debug!("disconnected by server (admin action)");
                        break Ok(());
                    }
                    continue;
                }
                Next::ReassemblyTimedOut => {
                    self.reassembler.abort();
                    break Err(ConnectionError::ReassemblyTimeout);
                }
                Next::Frame(item) => item,
            };

            let Some(frame) = frame_or_eof.transpose()? else {
                break Ok(()); // clean EOF
            };

            let Some(frame) = self.reassembler.push(frame, MAX_REASSEMBLED_PAYLOAD)? else {
                continue; // mid-group fragment
            };

            match frame.header.packet_type {
                PacketType::Ping => {
                    let session_id = self.session.as_ref().expect("authed").id;
                    self.ctx.presence.touch(session_id).await;
                    self.send(PacketType::Pong, PacketFlags::empty(), frame.payload)
                        .await?;
                }
                PacketType::Disconnect => {
                    debug!("client disconnected cleanly");
                    break Ok(());
                }
                PacketType::SetIdentity => {
                    let req = SetIdentity::decode(&frame.payload)?;
                    let session_id = self.session.as_ref().expect("authed").id;
                    self.ctx.presence.set_identity(session_id, req.name, req.description).await;
                }
                PacketType::PresenceListRequest => {
                    PresenceListRequest::decode(&frame.payload)?;
                    let users = self.ctx.presence.list().await;
                    let response = PresenceListResponse { users };
                    self.send(
                        PacketType::PresenceListResponse,
                        PacketFlags::empty(),
                        response.encode(),
                    )
                    .await?;
                }
                PacketType::ConnectionListRequest => {
                    ConnectionListRequest::decode(&frame.payload)?;
                    let privs = self.session.as_ref().expect("authed").privileges;
                    // USER_KICK matches "who is allowed to see and act on
                    // everyone's live session" — same privilege that lets
                    // you kick, so gating both under one bit keeps the
                    // admin model simple.
                    if !privs.contains(Privileges::USER_KICK) {
                        self.send_error("missing USER_KICK privilege").await?;
                        continue;
                    }
                    let connections = self.ctx.presence.list().await;
                    let response = ConnectionListResponse { connections };
                    self.send(
                        PacketType::ConnectionListResponse,
                        PacketFlags::empty(),
                        response.encode(),
                    )
                    .await?;
                }
                PacketType::UserInfoRequest => {
                    let request = UserInfoRequest::decode(&frame.payload)?;
                    match self.ctx.presence.get(&request.username).await {
                        Some(entry) => {
                            let response = UserInfoResponse { entry };
                            self.send(
                                PacketType::UserInfoResponse,
                                PacketFlags::empty(),
                                response.encode(),
                            )
                            .await?;
                        }
                        None => self.send_error("user is not online").await?,
                    }
                }
                PacketType::PrivateSend => {
                    let send = PrivateSend::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::CHAT_PRIVATE) {
                        self.send_error("missing CHAT_PRIVATE privilege").await?;
                        continue;
                    }
                    self.ctx.presence.touch(session.id).await;
                    let msg = PrivateMessage {
                        from: session.username.clone(),
                        to: send.to.clone(),
                        timestamp: unix_now(),
                        text: send.text,
                    };
                    let outbound = Outbound {
                        packet_type: PacketType::PrivateMessage,
                        flags: PacketFlags::empty(),
                        payload: msg.encode(),
                    };
                    // Deliver to the recipient's connection(s). Don't echo to
                    // the sender if messaging themselves twice; instead always
                    // echo once to the sender so their own sessions show the
                    // sent line in the conversation.
                    let reached = self.ctx.presence.deliver(&send.to, outbound.clone()).await;
                    if reached == 0 {
                        self.send_error(&format!("{} is not online", send.to)).await?;
                    } else if send.to != session.username {
                        // Echo to the sender's own sessions so the sent
                        // message appears in their transcript.
                        self.ctx
                            .presence
                            .deliver(&session.username, outbound)
                            .await;
                    }
                }
                PacketType::ChatJoin => {
                    let join = ChatJoin::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed in dispatch");
                    let member = Member {
                        session_id: session.id,
                        username: session.username.clone(),
                        class: session.class as u8,
                        privileges: session.privileges,
                        tx: outbound_tx.clone(),
                    };
                    match self.ctx.rooms.join(&join.room, member).await {
                        Ok(handle) => {
                            joined.insert(join.room, handle);
                        }
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::ChatInvite => {
                    let invite = ChatInvite::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::CHAT_PRIVATE) {
                        self.send_error("missing CHAT_PRIVATE privilege").await?;
                        continue;
                    }
                    if invite.to == session.username {
                        self.send_error("cannot invite yourself").await?;
                        continue;
                    }
                    // A UUID-named room can't collide with a user-typed public
                    // room name, and marks it temporary in RoomManager (evicted
                    // once its last member leaves).
                    let room_id = format!("priv-{}", Uuid::new_v4());
                    let member = Member {
                        session_id: session.id,
                        username: session.username.clone(),
                        class: session.class as u8,
                        privileges: session.privileges,
                        tx: outbound_tx.clone(),
                    };
                    let handle = match self.ctx.rooms.join_private(&room_id, member).await {
                        Ok(handle) => handle,
                        Err(e) => {
                            self.send_error(&e.to_string()).await?;
                            continue;
                        }
                    };
                    joined.insert(room_id.clone(), handle);

                    let invited = ChatInvited {
                        from: session.username.clone(),
                        room: room_id.clone(),
                    };
                    let outbound = Outbound {
                        packet_type: PacketType::ChatInvited,
                        flags: PacketFlags::empty(),
                        payload: invited.encode(),
                    };
                    let reached = self.ctx.presence.deliver(&invite.to, outbound).await;
                    if reached == 0 {
                        // Nobody to invite — tear the just-created room back
                        // down rather than leave it stranded with one member.
                        joined.remove(&room_id);
                        self.ctx.rooms.leave(&room_id, session.id).await;
                        self.send_error(&format!("{} is not online", invite.to)).await?;
                    } else {
                        self.send(
                            PacketType::Info,
                            PacketFlags::SYSTEM_MESSAGE,
                            Bytes::copy_from_slice(
                                format!("invited {} — waiting for them to join", invite.to)
                                    .as_bytes(),
                            ),
                        )
                        .await?;
                    }
                }
                PacketType::ChatLeave => {
                    let leave = ChatLeave::decode(&frame.payload)?;
                    let session_id = self.session.as_ref().expect("authed").id;
                    if joined.remove(&leave.room).is_some() {
                        // Routed through RoomManager (not the retained handle
                        // directly) so it can drop a now-empty temporary room.
                        self.ctx.rooms.leave(&leave.room, session_id).await;
                    }
                }
                PacketType::ChatMessage => {
                    let send = ChatSend::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::CHAT_SEND) {
                        self.send_error("missing CHAT_SEND privilege").await?;
                        continue;
                    }
                    self.ctx.presence.touch(session.id).await;
                    match joined.get(&send.room) {
                        Some(handle) => {
                            let _ = handle
                                .send(RoomCommand::Message {
                                    session_id: session.id,
                                    flags: send.flags,
                                    text: send.text,
                                })
                                .await;
                        }
                        None => self.send_error("not in that room").await?,
                    }
                }
                PacketType::ChatTopicSet => {
                    let topic = ChatTopic::decode(&frame.payload)?;
                    let session_id = self.session.as_ref().expect("authed").id;
                    match joined.get(&topic.room) {
                        Some(handle) => {
                            let (reply, rx) = oneshot::channel();
                            let _ = handle
                                .send(RoomCommand::SetTopic {
                                    session_id,
                                    topic: topic.topic,
                                    reply,
                                })
                                .await;
                            if let Ok(Err(e)) = rx.await {
                                self.send_error(&e.to_string()).await?;
                            }
                        }
                        None => self.send_error("not in that room").await?,
                    }
                }
                PacketType::ChatRoomFlags => {
                    let flags = WireChatRoomFlags::decode(&frame.payload)?;
                    let session_id = self.session.as_ref().expect("authed").id;
                    // Route through the manager (not the joined map) so we
                    // return the same NotMember/NoPrivilege errors regardless
                    // of whether this connection's copy has an in-memory
                    // handle — a member's `join` above tracks its own
                    // handles, but the flag change is still valid from any
                    // joined session.
                    match self
                        .ctx
                        .rooms
                        .set_flags(
                            &flags.room,
                            session_id,
                            flags.min_class_join,
                            flags.interview_mode,
                        )
                        .await
                    {
                        Ok(()) => {}
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::FileListRequest => {
                    let request = FileListRequest::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::FILE_LIST) {
                        self.send_error("missing FILE_LIST privilege").await?;
                        continue;
                    }
                    match self.ctx.tree.list(&request.path, &session).await {
                        Ok(entries) => {
                            let response = FileListResponse {
                                path: request.path,
                                entries: entries
                                    .into_iter()
                                    .map(|e| FileEntry {
                                        name: e.name,
                                        kind: e.kind.as_u8(),
                                        size: e.size,
                                    })
                                    .collect(),
                            };
                            self.send(
                                PacketType::FileListResponse,
                                PacketFlags::empty(),
                                response.encode(),
                            )
                            .await?;
                        }
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::FileInfoRequest => {
                    let req = FileInfoRequest::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::FILE_LIST) {
                        self.send_error("missing FILE_LIST privilege").await?;
                        continue;
                    }
                    match self.ctx.tree.info(&req.path, &session).await {
                        Ok(node) => {
                            let response = FileInfoResponse {
                                name: node.name.clone(),
                                kind: node.kind.as_u8(),
                                size: node.size,
                                sha256: node.sha256.clone().and_then(|h| {
                                    <[u8; 32]>::try_from(h).ok()
                                }),
                                min_read_class: node.min_class_read as u8,
                                min_write_class: node.min_class_write as u8,
                                owner: node.owner.clone(),
                            };
                            self.send(
                                PacketType::FileInfoResponse,
                                PacketFlags::empty(),
                                response.encode(),
                            )
                            .await?;
                        }
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::FileCreateFolder => {
                    let req = FileCreateFolder::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::FILE_MANAGE_TREE) {
                        self.send_error("missing FILE_MANAGE_TREE privilege").await?;
                        continue;
                    }
                    let kind = match req.kind {
                        kdx_protocol::messages::KIND_DIR => NodeKind::Directory,
                        kdx_protocol::messages::KIND_DROPBOX => NodeKind::DropBox,
                        kdx_protocol::messages::KIND_UPLOAD => NodeKind::UploadFolder,
                        _ => {
                            self.send_error("not a folder kind").await?;
                            continue;
                        }
                    };
                    let read = class_from_u8(req.min_read_class);
                    let write = class_from_u8(req.min_write_class);
                    match self
                        .ctx
                        .tree
                        .create_folder(
                            &req.path,
                            &req.name,
                            kind,
                            read,
                            write,
                            req.owner.as_deref(),
                        )
                        .await
                    {
                        Ok(_) => self.reply_file_list(&req.path, &session).await?,
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::FileDelete => {
                    let req = FileDelete::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::FILE_MANAGE_TREE) {
                        self.send_error("missing FILE_MANAGE_TREE privilege").await?;
                        continue;
                    }
                    match self.ctx.tree.delete(&req.path, &session).await {
                        Ok(_) => {
                            // Re-list the deleted node's parent directory.
                            let parent = parent_path(&req.path);
                            self.reply_file_list(&parent, &session).await?;
                        }
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::FileMove => {
                    let req = FileMove::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::FILE_MANAGE_TREE) {
                        self.send_error("missing FILE_MANAGE_TREE privilege").await?;
                        continue;
                    }
                    match self.ctx.tree.move_node(&req.path, &req.dest_path, &session).await {
                        Ok(()) => self.reply_file_list(&req.dest_path, &session).await?,
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::FileAlias => {
                    let req = FileAlias::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::FILE_MANAGE_TREE) {
                        self.send_error("missing FILE_MANAGE_TREE privilege").await?;
                        continue;
                    }
                    match self
                        .ctx
                        .tree
                        .create_alias(&req.source_path, &req.dest_path, &session)
                        .await
                    {
                        Ok(_) => self.reply_file_list(&req.dest_path, &session).await?,
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::FileGenerateCatalog => {
                    FileGenerateCatalog::decode(&frame.payload)?;
                    let privs = self.session.as_ref().expect("authed").privileges;
                    if !privs.contains(Privileges::FILE_MANAGE_TREE) {
                        self.send_error("missing FILE_MANAGE_TREE privilege").await?;
                        continue;
                    }
                    let count = self.ctx.tree.generate_catalog().await as u32;
                    self.send(
                        PacketType::FileCatalogGenerated,
                        PacketFlags::empty(),
                        FileCatalogGenerated { count }.encode(),
                    )
                    .await?;
                }
                PacketType::FileSearchRequest => {
                    let req = FileSearchRequest::decode(&frame.payload)?;
                    let (class, privs) = {
                        let s = self.session.as_ref().expect("authed");
                        (s.class, s.privileges)
                    };
                    if !privs.contains(Privileges::FILE_LIST) {
                        self.send_error("missing FILE_LIST privilege").await?;
                        continue;
                    }
                    match self.ctx.tree.search(&req.query, class, FILE_SEARCH_LIMIT).await {
                        Ok(hits) => {
                            let response = FileSearchResponse {
                                entries: hits
                                    .into_iter()
                                    .map(|e| FileSearchEntry {
                                        path: e.path,
                                        name: e.name,
                                        kind: e.kind.as_u8(),
                                        size: e.size,
                                    })
                                    .collect(),
                            };
                            self.send(
                                PacketType::FileSearchResponse,
                                PacketFlags::empty(),
                                response.encode(),
                            )
                            .await?;
                        }
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::FileTransferStart if is_download(&frame.payload) => {
                    let request = TransferRequest::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::FILE_DOWNLOAD) {
                        self.send_error("missing FILE_DOWNLOAD privilege").await?;
                        continue;
                    }
                    let remote = format!(
                        "{}/{}",
                        request.path.trim_end_matches('/'),
                        request.name
                    );
                    match self
                        .ctx
                        .transfers
                        .begin_download(
                            &self.ctx.tree,
                            &session,
                            &remote,
                            request.chunk_size,
                            &request.have_bitmap,
                        )
                        .await
                    {
                        Ok((mut stream, accept)) => {
                            let msg = TransferAccept {
                                transfer_id: accept.transfer_id,
                                chunk_size: accept.chunk_size,
                                total_chunks: accept.total_chunks,
                                size: accept.size,
                                sha256: accept.sha256,
                                have_bitmap: accept.have_bitmap,
                            };
                            self.send(
                                PacketType::FileTransferStart,
                                PacketFlags::TRANSFER_START,
                                msg.encode(),
                            )
                            .await?;
                            self.stream_download(&mut stream).await?;
                        }
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::FileTransferStart => {
                    let request = TransferRequest::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::FILE_UPLOAD) {
                        self.send_error("missing FILE_UPLOAD privilege").await?;
                        continue;
                    }
                    if upload.is_some() {
                        self.send_error("a transfer is already active").await?;
                        continue;
                    }
                    let result = self
                        .ctx
                        .transfers
                        .begin_upload(
                            &self.ctx.tree,
                            &session,
                            &request.path,
                            &request.name,
                            request.size,
                            request.chunk_size,
                            request.sha256,
                            resume_id_from_wire(request.resume_id),
                        )
                        .await;
                    match result {
                        Ok((active, accept)) => {
                            upload = Some(active);
                            let msg = TransferAccept {
                                transfer_id: accept.transfer_id,
                                chunk_size: accept.chunk_size,
                                total_chunks: accept.total_chunks,
                                size: accept.size,
                                sha256: accept.sha256,
                                have_bitmap: accept.have_bitmap,
                            };
                            self.send(
                                PacketType::FileTransferStart,
                                PacketFlags::TRANSFER_START,
                                msg.encode(),
                            )
                            .await?;
                        }
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::FileTransferData => {
                    let data = TransferData::decode(&frame.payload)?;
                    let Some(active) = upload.as_mut() else {
                        self.send_error("no active transfer").await?;
                        continue;
                    };
                    if data.transfer_id != *active.id().as_bytes() {
                        self.send_error("unknown transfer id").await?;
                        continue;
                    }
                    match self
                        .ctx
                        .transfers
                        .write_chunk(active, data.chunk_index, &data.chunk_hash, &data.data)
                        .await
                    {
                        Ok(false) => {} // more chunks to come
                        Ok(true) => {
                            let finished = upload.take().expect("active upload present");
                            let transfer_id = *finished.id().as_bytes();
                            let (status, message) =
                                match self.ctx.transfers.finish(&self.ctx.tree, finished).await {
                                    Ok(()) => (TRANSFER_VERIFIED, "verified".to_string()),
                                    Err(TransferError::FileHashMismatch) => {
                                        (TRANSFER_HASH_MISMATCH, "file hash mismatch".to_string())
                                    }
                                    Err(e) => return Err(ConnectionError::Transfer(e)),
                                };
                            let end = TransferEnd {
                                transfer_id,
                                status,
                                message,
                            };
                            self.send(
                                PacketType::FileTransferEnd,
                                PacketFlags::TRANSFER_END,
                                end.encode(),
                            )
                            .await?;
                        }
                        // Recoverable per-chunk problems: report, let the
                        // client resend. Anything else is connection-fatal.
                        Err(
                            e @ (TransferError::ChunkHashMismatch
                            | TransferError::BadChunkIndex
                            | TransferError::BadChunkLength),
                        ) => self.send_error(&e.to_string()).await?,
                        Err(e) => return Err(ConnectionError::Transfer(e)),
                    }
                }
                PacketType::RoleListRequest => {
                    RoleListRequest::decode(&frame.payload)?;
                    // Role names and privilege bits are admin data, gated
                    // like AccountRolesRequest (AUTHZ-12).
                    let privs = self.session.as_ref().expect("authed").privileges;
                    if !privs.contains(Privileges::USER_ADMIN) {
                        self.send_error("missing USER_ADMIN privilege").await?;
                        continue;
                    }
                    self.reply_role_list().await?;
                }
                // Role and account mutations go through `auth::policy`, which
                // enforces rank / no-self-escalation / last-admin rules and
                // kicks every live session whose privileges changed.
                PacketType::RoleCreate => {
                    let create = RoleCreate::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    match policy::create_role(&self.ctx, &session, &create).await {
                        Ok(()) => {
                            let _ = self
                                .ctx
                                .history
                                .record(unix_now(), Some(&session.username), "role_created", &create.name)
                                .await;
                            self.reply_role_list().await?
                        }
                        Err(refusal) => self.send_refusal(refusal).await?,
                    }
                }
                PacketType::RoleUpdate => {
                    let update = RoleUpdate::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    match policy::update_role(&self.ctx, &session, &update).await {
                        Ok(()) => {
                            let _ = self
                                .ctx
                                .history
                                .record(unix_now(), Some(&session.username), "role_updated", &update.name)
                                .await;
                            self.reply_role_list().await?
                        }
                        Err(refusal) => self.send_refusal(refusal).await?,
                    }
                }
                PacketType::RoleDelete => {
                    let delete = RoleDelete::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    let role_id = Uuid::from_bytes(delete.id);
                    match policy::delete_role(&self.ctx, &session, role_id).await {
                        Ok(()) => {
                            let _ = self
                                .ctx
                                .history
                                .record(unix_now(), Some(&session.username), "role_deleted", &role_id.to_string())
                                .await;
                            self.reply_role_list().await?
                        }
                        Err(refusal) => self.send_refusal(refusal).await?,
                    }
                }
                PacketType::RoleAssign => {
                    let assign = RoleAssign::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    let role_id = Uuid::from_bytes(assign.role_id);
                    match policy::set_role_assignment(&self.ctx, &session, &assign.username, role_id, true)
                        .await
                    {
                        Ok(()) => {
                            let _ = self
                                .ctx
                                .history
                                .record(
                                    unix_now(),
                                    Some(&session.username),
                                    "role_assigned",
                                    &format!("target={}", assign.username),
                                )
                                .await;
                            self.reply_role_list().await?
                        }
                        Err(refusal) => self.send_refusal(refusal).await?,
                    }
                }
                PacketType::RoleUnassign => {
                    let unassign = RoleUnassign::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    let role_id = Uuid::from_bytes(unassign.role_id);
                    match policy::set_role_assignment(&self.ctx, &session, &unassign.username, role_id, false)
                        .await
                    {
                        Ok(()) => {
                            let _ = self
                                .ctx
                                .history
                                .record(
                                    unix_now(),
                                    Some(&session.username),
                                    "role_unassigned",
                                    &format!("target={}", unassign.username),
                                )
                                .await;
                            self.reply_role_list().await?
                        }
                        Err(refusal) => self.send_refusal(refusal).await?,
                    }
                }
                PacketType::AccountRolesRequest => {
                    let request = AccountRolesRequest::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::USER_ADMIN) {
                        self.send_error("missing USER_ADMIN privilege").await?;
                        continue;
                    }
                    let account_id = match self.ctx.auth.account_id(&request.username).await {
                        Ok(Some(account_id)) => account_id,
                        Ok(None) => {
                            self.send_error("no such account").await?;
                            continue;
                        }
                        Err(e) => {
                            self.send_refusal(Refusal::internal("account roles lookup", e)).await?;
                            continue;
                        }
                    };
                    match self.ctx.roles.for_account(&account_id).await {
                        Ok(roles) => {
                            let response = AccountRolesResponse {
                                username: request.username,
                                role_ids: roles.into_iter().map(|r| *r.id.as_bytes()).collect(),
                            };
                            self.send(
                                PacketType::AccountRolesResponse,
                                PacketFlags::empty(),
                                response.encode(),
                            )
                            .await?;
                        }
                        Err(e) => {
                            self.send_refusal(Refusal::internal("account roles lookup", e)).await?
                        }
                    }
                }
                PacketType::AccountListRequest => {
                    AccountListRequest::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::USER_ADMIN) {
                        self.send_error("missing USER_ADMIN privilege").await?;
                        continue;
                    }
                    self.reply_account_list().await?;
                }
                PacketType::AccountCreate => {
                    let create = AccountCreate::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    match policy::create_account(&self.ctx, &session, &create).await {
                        Ok(()) => {
                            let _ = self
                                .ctx
                                .history
                                .record(unix_now(), Some(&session.username), "account_created", &create.username)
                                .await;
                            self.reply_account_list().await?
                        }
                        Err(refusal) => self.send_refusal(refusal).await?,
                    }
                }
                PacketType::AccountUpdate => {
                    let update = AccountUpdate::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    match policy::update_account(&self.ctx, &session, &update).await {
                        Ok(()) => {
                            let _ = self
                                .ctx
                                .history
                                .record(unix_now(), Some(&session.username), "account_updated", &update.username)
                                .await;
                            self.reply_account_list().await?
                        }
                        Err(refusal) => self.send_refusal(refusal).await?,
                    }
                }
                PacketType::TrackerListRequest => {
                    let req = TrackerListRequest::decode(&frame.payload)?;
                    let filter = (!req.filter.trim().is_empty()).then_some(req.filter.as_str());
                    let servers = self
                        .ctx
                        .tracker
                        .query(filter)
                        .await
                        .into_iter()
                        .map(|e| TrackerServer {
                            name: e.name,
                            host: e.host,
                            port: e.port,
                            users: e.users,
                            max_users: e.max_users,
                            description: e.description,
                        })
                        .collect();
                    let response = TrackerListResponse { servers };
                    self.send(
                        PacketType::TrackerListResponse,
                        PacketFlags::empty(),
                        response.encode(),
                    )
                    .await?;
                }
                PacketType::ServerSettingsRequest => {
                    ServerSettingsRequest::decode(&frame.payload)?;
                    let privs = self.session.as_ref().expect("authed").privileges;
                    if !privs.contains(Privileges::SERVER_ADMIN) {
                        self.send_error("missing SERVER_ADMIN privilege").await?;
                        continue;
                    }
                    self.reply_server_settings().await?;
                }
                PacketType::HistoryListRequest => {
                    let req = HistoryListRequest::decode(&frame.payload)?;
                    let privs = self.session.as_ref().expect("authed").privileges;
                    if !privs.contains(Privileges::SERVER_ADMIN) {
                        self.send_error("missing SERVER_ADMIN privilege").await?;
                        continue;
                    }
                    let limit = req.limit.clamp(1, HISTORY_LIST_LIMIT);
                    match self.ctx.history.recent(limit).await {
                        Ok(entries) => {
                            let response = HistoryListResponse {
                                entries: entries
                                    .into_iter()
                                    .map(|e| WireHistoryEntry {
                                        timestamp: e.timestamp,
                                        actor: e.actor.unwrap_or_default(),
                                        action: e.action,
                                        detail: e.detail,
                                    })
                                    .collect(),
                            };
                            self.send(
                                PacketType::HistoryListResponse,
                                PacketFlags::empty(),
                                response.encode(),
                            )
                            .await?;
                        }
                        Err(e) => self.send_refusal(Refusal::internal("history listing", e)).await?,
                    }
                }
                PacketType::IpRuleListRequest => {
                    IpRuleListRequest::decode(&frame.payload)?;
                    let privs = self.session.as_ref().expect("authed").privileges;
                    if !privs.contains(Privileges::SERVER_ADMIN) {
                        self.send_error("missing SERVER_ADMIN privilege").await?;
                        continue;
                    }
                    self.reply_ip_rule_list().await?;
                }
                PacketType::IpRuleCreate => {
                    let create = IpRuleCreate::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::SERVER_ADMIN) {
                        self.send_error("missing SERVER_ADMIN privilege").await?;
                        continue;
                    }
                    let admin_name = session.username.clone();
                    if let Err(msg) =
                        crate::limits::check_len("note", &create.note, crate::limits::MAX_REASON_LEN)
                    {
                        self.send_error(&msg).await?;
                        continue;
                    }
                    let action = match create.action.as_str() {
                        "allow" => crate::ip_rules::Action::Allow,
                        "deny" => crate::ip_rules::Action::Deny,
                        _ => {
                            self.send_error("action must be 'allow' or 'deny'").await?;
                            continue;
                        }
                    };
                    match self
                        .ctx
                        .ip_rules
                        .create(
                            create.position,
                            action,
                            &create.cidr,
                            &create.note,
                            &admin_name,
                            unix_now(),
                        )
                        .await
                    {
                        Ok(_) => {
                            // Rules are checked at accept; apply the new set to
                            // sessions already connected too (AUTHZ-8).
                            self.enforce_ip_rules_on_live_sessions().await;
                            let _ = self
                                .ctx
                                .history
                                .record(
                                    unix_now(),
                                    Some(&admin_name),
                                    "ip_rule_created",
                                    &format!("{} {}", create.action, create.cidr),
                                )
                                .await;
                            self.reply_ip_rule_list().await?
                        }
                        Err(e) => self.send_refusal(ip_rule_refusal("ip rule create", e)).await?,
                    }
                }
                PacketType::IpRuleDelete => {
                    let del = IpRuleDelete::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::SERVER_ADMIN) {
                        self.send_error("missing SERVER_ADMIN privilege").await?;
                        continue;
                    }
                    let admin_name = session.username.clone();
                    match self.ctx.ip_rules.delete(&del.id).await {
                        Ok(()) => {
                            // Dropping an allow-exception can newly deny
                            // addresses that are connected right now.
                            self.enforce_ip_rules_on_live_sessions().await;
                            let _ = self
                                .ctx
                                .history
                                .record(unix_now(), Some(&admin_name), "ip_rule_deleted", &del.id)
                                .await;
                            self.reply_ip_rule_list().await?
                        }
                        Err(e) => self.send_refusal(ip_rule_refusal("ip rule delete", e)).await?,
                    }
                }
                PacketType::ServerSettingsUpdate => {
                    let update = ServerSettingsUpdate::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::SERVER_ADMIN) {
                        self.send_error("missing SERVER_ADMIN privilege").await?;
                        continue;
                    }
                    let admin_name = session.username.clone();
                    // Required name and length caps (OPS-11): an oversized
                    // greeting would otherwise break every later login.
                    if let Err(msg) = ServerSettings::validate(
                        &update.name,
                        &update.description,
                        &update.greeting,
                    ) {
                        self.send_error(&msg).await?;
                        continue;
                    }
                    let new_name = update.name.clone();
                    // Persisted, so a restart keeps it (STORE-14).
                    if let Err(e) = self
                        .ctx
                        .settings
                        .update(update.name, update.description, update.greeting, update.max_users)
                        .await
                    {
                        let refusal = match e {
                            crate::settings::SettingsError::Invalid(msg) => Refusal::denied(msg),
                            other => Refusal::internal("settings update", other),
                        };
                        self.send_refusal(refusal).await?;
                        continue;
                    }
                    let _ = self
                        .ctx
                        .history
                        .record(unix_now(), Some(&admin_name), "server_settings_updated", &new_name)
                        .await;
                    self.reply_server_settings().await?;
                }
                PacketType::AdminBroadcast => {
                    let broadcast = AdminBroadcast::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::SERVER_ADMIN) {
                        self.send_error("missing SERVER_ADMIN privilege").await?;
                        continue;
                    }
                    let admin_name = session.username.clone();
                    if broadcast.text.trim().is_empty() {
                        self.send_error("broadcast text is required").await?;
                        continue;
                    }
                    if let Err(msg) = crate::limits::check_len(
                        "broadcast",
                        &broadcast.text,
                        crate::limits::MAX_BROADCAST_LEN,
                    ) {
                        self.send_error(&msg).await?;
                        continue;
                    }
                    let outbound = Outbound {
                        packet_type: PacketType::Info,
                        flags: PacketFlags::SYSTEM_MESSAGE,
                        payload: Bytes::copy_from_slice(broadcast.text.as_bytes()),
                    };
                    let reached = self.ctx.presence.broadcast_all(outbound).await;
                    let _ = self
                        .ctx
                        .history
                        .record(unix_now(), Some(&admin_name), "broadcast", &broadcast.text)
                        .await;
                    self.send(
                        PacketType::Info,
                        PacketFlags::SYSTEM_MESSAGE,
                        Bytes::copy_from_slice(format!("broadcast sent to {reached} session(s)").as_bytes()),
                    )
                    .await?;
                }
                PacketType::AdminShutdown => {
                    let shutdown = AdminShutdown::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::SERVER_ADMIN) {
                        self.send_error("missing SERVER_ADMIN privilege").await?;
                        continue;
                    }
                    let admin_name = session.username.clone();
                    let message = if shutdown.message.trim().is_empty() {
                        "the server is shutting down".to_string()
                    } else {
                        shutdown.message
                    };
                    let notice = Outbound {
                        packet_type: PacketType::Info,
                        flags: PacketFlags::SYSTEM_MESSAGE,
                        payload: Bytes::copy_from_slice(message.as_bytes()),
                    };
                    let _ = self
                        .ctx
                        .history
                        .record(unix_now(), Some(&admin_name), "shutdown", &message)
                        .await;
                    self.ctx.presence.broadcast_all(notice).await;
                    self.ctx.presence.disconnect_all(&message).await;
                    // Stop the accept loop; already-open connections (this one
                    // included) close individually as their queued Disconnect
                    // event above is processed on the next select iteration.
                    self.ctx.shutdown.notify_waiters();
                }
                PacketType::NewsgroupListRequest => {
                    NewsgroupListRequest::decode(&frame.payload)?;
                    self.reply_newsgroup_list().await?;
                }
                PacketType::NewsgroupCreate => {
                    let create = NewsgroupCreate::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::USER_ADMIN) {
                        self.send_error("missing USER_ADMIN privilege").await?;
                        continue;
                    }
                    let admin_name = session.username.clone();
                    if create.name.trim().is_empty() {
                        self.send_error("newsgroup name is required").await?;
                        continue;
                    }
                    if let Err(msg) = crate::limits::check_len(
                        "newsgroup name",
                        &create.name,
                        crate::limits::MAX_NAME_LEN,
                    )
                    .and_then(|()| {
                        crate::limits::check_len(
                            "newsgroup description",
                            &create.description,
                            crate::limits::MAX_LONG_DESCRIPTION_LEN,
                        )
                    }) {
                        self.send_error(&msg).await?;
                        continue;
                    }
                    // `create_group` refuses class thresholds above Admin
                    // (STORE-12): such a group would be invisible to all.
                    match self
                        .ctx
                        .news
                        .create_group(
                            &create.name,
                            &create.description,
                            create.min_read_class,
                            create.min_post_class,
                        )
                        .await
                    {
                        Ok(_) => {
                            let _ = self
                                .ctx
                                .history
                                .record(unix_now(), Some(&admin_name), "newsgroup_created", &create.name)
                                .await;
                            self.reply_newsgroup_list().await?
                        }
                        Err(e) => self.send_refusal(news_refusal("newsgroup create", e)).await?,
                    }
                }
                PacketType::NewsThreadListRequest => {
                    let req = NewsThreadListRequest::decode(&frame.payload)?;
                    let group_id = Uuid::from_bytes(req.newsgroup_id);
                    match self.ctx.news.group(group_id).await {
                        Ok(group) => {
                            let my_class = self.session.as_ref().expect("authed").class as u8;
                            if my_class < group.min_read_class {
                                self.send_error("you may not read this newsgroup").await?;
                                continue;
                            }
                            self.reply_thread_list(group_id).await?;
                        }
                        Err(e) => self.send_refusal(news_refusal("news listing", e)).await?,
                    }
                }
                PacketType::NewsPostCreate => {
                    let post = NewsPostCreate::decode(&frame.payload)?;
                    let (author, my_class) = {
                        let s = self.session.as_ref().expect("authed");
                        (s.username.clone(), s.class as u8)
                    };
                    if let Err(msg) = crate::limits::check_len(
                        "subject",
                        &post.subject,
                        crate::limits::MAX_NEWS_SUBJECT_LEN,
                    )
                    .and_then(|()| {
                        crate::limits::check_len("body", &post.body, crate::limits::MAX_NEWS_BODY_LEN)
                    }) {
                        self.send_error(&msg).await?;
                        continue;
                    }
                    let group_id = Uuid::from_bytes(post.newsgroup_id);
                    let group = match self.ctx.news.group(group_id).await {
                        Ok(g) => g,
                        Err(e) => {
                            self.send_refusal(news_refusal("news post", e)).await?;
                            continue;
                        }
                    };
                    if my_class < group.min_post_class {
                        self.send_error("you may not post to this newsgroup").await?;
                        continue;
                    }
                    if post.subject.trim().is_empty() {
                        self.send_error("a subject is required").await?;
                        continue;
                    }
                    // Per-account posting rate limit (DOS-11).
                    if !self.ctx.news.allow_post(&author) {
                        self.send_error("you are posting too fast; wait a few seconds")
                            .await?;
                        continue;
                    }
                    // All-zero parent id means "thread root". A reply's parent
                    // must be in this same group (STORE-11).
                    let parent = (post.parent_id != [0u8; 16]).then(|| Uuid::from_bytes(post.parent_id));
                    match self
                        .ctx
                        .news
                        .create_post(group_id, parent, &author, &post.subject, &post.body, unix_now())
                        .await
                    {
                        // Only a reader of the group gets the thread list back;
                        // a post-only member just gets their own post echoed
                        // (AUTHZ-10 / STORE-7).
                        Ok(created) if my_class < group.min_read_class => {
                            self.send_thread_list(group_id, vec![created]).await?
                        }
                        Ok(_) => self.reply_thread_list(group_id).await?,
                        Err(e) => self.send_refusal(news_refusal("news post", e)).await?,
                    }
                }
                PacketType::NewsPostDelete => {
                    let del = NewsPostDelete::decode(&frame.payload)?;
                    let (username, privs, my_class) = {
                        let s = self.session.as_ref().expect("authed");
                        (s.username.clone(), s.privileges, s.class as u8)
                    };
                    let post_id = Uuid::from_bytes(del.post_id);
                    let post = match self.ctx.news.post(post_id).await {
                        Ok(post) => post,
                        Err(e) => {
                            self.send_refusal(news_refusal("news delete", e)).await?;
                            continue;
                        }
                    };
                    let group = match self.ctx.news.group(post.newsgroup_id).await {
                        Ok(group) => group,
                        Err(e) => {
                            self.send_refusal(news_refusal("news delete", e)).await?;
                            continue;
                        }
                    };
                    let can_read = my_class >= group.min_read_class;
                    // USER_ADMIN may delete anyone's post in a group they can
                    // read, replies included. Everyone else may delete only
                    // their own post, and not once others have replied to it,
                    // since the delete cascades to the replies (AUTHZ-10).
                    let result = if privs.contains(Privileges::USER_ADMIN) && can_read {
                        self.ctx.news.delete_post(post_id).await.map(|()| true)
                    } else if post.author == username {
                        self.ctx.news.delete_own_post(post_id, &username).await
                    } else {
                        self.send_error("you can only delete your own posts").await?;
                        continue;
                    };
                    match result {
                        Ok(true) if can_read => self.reply_thread_list(post.newsgroup_id).await?,
                        Ok(true) => self.send_thread_list(post.newsgroup_id, Vec::new()).await?,
                        Ok(false) => {
                            self.send_error("cannot delete a post other users have replied to")
                                .await?
                        }
                        Err(e) => self.send_refusal(news_refusal("news delete", e)).await?,
                    }
                }
                PacketType::AdminDisconnect => {
                    let req = AdminDisconnect::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    // Kicking always needs USER_KICK; a ban additionally needs
                    // USER_BAN. Both are checked against the account's stored
                    // privileges as well as the login snapshot, so a demoted
                    // moderator can't keep acting (AUTHZ-2).
                    let actor = match policy::resolve_actor(&self.ctx, &session, Privileges::USER_KICK)
                        .await
                    {
                        Ok(actor) => actor,
                        Err(refusal) => {
                            self.send_refusal(refusal).await?;
                            continue;
                        }
                    };
                    let admin_name = actor.username.clone();
                    let admin_class = actor.authority.class;
                    if req.ban_secs > 0 && !actor.authority.privileges.contains(Privileges::USER_BAN) {
                        self.send_error("missing USER_BAN privilege").await?;
                        continue;
                    }
                    if req.username == admin_name {
                        self.send_error("cannot disconnect yourself").await?;
                        continue;
                    }
                    if let Err(msg) =
                        crate::limits::check_len("reason", &req.reason, crate::limits::MAX_REASON_LEN)
                    {
                        self.send_error(&msg).await?;
                        continue;
                    }
                    // Rank guard: never act on a user who outranks you. Take
                    // the higher of the live (presence) and stored class, so
                    // neither a stale session nor an offline target slips by.
                    let live_class = self.ctx.presence.get(&req.username).await.map(|e| e.class);
                    let stored = match self.ctx.roles.account_state(&req.username).await {
                        Ok(stored) => stored,
                        Err(e) => {
                            self.send_refusal(Refusal::internal("disconnect", e)).await?;
                            continue;
                        }
                    };
                    let target_class = live_class.max(stored.as_ref().map(|s| s.class as u8));
                    if target_class.is_some_and(|tc| tc > admin_class as u8) {
                        self.send_error("cannot disconnect a higher-class user").await?;
                        continue;
                    }
                    // Record the ban before kicking, so a racing reconnect is
                    // already refused by the login path. A shorter re-ban never
                    // cuts short a longer ban set by a higher rank (STORE-13).
                    let mut longer_ban_kept = false;
                    if req.ban_secs > 0 {
                        let Some(target) = &stored else {
                            self.send_error("no such account").await?;
                            continue;
                        };
                        let now = unix_now() as i64;
                        let until = now.saturating_add(req.ban_secs as i64);
                        match self
                            .ctx
                            .roles
                            .set_ban(&target.account_id, until, &req.reason, &admin_name, admin_class, now)
                            .await
                        {
                            Ok(in_force) => longer_ban_kept = in_force > until,
                            Err(e) => {
                                self.send_refusal(Refusal::internal("ban", e)).await?;
                                continue;
                            }
                        }
                    }
                    let reason = if req.reason.is_empty() {
                        "disconnected by an administrator".to_string()
                    } else {
                        req.reason.clone()
                    };
                    let reached = self.ctx.presence.disconnect(&req.username, &reason).await;
                    if reached == 0 && req.ban_secs == 0 {
                        // Pure kick with nobody online is a no-op worth
                        // reporting; a ban of an offline account is fine.
                        self.send_error(&format!("{} is not online", req.username))
                            .await?;
                    } else {
                        let ack = if req.ban_secs > 0 {
                            let kept = if longer_ban_kept {
                                " (a longer existing ban stays in force)"
                            } else {
                                ""
                            };
                            format!(
                                "banned {}{} — {} session(s) dropped",
                                req.username, kept, reached
                            )
                        } else {
                            format!("disconnected {} — {} session(s)", req.username, reached)
                        };
                        let action = if req.ban_secs > 0 { "banned" } else { "kicked" };
                        let detail = if req.ban_secs > 0 {
                            format!(
                                "target={}, ban_secs={}, reason={}",
                                req.username, req.ban_secs, reason
                            )
                        } else {
                            format!("target={}, reason={}", req.username, reason)
                        };
                        let _ = self
                            .ctx
                            .history
                            .record(unix_now(), Some(&admin_name), action, &detail)
                            .await;
                        self.send(
                            PacketType::Info,
                            PacketFlags::SYSTEM_MESSAGE,
                            Bytes::copy_from_slice(ack.as_bytes()),
                        )
                        .await?;
                    }
                }
                other => {
                    warn!(packet_type = ?other, "unhandled packet type");
                    self.send(
                        PacketType::Error,
                        PacketFlags::SYSTEM_MESSAGE,
                        Bytes::from_static(b"unhandled packet type"),
                    )
                    .await?;
                }
            }
        };

        // Cleanup regardless of how the loop ended: leave rooms, presence,
        // and end the session.
        if let Some(session) = &self.session {
            for (room, _handle) in joined {
                self.ctx.rooms.leave(&room, session.id).await;
                debug!(room, "left on disconnect");
            }
            self.ctx.presence.leave(session.id).await;
            self.ctx.auth.end_session(session.id);
        }
        result
    }

    /// Fire-and-forget an audit-log entry on a detached task, used only for
    /// the login paths in `authenticate()`. Awaiting `history.record` inline
    /// there — even though it's best-effort and its own errors are ignored —
    /// still delayed `dispatch_loop`'s `presence.join()` on the success path,
    /// just long enough to lose a race against another connection's
    /// immediately-following broadcast. Other call sites (role/account/
    /// settings mutations etc.) await `history.record` inline on purpose:
    /// their reply is the thing a test or client might act on next, and the
    /// write should be durable before that reply lands.
    fn record_history(&self, actor: Option<String>, action: &'static str, detail: String) {
        let ctx = self.ctx.clone();
        tokio::spawn(async move {
            let _ = ctx.history.record(unix_now(), actor.as_deref(), action, &detail).await;
        });
    }

    async fn send_error(&mut self, message: &str) -> Result<(), ProtocolError> {
        self.send(
            PacketType::Error,
            PacketFlags::SYSTEM_MESSAGE,
            Bytes::copy_from_slice(message.as_bytes()),
        )
        .await
    }

    /// Report a refused or failed admin request: a policy refusal goes to the
    /// client verbatim; an internal failure is logged here and the client
    /// gets only a generic message (STORE-9).
    async fn send_refusal(&mut self, refusal: Refusal) -> Result<(), ProtocolError> {
        if let Refusal::Internal { what, detail } = &refusal {
            warn!(error = %detail, "{what} failed");
        }
        self.send_error(&refusal.client_message()).await
    }

    /// Apply the current IP rules to already-connected sessions: drop every
    /// user connected from an address the rules now deny, except the acting
    /// admin (who can then still undo a rule that would lock them out).
    async fn enforce_ip_rules_on_live_sessions(&mut self) {
        let actor = self.session.as_ref().expect("authed").username.clone();
        let kicked = self
            .ctx
            .ip_rules
            .disconnect_denied(
                &self.ctx.presence,
                "your address is no longer allowed on this server",
                &actor,
            )
            .await;
        if !kicked.is_empty() {
            debug!(users = ?kicked, "disconnected sessions denied by IP rules");
        }
    }

    /// Send the full, current role list — the reply to a successful role
    /// mutation as well as to `RoleListRequest` itself, so every client's
    /// Roles window can just re-render from one message shape.
    async fn reply_role_list(&mut self) -> Result<(), ConnectionError> {
        match self.ctx.roles.list().await {
            Ok(roles) => {
                let response = RoleListResponse {
                    roles: roles.into_iter().map(role_to_wire).collect(),
                };
                self.send(
                    PacketType::RoleListResponse,
                    PacketFlags::empty(),
                    response.encode(),
                )
                .await?;
            }
            Err(e) => self.send_refusal(Refusal::internal("role listing", e)).await?,
        }
        Ok(())
    }

    /// Send the full account list — the reply to `AccountListRequest` and to
    /// every successful account mutation, so the Accounts window re-renders
    /// from one message shape.
    async fn reply_account_list(&mut self) -> Result<(), ConnectionError> {
        match self.ctx.auth.list_accounts().await {
            Ok(rows) => {
                let response = AccountListResponse {
                    accounts: rows
                        .into_iter()
                        .map(|(username, base_class, granted, revoked)| AccountSummary {
                            username,
                            base_class,
                            granted,
                            revoked,
                        })
                        .collect(),
                };
                self.send(
                    PacketType::AccountListResponse,
                    PacketFlags::empty(),
                    response.encode(),
                )
                .await?;
            }
            Err(e) => self.send_refusal(Refusal::internal("account listing", e)).await?,
        }
        Ok(())
    }

    /// List `path` for `class` and send it as a `FileListResponse` — the reply
    /// to a successful folder create/delete so the Files window re-renders.
    async fn reply_file_list(&mut self, path: &str, session: &Session) -> Result<(), ConnectionError> {
        match self.ctx.tree.list(path, &session).await {
            Ok(entries) => {
                let response = FileListResponse {
                    path: path.to_owned(),
                    entries: entries
                        .into_iter()
                        .map(|e| FileEntry {
                            name: e.name,
                            kind: e.kind.as_u8(),
                            size: e.size,
                        })
                        .collect(),
                };
                self.send(
                    PacketType::FileListResponse,
                    PacketFlags::empty(),
                    response.encode(),
                )
                .await?;
            }
            Err(e) => self.send_error(&e.to_string()).await?,
        }
        Ok(())
    }

    /// Send the current server settings — the reply to `ServerSettingsRequest`
    /// and to a successful `ServerSettingsUpdate`.
    async fn reply_server_settings(&mut self) -> Result<(), ConnectionError> {
        let snap = self.ctx.settings.snapshot().await;
        let response = ServerSettingsResponse {
            name: snap.name,
            description: snap.description,
            greeting: snap.greeting,
            max_users: snap.max_users,
            port: self.ctx.bind_port,
            max_upload_bytes_per_sec: self.ctx.transfers.upload_rate(),
            max_download_bytes_per_sec: self.ctx.transfers.download_rate(),
        };
        self.send(
            PacketType::ServerSettingsResponse,
            PacketFlags::empty(),
            response.encode(),
        )
        .await?;
        Ok(())
    }

    /// Send the current IP rule set — the reply to a successful create or delete
    /// so the admin's window can just re-render from one message shape.
    async fn reply_ip_rule_list(&mut self) -> Result<(), ConnectionError> {
        match self.ctx.ip_rules.list().await {
            Ok(rules) => {
                let response = IpRuleListResponse {
                    rules: rules
                        .into_iter()
                        .map(|r| WireIpRule {
                            id: r.id,
                            position: r.position,
                            action: match r.action {
                                crate::ip_rules::Action::Allow => "allow".into(),
                                crate::ip_rules::Action::Deny => "deny".into(),
                            },
                            cidr: r.cidr,
                            note: r.note,
                            created_by: r.created_by,
                            created_at: r.created_at,
                        })
                        .collect(),
                };
                self.send(
                    PacketType::IpRuleListResponse,
                    PacketFlags::empty(),
                    response.encode(),
                )
                .await?;
            }
            Err(e) => self.send_refusal(ip_rule_refusal("ip rule listing", e)).await?,
        }
        Ok(())
    }

    /// Send the newsgroups the caller may read (filtered by their class) — the
    /// reply to `NewsgroupListRequest` and to a successful create.
    async fn reply_newsgroup_list(&mut self) -> Result<(), ConnectionError> {
        let my_class = self.session.as_ref().expect("authed").class as u8;
        match self.ctx.news.list_groups().await {
            Ok(groups) => {
                let groups = groups
                    .into_iter()
                    .filter(|g| my_class >= g.min_read_class)
                    .map(|g| NewsgroupInfo {
                        id: *g.id.as_bytes(),
                        name: g.name,
                        description: g.description,
                        min_read_class: g.min_read_class,
                        min_post_class: g.min_post_class,
                    })
                    .collect();
                let response = NewsgroupListResponse { groups };
                self.send(
                    PacketType::NewsgroupListResponse,
                    PacketFlags::empty(),
                    response.encode(),
                )
                .await?;
            }
            Err(e) => self.send_refusal(news_refusal("newsgroup listing", e)).await?,
        }
        Ok(())
    }

    /// Send the newest posts of a newsgroup — the reply to
    /// `NewsThreadListRequest` and to a reader's successful post/delete, so
    /// the News window re-renders from one shape. Bounded by
    /// [`crate::news::reply_window`] (DOS-11). The caller has already passed
    /// the read-class check.
    async fn reply_thread_list(&mut self, group_id: Uuid) -> Result<(), ConnectionError> {
        match self
            .ctx
            .news
            .recent_posts(group_id, crate::news::THREAD_REPLY_MAX_POSTS)
            .await
        {
            Ok(newest_first) => {
                let posts = crate::news::reply_window(newest_first);
                self.send_thread_list(group_id, posts).await?;
            }
            Err(e) => self.send_refusal(news_refusal("news listing", e)).await?,
        }
        Ok(())
    }

    /// Send exactly `posts` as a group's `NewsThreadListResponse`.
    async fn send_thread_list(
        &mut self,
        group_id: Uuid,
        posts: Vec<NewsPostDomain>,
    ) -> Result<(), ConnectionError> {
        let response = NewsThreadListResponse {
            newsgroup_id: *group_id.as_bytes(),
            posts: posts.into_iter().map(news_post_to_wire).collect(),
        };
        self.send(
            PacketType::NewsThreadListResponse,
            PacketFlags::empty(),
            response.encode(),
        )
        .await?;
        Ok(())
    }

    /// Stream every chunk the client still needs, then the terminal
    /// `TransferEnd`. Runs inline in the dispatch loop — one transfer at a
    /// time per connection, matching the upload model.
    async fn stream_download(
        &mut self,
        stream: &mut crate::transfer::ActiveDownload,
    ) -> Result<(), ConnectionError> {
        let transfer_id = *stream.id().as_bytes();
        while let Some(chunk) = stream.next_chunk().await? {
            let data = TransferData {
                transfer_id,
                chunk_index: chunk.index,
                chunk_hash: chunk.hash,
                data: chunk.data,
            };
            self.send_fragmented(PacketType::FileTransferData, PacketFlags::empty(), data.encode())
                .await?;
        }
        let end = TransferEnd {
            transfer_id,
            status: TRANSFER_VERIFIED,
            message: "verified".into(),
        };
        self.send(PacketType::FileTransferEnd, PacketFlags::TRANSFER_END, end.encode())
            .await?;
        Ok(())
    }

    /// Send a payload, fragmenting it across frames when it exceeds the frame
    /// cap (download chunks can be larger than one frame).
    async fn send_fragmented(
        &mut self,
        packet_type: PacketType,
        flags: PacketFlags,
        payload: Bytes,
    ) -> Result<(), ProtocolError> {
        let mut seq = self.next_sequence;
        let frames = kdx_protocol::fragment(
            packet_type,
            flags,
            payload,
            kdx_protocol::DEFAULT_MAX_FRAME_PAYLOAD,
            || {
                let s = seq;
                seq = seq.wrapping_add(1);
                s
            },
        );
        self.next_sequence = seq;
        for frame in frames {
            self.framed.send(frame).await?;
        }
        Ok(())
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

/// Peek a `FileTransferStart` payload's direction byte without a full decode,
/// so dispatch can branch upload vs download. The direction is the first
/// payload byte (see `TransferRequest::encode`).
fn is_download(payload: &[u8]) -> bool {
    payload.first() == Some(&kdx_protocol::messages::DIRECTION_DOWNLOAD)
}

/// Clamp a wire class byte (0..=3) to a `BaseClass`.
fn class_from_u8(v: u8) -> BaseClass {
    BaseClass::try_from(v.min(3)).expect("clamped to a valid class")
}

/// The parent directory of a `/`-separated path (`/a/b/c` → `/a/b`, `/x` → `/`).
fn parent_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some((parent, _)) if !parent.is_empty() => parent.to_string(),
        _ => "/".to_string(),
    }
}

fn news_post_to_wire(p: NewsPostDomain) -> WireNewsPost {
    WireNewsPost {
        id: *p.id.as_bytes(),
        newsgroup_id: *p.newsgroup_id.as_bytes(),
        // Domain uses Option<Uuid>; the wire uses an all-zeros sentinel root.
        parent_id: p.parent_id.map(|u| *u.as_bytes()).unwrap_or([0u8; 16]),
        author: p.author,
        subject: p.subject,
        body: p.body,
        timestamp: p.timestamp,
    }
}

fn role_to_wire(role: Role) -> RoleInfo {
    RoleInfo {
        id: *role.id.as_bytes(),
        name: role.name,
        privileges: role.privileges.bits(),
        rank: role.rank,
        color: role.color.unwrap_or_default(),
    }
}

/// What a client may be told about a failed news operation.
fn news_refusal(what: &'static str, err: crate::news::NewsError) -> Refusal {
    use crate::news::NewsError;
    match err {
        NewsError::Storage(e) => Refusal::storage(
            what,
            &e,
            "a newsgroup with that name already exists",
            "no such post",
        ),
        NewsError::CorruptId => Refusal::internal(what, err),
        other => Refusal::denied(other.to_string()),
    }
}

/// What a client may be told about a failed IP-rule operation.
fn ip_rule_refusal(what: &'static str, err: crate::ip_rules::IpRuleError) -> Refusal {
    use crate::ip_rules::IpRuleError;
    match err {
        IpRuleError::InvalidCidr(_) => {
            Refusal::denied("invalid CIDR (expected e.g. 10.0.0.0/8 or 2001:db8::/32)")
        }
        IpRuleError::InvalidAction(_) => Refusal::denied("action must be 'allow' or 'deny'"),
        IpRuleError::Storage(e) => Refusal::storage(what, &e, "that rule already exists", "no such rule"),
    }
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
        let tree = FileTree::load(pool.clone()).await.unwrap();
        let transfers = TransferManager::new(
            pool.clone(),
            crate::transfer::TransferConfig {
                files_root: dir.path().join("files"),
                max_upload_bytes_per_sec: 0,
                max_download_bytes_per_sec: 0,
            },
        )
        .await
        .unwrap();
        let ip_rules = crate::ip_rules::IpRuleManager::load(pool.clone())
            .await
            .expect("ip_rules load");
        let ctx = Arc::new(ServerCtx {
            roles: RoleManager::new(pool.clone()),
            news: NewsManager::new(pool.clone()),
            history: crate::history::HistoryLog::new(pool.clone()),
            ip_rules,
            auth: AuthManager::new(pool, Duration::from_secs(60)),
            rooms: RoomManager::new(),
            tree,
            transfers,
            presence: crate::presence::Presence::spawn(),
            tracker: crate::tracker::Tracker::spawn(crate::tracker::DEFAULT_TTL),
            settings: crate::settings::ServerSettings::new(
                "Test Server".into(),
                String::new(),
                256,
            ),
            bind_port: 0,
            shutdown: Arc::new(Notify::new()),
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

        // Entering dispatch joins the presence roster; joins broadcast only
        // to *other* connections, so this sole client receives nothing.

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

    /// Like `test_ctx`, but seeds a `sysop` admin account instead of a plain
    /// power user, for exercising the USER_ADMIN-gated role wire protocol.
    async fn admin_test_ctx() -> (Arc<ServerCtx>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = kdx_storage::connect(&dir.path().join("test.db"))
            .await
            .unwrap();
        let phc = hash_password("s3cret").unwrap();
        accounts::create(&pool, "sysop", &phc, 3).await.unwrap();
        accounts::create(&pool, "plain", &phc, 1).await.unwrap();
        let tree = FileTree::load(pool.clone()).await.unwrap();
        let transfers = TransferManager::new(
            pool.clone(),
            crate::transfer::TransferConfig {
                files_root: dir.path().join("files"),
                max_upload_bytes_per_sec: 0,
                max_download_bytes_per_sec: 0,
            },
        )
        .await
        .unwrap();
        let ip_rules = crate::ip_rules::IpRuleManager::load(pool.clone())
            .await
            .expect("ip_rules load");
        let ctx = Arc::new(ServerCtx {
            roles: RoleManager::new(pool.clone()),
            news: NewsManager::new(pool.clone()),
            history: crate::history::HistoryLog::new(pool.clone()),
            ip_rules,
            auth: AuthManager::new(pool, Duration::from_secs(60)),
            rooms: RoomManager::new(),
            tree,
            transfers,
            presence: crate::presence::Presence::spawn(),
            tracker: crate::tracker::Tracker::spawn(crate::tracker::DEFAULT_TTL),
            settings: crate::settings::ServerSettings::new(
                "Test Server".into(),
                String::new(),
                256,
            ),
            bind_port: 0,
            shutdown: Arc::new(Notify::new()),
        });
        (ctx, dir)
    }

    /// Send a request and return the next reply frame, skipping unrelated
    /// pushes (e.g. `PresenceChange` from another connection logging in) that
    /// can interleave on a connection that's also joined the presence
    /// roster.
    async fn send_and_recv(
        client: &mut Framed<tokio::io::DuplexStream, KdxCodec>,
        seq: &mut u32,
        packet_type: PacketType,
        payload: Bytes,
    ) -> KdxFrame {
        client
            .send(client_frame(packet_type, bump(seq), payload))
            .await
            .unwrap();
        loop {
            let frame = client.next().await.unwrap().unwrap();
            if frame.header.packet_type != PacketType::PresenceChange {
                return frame;
            }
        }
    }

    #[tokio::test]
    async fn sysop_can_define_and_assign_a_custom_role() {
        let (ctx, _dir) = admin_test_ctx().await;
        let (client, server) = tokio::io::duplex(8192);
        let conn = tokio::spawn(Connection::new(server, ctx.clone()).run());
        let mut client = client_framed(client);
        let mut seq = 0;

        do_handshake(&mut client, &mut seq).await;
        let login = do_login(&mut client, &mut seq, "sysop", "s3cret").await;
        assert!(login.success);

        // Define a role beyond any base class's set.
        let create = RoleCreate {
            name: "Moderator".into(),
            privileges: (Privileges::USER_KICK | Privileges::USER_BAN).bits(),
            rank: 10,
            color: "#e11b1b".into(),
        };
        let frame = send_and_recv(&mut client, &mut seq, PacketType::RoleCreate, create.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::RoleListResponse);
        let list = RoleListResponse::decode(&frame.payload).unwrap();
        assert_eq!(list.roles.len(), 1);
        assert_eq!(list.roles[0].name, "Moderator");
        let role_id = list.roles[0].id;

        // Assign it to another account by username.
        let assign = RoleAssign {
            username: "plain".into(),
            role_id,
        };
        let frame = send_and_recv(&mut client, &mut seq, PacketType::RoleAssign, assign.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::RoleListResponse);

        // Confirm the assignment stuck via AccountRolesRequest.
        let frame = send_and_recv(
            &mut client,
            &mut seq,
            PacketType::AccountRolesRequest,
            (kdx_protocol::messages::AccountRolesRequest {
                username: "plain".into(),
            })
            .encode(),
        )
        .await;
        assert_eq!(frame.header.packet_type, PacketType::AccountRolesResponse);
        let resp = AccountRolesResponse::decode(&frame.payload).unwrap();
        assert_eq!(resp.role_ids, vec![role_id]);

        // The role's privileges show up on a fresh login for that account —
        // not just in the assignment records.
        let (client2, server2) = tokio::io::duplex(8192);
        let conn2 = tokio::spawn(Connection::new(server2, ctx.clone()).run());
        let mut client2 = client_framed(client2);
        let mut seq2 = 0;
        do_handshake(&mut client2, &mut seq2).await;
        let login2 = do_login(&mut client2, &mut seq2, "plain", "s3cret").await;
        assert!(login2.success);
        let session2 = ctx
            .auth
            .validate(uuid::Uuid::from_bytes(login2.session_id))
            .unwrap();
        assert!(session2.privileges.contains(Privileges::USER_KICK));
        assert!(session2.privileges.contains(Privileges::USER_BAN));
        client2
            .send(client_frame(PacketType::Disconnect, bump(&mut seq2), Bytes::new()))
            .await
            .unwrap();
        conn2.await.unwrap().unwrap();

        // Unassign, then delete — list drains back to empty.
        let unassign = RoleUnassign {
            username: "plain".into(),
            role_id,
        };
        send_and_recv(&mut client, &mut seq, PacketType::RoleUnassign, unassign.encode()).await;

        let delete = RoleDelete { id: role_id };
        let frame = send_and_recv(&mut client, &mut seq, PacketType::RoleDelete, delete.encode()).await;
        let list = RoleListResponse::decode(&frame.payload).unwrap();
        assert!(list.roles.is_empty());

        client
            .send(client_frame(PacketType::Disconnect, bump(&mut seq), Bytes::new()))
            .await
            .unwrap();
        conn.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn plain_user_cannot_manage_roles() {
        let (ctx, _dir) = admin_test_ctx().await;
        let (client, server) = tokio::io::duplex(8192);
        let conn = tokio::spawn(Connection::new(server, ctx).run());
        let mut client = client_framed(client);
        let mut seq = 0;

        do_handshake(&mut client, &mut seq).await;
        let login = do_login(&mut client, &mut seq, "plain", "s3cret").await;
        assert!(login.success);

        let create = RoleCreate {
            name: "Moderator".into(),
            privileges: Privileges::USER_KICK.bits(),
            rank: 1,
            color: String::new(),
        };
        let frame = send_and_recv(&mut client, &mut seq, PacketType::RoleCreate, create.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::Error);

        client
            .send(client_frame(PacketType::Disconnect, bump(&mut seq), Bytes::new()))
            .await
            .unwrap();
        conn.await.unwrap().unwrap();
    }

    // ---- admin authorization hardening (AUTH-1, AUTHZ-*, STORE-*, DOS-11) ----

    type Client = Framed<tokio::io::DuplexStream, KdxCodec>;
    type ConnTask = tokio::task::JoinHandle<Result<(), ConnectionError>>;

    /// Handshake and log `username` (password "s3cret") in on a fresh duplex
    /// connection whose presence address is `peer`, then ping so the
    /// dispatch loop (and its presence join) is known to be running.
    async fn connect_as(ctx: &Arc<ServerCtx>, username: &str, peer: &str) -> (Client, u32, ConnTask) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let conn = tokio::spawn(Connection::new_with_peer(server, ctx.clone(), peer.to_string()).run());
        let mut client = client_framed(client);
        let mut seq = 0;
        do_handshake(&mut client, &mut seq).await;
        let login = do_login(&mut client, &mut seq, username, "s3cret").await;
        assert!(login.success, "{username} should log in");
        let pong = send_and_recv(&mut client, &mut seq, PacketType::Ping, Bytes::from_static(b"p")).await;
        assert_eq!(pong.header.packet_type, PacketType::Pong);
        (client, seq, conn)
    }

    async fn hang_up(mut client: Client, mut seq: u32, conn: ConnTask) {
        client
            .send(client_frame(PacketType::Disconnect, bump(&mut seq), Bytes::new()))
            .await
            .unwrap();
        conn.await.unwrap().unwrap();
    }

    /// Read until the server's `Disconnect` frame (`true`) or EOF/timeout.
    async fn wait_for_disconnect(client: &mut Client) -> bool {
        loop {
            match timeout(Duration::from_secs(5), client.next()).await {
                Ok(Some(Ok(frame))) if frame.header.packet_type == PacketType::Disconnect => return true,
                Ok(Some(Ok(_))) => continue,
                _ => return false,
            }
        }
    }

    async fn seed(ctx: &ServerCtx, username: &str, class: i64, granted: Privileges) {
        ctx.auth
            .create_account(username, "s3cret", class, granted.bits() as i64, 0)
            .await
            .unwrap();
    }

    fn error_text(frame: &KdxFrame) -> String {
        assert_eq!(frame.header.packet_type, PacketType::Error);
        String::from_utf8_lossy(&frame.payload).into_owned()
    }

    #[tokio::test]
    async fn delegated_user_admin_cannot_escalate_or_touch_admins() {
        let (ctx, _dir) = admin_test_ctx().await;
        seed(&ctx, "helpdesk", 2, Privileges::USER_ADMIN).await;
        let (mut client, mut seq, conn) = connect_as(&ctx, "helpdesk", "unknown").await;

        let all = Privileges::all().bits();
        let attempts = [
            // Grant itself every privilege.
            (
                PacketType::AccountUpdate,
                AccountUpdate { username: "helpdesk".into(), base_class: 2, granted: all, revoked: 0 }.encode(),
            ),
            // Demote and strip the real admin.
            (
                PacketType::AccountUpdate,
                AccountUpdate { username: "sysop".into(), base_class: 0, granted: 0, revoked: all }.encode(),
            ),
            // Mint a puppet holding privileges it lacks...
            (
                PacketType::AccountCreate,
                AccountCreate {
                    username: "puppet".into(),
                    password: "pw".into(),
                    base_class: 1,
                    granted: Privileges::SERVER_ADMIN.bits(),
                    revoked: 0,
                }
                .encode(),
            ),
            // ...or of its own rank.
            (
                PacketType::AccountCreate,
                AccountCreate { username: "peer".into(), password: "pw".into(), base_class: 2, granted: 0, revoked: 0 }
                    .encode(),
            ),
            // A role carrying privileges it lacks.
            (
                PacketType::RoleCreate,
                RoleCreate { name: "Root".into(), privileges: all, rank: 99, color: String::new() }.encode(),
            ),
        ];
        for (packet_type, payload) in attempts {
            let frame = send_and_recv(&mut client, &mut seq, packet_type, payload).await;
            assert_eq!(frame.header.packet_type, PacketType::Error, "{packet_type:?} must be refused");
        }

        // A role within its own privileges is fine, but it can't hand that
        // role to itself (it doesn't outrank itself)...
        let create = RoleCreate { name: "Helper".into(), privileges: Privileges::CHAT_SEND.bits(), rank: 1, color: String::new() };
        let frame = send_and_recv(&mut client, &mut seq, PacketType::RoleCreate, create.encode()).await;
        let role_id = RoleListResponse::decode(&frame.payload).unwrap().roles[0].id;
        let assign = RoleAssign { username: "helpdesk".into(), role_id };
        let frame = send_and_recv(&mut client, &mut seq, PacketType::RoleAssign, assign.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::Error);
        // ...while it can still manage a lower account within its bounds.
        let demote = AccountUpdate { username: "plain".into(), base_class: 0, granted: 0, revoked: 0 };
        let frame = send_and_recv(&mut client, &mut seq, PacketType::AccountUpdate, demote.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::AccountListResponse);

        // None of the escalations stuck.
        let sysop = ctx.roles.account_state("sysop").await.unwrap().unwrap();
        assert_eq!((sysop.class, sysop.revoked), (BaseClass::Admin, 0));
        let me = ctx.roles.account_state("helpdesk").await.unwrap().unwrap();
        assert_eq!(me.effective(), BaseClass::PowerUser.privileges() | Privileges::USER_ADMIN);
        assert!(ctx.roles.account_state("puppet").await.unwrap().is_none());
        assert!(ctx.roles.account_state("peer").await.unwrap().is_none());

        hang_up(client, seq, conn).await;
    }

    #[tokio::test]
    async fn last_admin_cannot_demote_or_strip_itself() {
        let (ctx, _dir) = admin_test_ctx().await;
        seed(&ctx, "backup", 3, Privileges::empty()).await;
        let (mut client, mut seq, conn) = connect_as(&ctx, "sysop", "unknown").await;

        // With a second admin around, demoting that one is fine...
        let demote = AccountUpdate { username: "backup".into(), base_class: 1, granted: 0, revoked: 0 };
        let frame = send_and_recv(&mut client, &mut seq, PacketType::AccountUpdate, demote.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::AccountListResponse);

        // ...but now sysop is the last one.
        let attempts = [
            AccountUpdate { username: "sysop".into(), base_class: 2, granted: 0, revoked: 0 },
            AccountUpdate {
                username: "sysop".into(),
                base_class: 3,
                granted: 0,
                revoked: Privileges::USER_ADMIN.bits(),
            },
        ];
        for update in attempts {
            let frame = send_and_recv(&mut client, &mut seq, PacketType::AccountUpdate, update.encode()).await;
            assert!(error_text(&frame).contains("administrator"));
        }
        let sysop = ctx.roles.account_state("sysop").await.unwrap().unwrap();
        assert!(sysop.administers());

        hang_up(client, seq, conn).await;
    }

    #[tokio::test]
    async fn demoting_a_live_admin_disconnects_them() {
        let (ctx, _dir) = admin_test_ctx().await;
        seed(&ctx, "deputy", 3, Privileges::empty()).await;
        let (mut deputy, _dseq, deputy_conn) = connect_as(&ctx, "deputy", "unknown").await;
        let (mut sysop, mut seq, conn) = connect_as(&ctx, "sysop", "unknown").await;

        let demote = AccountUpdate { username: "deputy".into(), base_class: 1, granted: 0, revoked: 0 };
        let frame = send_and_recv(&mut sysop, &mut seq, PacketType::AccountUpdate, demote.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::AccountListResponse);

        // The demoted admin's live session is forced to reconnect.
        assert!(wait_for_disconnect(&mut deputy).await, "deputy should be disconnected");
        deputy_conn.await.unwrap().unwrap();

        hang_up(sysop, seq, conn).await;
    }

    #[tokio::test]
    async fn stale_session_cannot_reuse_revoked_admin_rights() {
        let (ctx, _dir) = admin_test_ctx().await;
        seed(&ctx, "deputy", 3, Privileges::empty()).await;
        let (mut deputy, mut seq, conn) = connect_as(&ctx, "deputy", "unknown").await;

        // Demoted behind the session's back (no kick): its login snapshot
        // still says Admin, but the stored account now rules.
        ctx.auth.update_account("deputy", 1, 0, 0).await.unwrap();

        let repromote = AccountUpdate { username: "deputy".into(), base_class: 3, granted: 0, revoked: 0 };
        let frame = send_and_recv(&mut deputy, &mut seq, PacketType::AccountUpdate, repromote.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::Error);
        let demote_sysop = AccountUpdate { username: "sysop".into(), base_class: 0, granted: 0, revoked: 0 };
        let frame = send_and_recv(&mut deputy, &mut seq, PacketType::AccountUpdate, demote_sysop.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::Error);
        let kick = AdminDisconnect { username: "sysop".into(), reason: String::new(), ban_secs: 60 };
        let frame = send_and_recv(&mut deputy, &mut seq, PacketType::AdminDisconnect, kick.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::Error);

        assert_eq!(ctx.roles.account_state("deputy").await.unwrap().unwrap().class, BaseClass::User);
        assert_eq!(ctx.roles.account_state("sysop").await.unwrap().unwrap().class, BaseClass::Admin);

        hang_up(deputy, seq, conn).await;
    }

    #[tokio::test]
    async fn role_list_is_admin_only_and_role_grants_kick_live_holders() {
        let (ctx, _dir) = admin_test_ctx().await;
        let (mut plain, mut pseq, plain_conn) = connect_as(&ctx, "plain", "unknown").await;
        let frame = send_and_recv(&mut plain, &mut pseq, PacketType::RoleListRequest, RoleListRequest.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::Error);

        let (mut sysop, mut seq, conn) = connect_as(&ctx, "sysop", "unknown").await;
        let create = RoleCreate { name: "Mod".into(), privileges: Privileges::USER_KICK.bits(), rank: 5, color: "#e11b1b".into() };
        let frame = send_and_recv(&mut sysop, &mut seq, PacketType::RoleCreate, create.encode()).await;
        let role_id = RoleListResponse::decode(&frame.payload).unwrap().roles[0].id;
        let assign = RoleAssign { username: "plain".into(), role_id };
        let frame = send_and_recv(&mut sysop, &mut seq, PacketType::RoleAssign, assign.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::RoleListResponse);

        // plain's session predates the grant: it must reconnect.
        assert!(wait_for_disconnect(&mut plain).await, "role holder should be disconnected");
        plain_conn.await.unwrap().unwrap();

        // A malformed color is refused rather than stored.
        let bad = RoleCreate { name: "Evil".into(), privileges: 0, rank: 0, color: "red;background:url(x)".into() };
        let frame = send_and_recv(&mut sysop, &mut seq, PacketType::RoleCreate, bad.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::Error);

        hang_up(sysop, seq, conn).await;
    }

    fn thread_posts(frame: &KdxFrame) -> Vec<WireNewsPost> {
        assert_eq!(frame.header.packet_type, PacketType::NewsThreadListResponse);
        NewsThreadListResponse::decode(&frame.payload).unwrap().posts
    }

    fn newsgroup_id(frame: &KdxFrame, name: &str) -> [u8; 16] {
        assert_eq!(frame.header.packet_type, PacketType::NewsgroupListResponse);
        NewsgroupListResponse::decode(&frame.payload)
            .unwrap()
            .groups
            .into_iter()
            .find(|g| g.name == name)
            .expect("group listed")
            .id
    }

    fn news_post(group: [u8; 16], parent: [u8; 16], subject: &str) -> Bytes {
        NewsPostCreate { newsgroup_id: group, parent_id: parent, subject: subject.into(), body: "body".into() }.encode()
    }

    #[tokio::test]
    async fn news_replies_respect_read_class_group_boundaries_and_authorship() {
        let (ctx, _dir) = admin_test_ctx().await;
        let (mut sysop, mut seq, conn) = connect_as(&ctx, "sysop", "unknown").await;

        // A class threshold above Admin would hide the group from everyone.
        let hidden = NewsgroupCreate { name: "hidden".into(), description: String::new(), min_read_class: 4, min_post_class: 0 };
        let frame = send_and_recv(&mut sysop, &mut seq, PacketType::NewsgroupCreate, hidden.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::Error);
        assert!(ctx.news.list_groups().await.unwrap().is_empty());

        // A write-only suggestion box (read: admin, post: anyone) and a public group.
        let box_group = NewsgroupCreate { name: "suggestions".into(), description: String::new(), min_read_class: 3, min_post_class: 0 };
        let frame = send_and_recv(&mut sysop, &mut seq, PacketType::NewsgroupCreate, box_group.encode()).await;
        let suggestions = newsgroup_id(&frame, "suggestions");
        let public = NewsgroupCreate { name: "general".into(), description: String::new(), min_read_class: 0, min_post_class: 0 };
        let frame = send_and_recv(&mut sysop, &mut seq, PacketType::NewsgroupCreate, public.encode()).await;
        let general = newsgroup_id(&frame, "general");

        let frame = send_and_recv(&mut sysop, &mut seq, PacketType::NewsPostCreate, news_post(suggestions, [0; 16], "secret plans")).await;
        let secret_id = thread_posts(&frame)[0].id;

        // A post-only member gets back just their own post, never the group.
        let (mut plain, mut pseq, plain_conn) = connect_as(&ctx, "plain", "unknown").await;
        let frame = send_and_recv(&mut plain, &mut pseq, PacketType::NewsPostCreate, news_post(suggestions, [0; 16], "idea")).await;
        let posts = thread_posts(&frame);
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].author, "plain");

        // A reply must name a parent in the same group.
        let frame = send_and_recv(&mut plain, &mut pseq, PacketType::NewsPostCreate, news_post(general, secret_id, "re: secret")).await;
        assert_eq!(frame.header.packet_type, PacketType::Error);

        // plain starts a thread, sysop replies; plain may no longer delete the
        // root, since that would take sysop's reply with it.
        let frame = send_and_recv(&mut plain, &mut pseq, PacketType::NewsPostCreate, news_post(general, [0; 16], "hello")).await;
        let root_id = thread_posts(&frame)[0].id;
        let frame = send_and_recv(&mut sysop, &mut seq, PacketType::NewsPostCreate, news_post(general, root_id, "re: hello")).await;
        assert_eq!(thread_posts(&frame).len(), 2);
        let delete = NewsPostDelete { post_id: root_id };
        let frame = send_and_recv(&mut plain, &mut pseq, PacketType::NewsPostDelete, delete.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::Error);
        assert_eq!(ctx.news.posts(Uuid::from_bytes(general)).await.unwrap().len(), 2);
        // A moderator (USER_ADMIN) still can.
        let frame = send_and_recv(&mut sysop, &mut seq, PacketType::NewsPostDelete, delete.encode()).await;
        assert!(thread_posts(&frame).is_empty());

        hang_up(plain, pseq, plain_conn).await;
        hang_up(sysop, seq, conn).await;
    }

    #[tokio::test]
    async fn deny_rule_disconnects_matching_live_sessions() {
        let (ctx, _dir) = admin_test_ctx().await;
        // How an IPv4 client shows up on a dual-stack listener.
        let (mut plain, _pseq, plain_conn) = connect_as(&ctx, "plain", "[::ffff:10.9.9.9]:4000").await;
        let (mut sysop, mut seq, conn) = connect_as(&ctx, "sysop", "192.0.2.1:5000").await;

        let rule = IpRuleCreate { position: 10, action: "deny".into(), cidr: "10.0.0.0/8".into(), note: "abuse".into() };
        let frame = send_and_recv(&mut sysop, &mut seq, PacketType::IpRuleCreate, rule.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::IpRuleListResponse);

        assert!(wait_for_disconnect(&mut plain).await, "denied address should be dropped");
        plain_conn.await.unwrap().unwrap();
        // The admin, from an allowed address, is untouched.
        let pong = send_and_recv(&mut sysop, &mut seq, PacketType::Ping, Bytes::from_static(b"p")).await;
        assert_eq!(pong.header.packet_type, PacketType::Pong);

        hang_up(sysop, seq, conn).await;
    }

    #[tokio::test]
    async fn bad_admin_input_gets_errors_not_disconnects() {
        let (ctx, _dir) = admin_test_ctx().await;
        let (mut sysop, mut seq, conn) = connect_as(&ctx, "sysop", "unknown").await;

        // An oversized greeting would break every later login (OPS-11).
        let update = ServerSettingsUpdate {
            name: "Test Server".into(),
            description: String::new(),
            greeting: "g".repeat(crate::limits::MAX_GREETING_LEN + 1),
            max_users: 10,
        };
        let frame = send_and_recv(&mut sysop, &mut seq, PacketType::ServerSettingsUpdate, update.encode()).await;
        assert!(error_text(&frame).contains("greeting"));
        assert_eq!(ctx.settings.greeting().await, "");

        // A duplicate role name is reported plainly, without SQL text (STORE-9).
        let create = RoleCreate { name: "Mod".into(), privileges: 0, rank: 0, color: String::new() };
        send_and_recv(&mut sysop, &mut seq, PacketType::RoleCreate, create.encode()).await;
        let frame = send_and_recv(&mut sysop, &mut seq, PacketType::RoleCreate, create.encode()).await;
        let text = error_text(&frame);
        assert!(text.contains("already exists"), "got: {text}");
        assert!(!text.contains("UNIQUE") && !text.contains("code"), "leaked: {text}");

        // Length caps (limits.rs).
        let broadcast = AdminBroadcast { text: "b".repeat(crate::limits::MAX_BROADCAST_LEN + 1) };
        let frame = send_and_recv(&mut sysop, &mut seq, PacketType::AdminBroadcast, broadcast.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::Error);
        let group = NewsgroupCreate {
            name: "n".repeat(crate::limits::MAX_NAME_LEN + 1),
            description: String::new(),
            min_read_class: 0,
            min_post_class: 0,
        };
        let frame = send_and_recv(&mut sysop, &mut seq, PacketType::NewsgroupCreate, group.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::Error);
        let kick = AdminDisconnect { username: "plain".into(), reason: "r".repeat(crate::limits::MAX_REASON_LEN + 1), ban_secs: 0 };
        let frame = send_and_recv(&mut sysop, &mut seq, PacketType::AdminDisconnect, kick.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::Error);

        // Still connected, and logins still work.
        let pong = send_and_recv(&mut sysop, &mut seq, PacketType::Ping, Bytes::from_static(b"p")).await;
        assert_eq!(pong.header.packet_type, PacketType::Pong);
        let (plain, pseq, plain_conn) = connect_as(&ctx, "plain", "unknown").await;
        hang_up(plain, pseq, plain_conn).await;

        hang_up(sysop, seq, conn).await;
    }

    #[tokio::test]
    async fn moderator_cannot_shorten_an_admin_ban() {
        let (ctx, _dir) = admin_test_ctx().await;
        seed(&ctx, "mod", 2, Privileges::USER_KICK | Privileges::USER_BAN).await;

        let (mut sysop, mut seq, conn) = connect_as(&ctx, "sysop", "unknown").await;
        let ban = AdminDisconnect { username: "plain".into(), reason: "spam".into(), ban_secs: 3600 };
        let frame = send_and_recv(&mut sysop, &mut seq, PacketType::AdminDisconnect, ban.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::Info);
        hang_up(sysop, seq, conn).await;

        let (mut moderator, mut mseq, mconn) = connect_as(&ctx, "mod", "unknown").await;
        let short = AdminDisconnect { username: "plain".into(), reason: "oops".into(), ban_secs: 1 };
        let frame = send_and_recv(&mut moderator, &mut mseq, PacketType::AdminDisconnect, short.encode()).await;
        assert_eq!(frame.header.packet_type, PacketType::Info);
        let ack = String::from_utf8_lossy(&frame.payload).into_owned();
        assert!(ack.contains("longer existing ban"), "got: {ack}");
        hang_up(moderator, mseq, mconn).await;

        // Still banned (the 1 s re-ban did not replace the hour-long one).
        let (client, server) = tokio::io::duplex(8192);
        let banned_conn = tokio::spawn(Connection::new(server, ctx.clone()).run());
        let mut client = client_framed(client);
        let mut bseq = 0;
        do_handshake(&mut client, &mut bseq).await;
        let result = do_login(&mut client, &mut bseq, "plain", "s3cret").await;
        assert!(!result.success, "plain should still be banned");
        drop(client);
        let _ = banned_conn.await;
    }
}
