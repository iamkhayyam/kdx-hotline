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
    KdxCodec, KdxFrame, PacketFlags, PacketType, ProtocolError, Reassembler,
    PROTOCOL_VERSION,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::timeout;
use tokio_util::codec::Framed;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::auth::{AuthManager, BaseClass, Privileges, Role, RoleManager, Session};
use crate::chat::{Member, Outbound, RoomCommand, RoomManager};
use crate::files::{FileTree, NodeKind};
use crate::news::{NewsManager, Post as NewsPostDomain};
use crate::history::HistoryLog;
use crate::presence::{unix_now, Presence};
use crate::settings::ServerSettings;
use crate::tracker::Tracker;
use crate::transfer::{resume_id_from_wire, ActiveUpload, TransferError, TransferManager};
use crate::chat::flood::FloodGate;
use crate::presence::KillSignal;
use crate::transfer::{ActiveDownload, DownloadChunk};

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

/// How long writing one outbound message (all of its frames) may take before
/// the peer is considered stuck and the connection is dropped.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Budget for the parting words of a server-initiated close (queued events,
/// then the `Disconnect` reason), so a peer that stopped reading can't hold
/// up a kick.
pub const FAREWELL_TIMEOUT: Duration = Duration::from_secs(5);
/// Floor for the post-login idle timeout (`session_ttl_secs`), comfortably
/// above the stock client's 30 s keepalive ping.
pub const MIN_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Cap on a reassembled inbound control message (everything but transfers).
pub const MAX_CONTROL_PAYLOAD: usize = 64 * 1024;
/// Cap on a reassembled inbound `FileTransferStart`, which carries a resume
/// bitmap that can outgrow `MAX_CONTROL_PAYLOAD` for large files.
pub const MAX_TRANSFER_START_PAYLOAD: usize = 1024 * 1024;
/// Error reply for a request refused by a per-command rate limit.
const SLOW_DOWN: &str = "rate limit exceeded: slow down";

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
    #[error("write to peer timed out")]
    WriteTimeout,
    #[error("no activity within the idle timeout")]
    IdleTimeout,
    /// Internal to `send`: the message can't be framed for any client (over
    /// `MAX_REASSEMBLED_PAYLOAD`). `send` answers with an `Error` reply
    /// instead, so this never ends a connection.
    #[error("outbound message of {len} bytes exceeds the reassembly cap")]
    MessageTooLarge { len: usize },
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
        let session = self.session.as_ref().expect("authed in dispatch").clone();
        // Armed before anything is registered, so every way out of here —
        // an error, a panic, or this task being dropped — unregisters the
        // session (see `SessionGuard`).
        let mut guard = SessionGuard {
            ctx: self.ctx.clone(),
            session_id: session.id,
            joined: HashMap::new(),
            armed: true,
        };
        // Outbound events (room broadcasts etc.) flow through this channel;
        // its sender is what we hand to room actors on join.
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Outbound>(OUTBOUND_QUEUE);

        // Join the server-wide presence roster for the User List / User Info
        // windows; every authenticated connection is visible here regardless
        // of which chat rooms it's in. Only sessions that may act on peers
        // (USER_KICK) see their addresses. The returned kill signal is how
        // kicks, bans and shutdown reach this connection.
        let mut kill = self
            .ctx
            .presence
            .join(
                session.id,
                session.username.clone(),
                session.class as u8,
                self.peer_addr.clone(),
                session.privileges.contains(Privileges::USER_KICK),
                outbound_tx.clone(),
            )
            .await;

        let result = self
            .dispatch_inner(&mut guard.joined, &outbound_tx, &mut outbound_rx, &mut kill)
            .await;
        // Cleanup regardless of how the loop ended: leave rooms, presence,
        // and end the session.
        guard.cleanup().await;
        result
    }

    /// The dispatch loop proper. Every way out of it — `break`, `?`, an
    /// explicit `return` — lands back in `dispatch_loop`, which then runs the
    /// session cleanup.
    async fn dispatch_inner(
        &mut self,
        joined: &mut HashMap<String, mpsc::Sender<RoomCommand>>,
        outbound_tx: &mpsc::Sender<Outbound>,
        outbound_rx: &mut mpsc::Receiver<Outbound>,
        kill: &mut KillSignal,
    ) -> Result<(), ConnectionError> {
        // One upload at a time per connection; the chunk stream is inherently
        // serialized on the socket anyway.
        let mut upload: Option<ActiveUpload> = None;
        // The download being streamed, pumped one chunk per loop turn below
        // the kill and event branches, so a kick never waits on it.
        let mut download: Option<DownloadPump> = None;
        let mut rate = RateLimits::new();
        // `session_ttl_secs` is the idle session lifetime: every inbound
        // frame (the stock client pings every 30 s) pushes this out.
        let idle_timeout = self.ctx.auth.session_ttl().max(MIN_IDLE_TIMEOUT);
        let mut idle_deadline = tokio::time::Instant::now() + idle_timeout;
        // Fixed when a fragment group opens, so neither trickled fragments
        // nor outbound traffic can extend it.
        let mut reassembly_deadline: Option<tokio::time::Instant> = None;

        enum Next {
            Killed(Option<String>),
            Event(Outbound),
            Frame(Option<Result<KdxFrame, ProtocolError>>),
            ReassemblyTimedOut,
            IdleTimedOut,
            Download(Box<Pulled>),
        }

        loop {
            let next = {
                // Over its inbound budget, the peer is simply read more
                // slowly; kills and events keep flowing meanwhile.
                let throttled_until = rate.inbound.ready_at();
                let framed = &mut self.framed;
                tokio::select! {
                    biased;
                    reason = kill.fired() => Next::Killed(reason),
                    // Senders never all drop while we hold outbound_tx.
                    event = outbound_rx.recv() => Next::Event(event.expect("outbound channel open")),
                    _ = sleep_until_opt(reassembly_deadline) => Next::ReassemblyTimedOut,
                    _ = tokio::time::sleep_until(idle_deadline) => Next::IdleTimedOut,
                    next = async {
                        if let Some(at) = throttled_until {
                            tokio::time::sleep_until(at).await;
                        }
                        framed.next().await
                    } => Next::Frame(next),
                    pulled = next_download(&mut download) => Next::Download(Box::new(pulled)),
                }
            };

            let frame_or_eof = match next {
                Next::Killed(reason) => {
                    // Kicked, banned, or the server is shutting down: flush
                    // what's already queued (e.g. the shutdown notice), send
                    // the reason, then close so the cleanup runs.
                    debug!("disconnected by server (admin action)");
                    self.farewell(outbound_rx, reason).await;
                    break Ok(());
                }
                Next::Event(event) => {
                    // An event too big for any client to reassemble is
                    // dropped, never fatal.
                    if event.payload.len() > MAX_REASSEMBLED_PAYLOAD {
                        warn!(
                            packet_type = ?event.packet_type,
                            len = event.payload.len(),
                            "dropping oversized outbound event"
                        );
                        continue;
                    }
                    // A `Disconnect` event closes the connection once sent.
                    let closing = event.packet_type == PacketType::Disconnect;
                    self.send(event.packet_type, event.flags, event.payload).await?;
                    if closing {
                        debug!("disconnected by server");
                        break Ok(());
                    }
                    continue;
                }
                Next::ReassemblyTimedOut => {
                    self.reassembler.abort();
                    break Err(ConnectionError::ReassemblyTimeout);
                }
                Next::IdleTimedOut => {
                    debug!("idle timeout");
                    self.farewell(outbound_rx, Some("idle timeout".into())).await;
                    break Err(ConnectionError::IdleTimeout);
                }
                Next::Download(pulled) => {
                    let (stream, chunk) = *pulled;
                    self.pump_download(&mut download, stream, chunk?).await?;
                    continue;
                }
                Next::Frame(item) => item,
            };

            let Some(frame) = frame_or_eof.transpose()? else {
                break Ok(()); // clean EOF
            };

            // Any inbound frame is activity.
            idle_deadline = tokio::time::Instant::now() + idle_timeout;
            // Everything but the data of an accepted upload spends inbound
            // budget.
            if !(frame.header.packet_type == PacketType::FileTransferData && upload.is_some()) {
                rate.inbound.allow();
            }

            let cap = reassembly_cap(frame.header.packet_type);
            let pushed = self.reassembler.push(frame, cap)?;
            if !self.reassembler.is_reassembling() {
                reassembly_deadline = None;
            } else if reassembly_deadline.is_none() {
                reassembly_deadline = Some(tokio::time::Instant::now() + REASSEMBLY_TIMEOUT);
            }
            let Some(frame) = pushed else {
                continue; // mid-group fragment
            };

            match frame.header.packet_type {
                PacketType::Ping => {
                    let session_id = self.session.as_ref().expect("authed").id;
                    self.ctx.presence.touch(session_id);
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
                    let checked = crate::limits::check_len(
                        "name",
                        &req.name,
                        crate::limits::MAX_NICK_LEN,
                    )
                    .and_then(|()| {
                        crate::limits::check_len(
                            "description",
                            &req.description,
                            crate::limits::MAX_DESCRIPTION_LEN,
                        )
                    });
                    if let Err(message) = checked {
                        self.send_error(&message).await?;
                        continue;
                    }
                    // Every change is broadcast to every user online.
                    if !rate.identity.allow() {
                        self.send_error(SLOW_DOWN).await?;
                        continue;
                    }
                    self.ctx.presence.set_identity(session_id, req.name, req.description).await;
                }
                PacketType::PresenceListRequest => {
                    PresenceListRequest::decode(&frame.payload)?;
                    let privs = self.session.as_ref().expect("authed").privileges;
                    let mut users = self.ctx.presence.list().await;
                    // Peer addresses are only for those who may act on them.
                    if !privs.contains(Privileges::USER_KICK) {
                        users.iter_mut().for_each(crate::presence::redact_address);
                    }
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
                    let privs = self.session.as_ref().expect("authed").privileges;
                    match self.ctx.presence.get(&request.username).await {
                        Some(mut entry) => {
                            if !privs.contains(Privileges::USER_KICK) {
                                crate::presence::redact_address(&mut entry);
                            }
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
                    let checked = crate::limits::check_len(
                        "recipient",
                        &send.to,
                        crate::limits::MAX_USERNAME_LEN,
                    )
                    .and_then(|()| {
                        crate::limits::check_len(
                            "message",
                            &send.text,
                            crate::limits::MAX_CHAT_TEXT_LEN,
                        )
                    });
                    if let Err(message) = checked {
                        self.send_error(&message).await?;
                        continue;
                    }
                    if !rate.private.allow() {
                        self.send_error(SLOW_DOWN).await?;
                        continue;
                    }
                    self.ctx.presence.touch(session.id);
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
                    // Each join is announced to the room.
                    if !rate.join.allow() {
                        self.send_error(SLOW_DOWN).await?;
                        continue;
                    }
                    if !joined.contains_key(&join.room)
                        && joined.len() >= crate::limits::MAX_JOINED_ROOMS_PER_CONNECTION
                    {
                        self.send_error("you are in too many chat rooms").await?;
                        continue;
                    }
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
                    if let Err(message) = crate::limits::check_len(
                        "recipient",
                        &invite.to,
                        crate::limits::MAX_USERNAME_LEN,
                    ) {
                        self.send_error(&message).await?;
                        continue;
                    }
                    if joined.len() >= crate::limits::MAX_JOINED_ROOMS_PER_CONNECTION {
                        self.send_error("you are in too many chat rooms").await?;
                        continue;
                    }
                    // Each invite creates a room and pings another user.
                    if !rate.invite.allow() {
                        self.send_error(SLOW_DOWN).await?;
                        continue;
                    }
                    // A UUID-named room under the private prefix can't collide
                    // with a user-typed public room name; RoomManager admits
                    // only the inviter and invitee, and evicts the room once
                    // its last member leaves.
                    let room_id = format!("{}{}", crate::chat::PRIVATE_ROOM_PREFIX, Uuid::new_v4());
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
                    self.ctx.rooms.invite(&room_id, &invite.to);

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
                    if let Err(message) = crate::limits::check_len(
                        "message",
                        &send.text,
                        crate::limits::MAX_CHAT_TEXT_LEN,
                    ) {
                        self.send_error(&message).await?;
                        continue;
                    }
                    self.ctx.presence.touch(session.id);
                    match joined.get(&send.room) {
                        Some(handle) => {
                            // Per connection, not per membership, so leaving
                            // and rejoining doesn't refill it.
                            if !rate.chat.allow() {
                                self.send(
                                    PacketType::Warning,
                                    PacketFlags::SYSTEM_MESSAGE,
                                    Bytes::from_static(b"flood protection: slow down"),
                                )
                                .await?;
                                continue;
                            }
                            let _ = handle
                                .send(RoomCommand::Message {
                                    session_id: session.id,
                                    flags: send.flags & kdx_protocol::messages::CHAT_ACTION,
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
                    if let Err(message) = crate::limits::check_len(
                        "topic",
                        &topic.topic,
                        crate::limits::MAX_TOPIC_LEN,
                    ) {
                        self.send_error(&message).await?;
                        continue;
                    }
                    if !rate.room_admin.allow() {
                        self.send_error(SLOW_DOWN).await?;
                        continue;
                    }
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
                    if !rate.room_admin.allow() {
                        self.send_error(SLOW_DOWN).await?;
                        continue;
                    }
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
                    self.reply_file_list(&request.path, &session).await?;
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
                        Err(e) => self.send_error(&e.client_message()).await?,
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
                            &session,
                        )
                        .await
                    {
                        Ok(_) => self.reply_file_list(&req.path, &session).await?,
                        Err(e) => self.send_error(&e.client_message()).await?,
                    }
                }
                PacketType::FileDelete => {
                    let req = FileDelete::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    // Folder deletes also need FILE_MANAGE_TREE; the tree
                    // checks that, since only it knows the node's kind.
                    if !session.privileges.contains(Privileges::FILE_DELETE) {
                        self.send_error("missing FILE_DELETE privilege").await?;
                        continue;
                    }
                    match self.ctx.tree.delete(&req.path, &session).await {
                        Ok(_) => {
                            // Re-list the deleted node's parent directory.
                            let parent = parent_path(&req.path);
                            self.reply_file_list(&parent, &session).await?;
                        }
                        Err(e) => self.send_error(&e.client_message()).await?,
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
                        Err(e) => self.send_error(&e.client_message()).await?,
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
                        Err(e) => self.send_error(&e.client_message()).await?,
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
                    let max_query = crate::limits::MAX_SEARCH_QUERY_LEN;
                    if let Err(msg) = crate::limits::check_len("search query", &req.query, max_query) {
                        self.send_error(&msg).await?;
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
                        Err(e) => self.send_error(&e.client_message()).await?,
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
                        Ok((stream, accept)) => {
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
                            download = Some(DownloadPump::new(stream));
                        }
                        Err(e) => {
                            if e.is_internal() {
                                warn!(error = %e, "download could not start");
                            }
                            self.send_error(&e.client_message()).await?;
                        }
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
                    if let Err(message) = crate::limits::check_len(
                        "path",
                        &request.path,
                        crate::limits::MAX_PATH_LEN,
                    )
                    .and_then(|()| {
                        crate::limits::check_len(
                            "file name",
                            &request.name,
                            crate::limits::MAX_FILE_NAME_LEN,
                        )
                    }) {
                        self.send_error(&message).await?;
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
                            let transfer_id = accept.transfer_id;
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
                            if !active.is_complete() {
                                upload = Some(active);
                                continue;
                            }
                            // Nothing left for the client to send (an empty
                            // file, or a resume of an upload whose chunks
                            // all arrived): verify and file it now.
                            let (status, message) =
                                match self.ctx.transfers.finish(&self.ctx.tree, active).await {
                                    Ok(()) => (TRANSFER_VERIFIED, "verified".to_string()),
                                    Err(TransferError::FileHashMismatch) => {
                                        (TRANSFER_HASH_MISMATCH, "file hash mismatch".to_string())
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "upload could not be filed");
                                        (
                                            kdx_protocol::messages::TRANSFER_ABORTED,
                                            format!("upload not filed: {}", e.client_message()),
                                        )
                                    }
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
                        Err(e) => {
                            if e.is_internal() {
                                warn!(error = %e, "upload could not start");
                            }
                            self.send_error(&e.client_message()).await?;
                        }
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
                                    // Name taken / folder gone meanwhile, or
                                    // a server failure: the upload has been
                                    // discarded; tell the client, stay up.
                                    Err(e) => {
                                        warn!(error = %e, "upload could not be filed");
                                        (
                                            kdx_protocol::messages::TRANSFER_ABORTED,
                                            format!("upload not filed: {}", e.client_message()),
                                        )
                                    }
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
                        // client resend.
                        Err(
                            e @ (TransferError::ChunkHashMismatch
                            | TransferError::BadChunkIndex
                            | TransferError::BadChunkLength),
                        ) => self.send_error(&e.to_string()).await?,
                        // A server-side failure (disk, database): end this
                        // attempt but keep the upload resumable.
                        Err(e) => {
                            warn!(error = %e, "upload chunk could not be stored");
                            let failed = upload.take().expect("active upload present");
                            let transfer_id = *failed.id().as_bytes();
                            self.ctx.transfers.release(failed).await;
                            let end = TransferEnd {
                                transfer_id,
                                status: kdx_protocol::messages::TRANSFER_ABORTED,
                                message: "upload interrupted by a server error; resume later"
                                    .into(),
                            };
                            self.send(
                                PacketType::FileTransferEnd,
                                PacketFlags::TRANSFER_END,
                                end.encode(),
                            )
                            .await?;
                        }
                    }
                }
                PacketType::FileTransferEnd => {
                    // The client is abandoning (or pausing) its upload: free
                    // the slot, keep the partial state for a later resume.
                    let end = TransferEnd::decode(&frame.payload)?;
                    match upload.take() {
                        Some(active) if end.transfer_id == *active.id().as_bytes() => {
                            debug!(status = end.status, "client ended its upload early");
                            self.ctx.transfers.release(active).await;
                        }
                        other => {
                            upload = other;
                            self.send_error("no matching active transfer").await?;
                        }
                    }
                }
                PacketType::RoleListRequest => {
                    RoleListRequest::decode(&frame.payload)?;
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
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::RoleCreate => {
                    let create = RoleCreate::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::USER_ADMIN) {
                        self.send_error("missing USER_ADMIN privilege").await?;
                        continue;
                    }
                    let admin_name = session.username.clone();
                    let color = (!create.color.is_empty()).then_some(create.color.as_str());
                    let result = self
                        .ctx
                        .roles
                        .create(
                            &create.name,
                            Privileges::from_bits_truncate(create.privileges),
                            create.rank,
                            color,
                        )
                        .await;
                    match result {
                        Ok(_) => {
                            let _ = self
                                .ctx
                                .history
                                .record(unix_now(), Some(&admin_name), "role_created", &create.name)
                                .await;
                            self.reply_role_list().await?
                        }
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::RoleUpdate => {
                    let update = RoleUpdate::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::USER_ADMIN) {
                        self.send_error("missing USER_ADMIN privilege").await?;
                        continue;
                    }
                    let admin_name = session.username.clone();
                    let color = (!update.color.is_empty()).then_some(update.color.as_str());
                    let result = self
                        .ctx
                        .roles
                        .update(
                            Uuid::from_bytes(update.id),
                            &update.name,
                            Privileges::from_bits_truncate(update.privileges),
                            update.rank,
                            color,
                        )
                        .await;
                    match result {
                        Ok(()) => {
                            let _ = self
                                .ctx
                                .history
                                .record(unix_now(), Some(&admin_name), "role_updated", &update.name)
                                .await;
                            self.reply_role_list().await?
                        }
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::RoleDelete => {
                    let delete = RoleDelete::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::USER_ADMIN) {
                        self.send_error("missing USER_ADMIN privilege").await?;
                        continue;
                    }
                    let admin_name = session.username.clone();
                    let role_id = Uuid::from_bytes(delete.id);
                    match self.ctx.roles.delete(role_id).await {
                        Ok(()) => {
                            let _ = self
                                .ctx
                                .history
                                .record(unix_now(), Some(&admin_name), "role_deleted", &role_id.to_string())
                                .await;
                            self.reply_role_list().await?
                        }
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::RoleAssign => {
                    let assign = RoleAssign::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::USER_ADMIN) {
                        self.send_error("missing USER_ADMIN privilege").await?;
                        continue;
                    }
                    let admin_name = session.username.clone();
                    match self.ctx.auth.account_id(&assign.username).await? {
                        Some(account_id) => {
                            match self
                                .ctx
                                .roles
                                .assign(&account_id, Uuid::from_bytes(assign.role_id))
                                .await
                            {
                                Ok(()) => {
                                    let _ = self
                                        .ctx
                                        .history
                                        .record(
                                            unix_now(),
                                            Some(&admin_name),
                                            "role_assigned",
                                            &format!("target={}", assign.username),
                                        )
                                        .await;
                                    self.reply_role_list().await?
                                }
                                Err(e) => self.send_error(&e.to_string()).await?,
                            }
                        }
                        None => self.send_error("no such account").await?,
                    }
                }
                PacketType::RoleUnassign => {
                    let unassign = RoleUnassign::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::USER_ADMIN) {
                        self.send_error("missing USER_ADMIN privilege").await?;
                        continue;
                    }
                    let admin_name = session.username.clone();
                    match self.ctx.auth.account_id(&unassign.username).await? {
                        Some(account_id) => {
                            match self
                                .ctx
                                .roles
                                .unassign(&account_id, Uuid::from_bytes(unassign.role_id))
                                .await
                            {
                                Ok(()) => {
                                    let _ = self
                                        .ctx
                                        .history
                                        .record(
                                            unix_now(),
                                            Some(&admin_name),
                                            "role_unassigned",
                                            &format!("target={}", unassign.username),
                                        )
                                        .await;
                                    self.reply_role_list().await?
                                }
                                Err(e) => self.send_error(&e.to_string()).await?,
                            }
                        }
                        None => self.send_error("no such account").await?,
                    }
                }
                PacketType::AccountRolesRequest => {
                    let request = AccountRolesRequest::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::USER_ADMIN) {
                        self.send_error("missing USER_ADMIN privilege").await?;
                        continue;
                    }
                    match self.ctx.auth.account_id(&request.username).await? {
                        Some(account_id) => match self.ctx.roles.for_account(&account_id).await {
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
                            Err(e) => self.send_error(&e.to_string()).await?,
                        },
                        None => self.send_error("no such account").await?,
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
                    let (admin_name, admin_class, privs) = {
                        let s = self.session.as_ref().expect("authed");
                        (s.username.clone(), s.class as u8, s.privileges)
                    };
                    if !privs.contains(Privileges::USER_ADMIN) {
                        self.send_error("missing USER_ADMIN privilege").await?;
                        continue;
                    }
                    // Can't mint an account outranking yourself.
                    if create.base_class > admin_class {
                        self.send_error("cannot create an account above your own class")
                            .await?;
                        continue;
                    }
                    if create.username.is_empty() || create.password.is_empty() {
                        self.send_error("username and password are required").await?;
                        continue;
                    }
                    match self
                        .ctx
                        .auth
                        .create_account(
                            &create.username,
                            &create.password,
                            create.base_class as i64,
                            create.granted as i64,
                            create.revoked as i64,
                        )
                        .await
                    {
                        Ok(()) => {
                            let _ = self
                                .ctx
                                .history
                                .record(unix_now(), Some(&admin_name), "account_created", &create.username)
                                .await;
                            self.reply_account_list().await?
                        }
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::AccountUpdate => {
                    let update = AccountUpdate::decode(&frame.payload)?;
                    let (admin_name, admin_class, privs) = {
                        let s = self.session.as_ref().expect("authed");
                        (s.username.clone(), s.class as u8, s.privileges)
                    };
                    if !privs.contains(Privileges::USER_ADMIN) {
                        self.send_error("missing USER_ADMIN privilege").await?;
                        continue;
                    }
                    if update.base_class > admin_class {
                        self.send_error("cannot raise an account above your own class")
                            .await?;
                        continue;
                    }
                    match self
                        .ctx
                        .auth
                        .update_account(
                            &update.username,
                            update.base_class as i64,
                            update.granted as i64,
                            update.revoked as i64,
                        )
                        .await
                    {
                        Ok(()) => {
                            let _ = self
                                .ctx
                                .history
                                .record(unix_now(), Some(&admin_name), "account_updated", &update.username)
                                .await;
                            self.reply_account_list().await?
                        }
                        Err(e) => self.send_error(&e.to_string()).await?,
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
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::IpRuleListRequest => {
                    IpRuleListRequest::decode(&frame.payload)?;
                    let privs = self.session.as_ref().expect("authed").privileges;
                    if !privs.contains(Privileges::SERVER_ADMIN) {
                        self.send_error("missing SERVER_ADMIN privilege").await?;
                        continue;
                    }
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
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::IpRuleCreate => {
                    let create = IpRuleCreate::decode(&frame.payload)?;
                    let session = self.session.as_ref().expect("authed").clone();
                    if !session.privileges.contains(Privileges::SERVER_ADMIN) {
                        self.send_error("missing SERVER_ADMIN privilege").await?;
                        continue;
                    }
                    let admin_name = session.username.clone();
                    let action = match create.action.as_str() {
                        "allow" => crate::ip_rules::Action::Allow,
                        "deny" => crate::ip_rules::Action::Deny,
                        other => {
                            self.send_error(&format!("invalid action: {other}")).await?;
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
                        Err(e) => self.send_error(&e.to_string()).await?,
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
                            let _ = self
                                .ctx
                                .history
                                .record(unix_now(), Some(&admin_name), "ip_rule_deleted", &del.id)
                                .await;
                            self.reply_ip_rule_list().await?
                        }
                        Err(e) => self.send_error(&e.to_string()).await?,
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
                    if update.name.trim().is_empty() {
                        self.send_error("server name is required").await?;
                        continue;
                    }
                    let new_name = update.name.clone();
                    self.ctx
                        .settings
                        .update(update.name, update.description, update.greeting, update.max_users)
                        .await;
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
                    if let Err(message) = crate::limits::check_len(
                        "shutdown message",
                        &shutdown.message,
                        crate::limits::MAX_BROADCAST_LEN,
                    ) {
                        self.send_error(&message).await?;
                        continue;
                    }
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
                    // included) close individually as their kill signal fires
                    // on the next select iteration. `notify_one` stores a
                    // permit, so the stop isn't lost if the accept loop isn't
                    // parked in `notified()` at this instant.
                    self.ctx.shutdown.notify_one();
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
                        Err(e) => self.send_error(&e.to_string()).await?,
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
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::NewsPostCreate => {
                    let post = NewsPostCreate::decode(&frame.payload)?;
                    let (author, my_class) = {
                        let s = self.session.as_ref().expect("authed");
                        (s.username.clone(), s.class as u8)
                    };
                    let group_id = Uuid::from_bytes(post.newsgroup_id);
                    let group = match self.ctx.news.group(group_id).await {
                        Ok(g) => g,
                        Err(e) => {
                            self.send_error(&e.to_string()).await?;
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
                    // All-zero parent id means "thread root".
                    let parent = (post.parent_id != [0u8; 16]).then(|| Uuid::from_bytes(post.parent_id));
                    match self
                        .ctx
                        .news
                        .create_post(group_id, parent, &author, &post.subject, &post.body, unix_now())
                        .await
                    {
                        Ok(_) => self.reply_thread_list(group_id).await?,
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::NewsPostDelete => {
                    let del = NewsPostDelete::decode(&frame.payload)?;
                    let (username, privs) = {
                        let s = self.session.as_ref().expect("authed");
                        (s.username.clone(), s.privileges)
                    };
                    let post_id = Uuid::from_bytes(del.post_id);
                    match self.ctx.news.post(post_id).await {
                        Ok(post) => {
                            // Authors may delete their own posts; USER_ADMIN may
                            // delete anyone's.
                            if post.author != username && !privs.contains(Privileges::USER_ADMIN) {
                                self.send_error("you can only delete your own posts").await?;
                                continue;
                            }
                            match self.ctx.news.delete_post(post_id).await {
                                Ok(()) => self.reply_thread_list(post.newsgroup_id).await?,
                                Err(e) => self.send_error(&e.to_string()).await?,
                            }
                        }
                        Err(e) => self.send_error(&e.to_string()).await?,
                    }
                }
                PacketType::AdminDisconnect => {
                    let req = AdminDisconnect::decode(&frame.payload)?;
                    // Pull what we need as owned values so we don't hold a
                    // borrow of `self.session` across the `&mut self` sends.
                    let (admin_name, admin_class, privs) = {
                        let s = self.session.as_ref().expect("authed");
                        (s.username.clone(), s.class as u8, s.privileges)
                    };
                    // Kicking always needs USER_KICK; a ban additionally needs
                    // USER_BAN.
                    if !privs.contains(Privileges::USER_KICK) {
                        self.send_error("missing USER_KICK privilege").await?;
                        continue;
                    }
                    if req.ban_secs > 0 && !privs.contains(Privileges::USER_BAN) {
                        self.send_error("missing USER_BAN privilege").await?;
                        continue;
                    }
                    if req.username == admin_name {
                        self.send_error("cannot disconnect yourself").await?;
                        continue;
                    }
                    // Rank guard: never act on a user who outranks you. Prefer
                    // the live (effective) class; fall back to the stored
                    // account class so an offline ban target is still checked.
                    let target_class = match self.ctx.presence.get(&req.username).await {
                        Some(entry) => Some(entry.class),
                        None => self
                            .ctx
                            .auth
                            .account_class(&req.username)
                            .await?
                            .map(|c| c as u8),
                    };
                    if target_class.is_some_and(|tc| tc > admin_class) {
                        self.send_error("cannot disconnect a higher-class user").await?;
                        continue;
                    }
                    // Record the ban before kicking, so a racing reconnect is
                    // already refused by the login path.
                    if req.ban_secs > 0 {
                        match self.ctx.auth.account_id(&req.username).await? {
                            Some(account_id) => {
                                let until = unix_now() as i64 + req.ban_secs as i64;
                                self.ctx
                                    .auth
                                    .set_ban(&account_id, until, &req.reason, &admin_name)
                                    .await?;
                            }
                            None => {
                                self.send_error("no such account").await?;
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
                            format!(
                                "banned {} — {} session(s) dropped",
                                req.username, reached
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
        }
    }

    /// Parting words of a server-initiated close: flush events already
    /// queued (e.g. a shutdown notice), then a `Disconnect` carrying
    /// `reason`. Best effort, bounded by `FAREWELL_TIMEOUT` so a peer that
    /// stopped reading can't hold the close up.
    async fn farewell(&mut self, outbound_rx: &mut mpsc::Receiver<Outbound>, reason: Option<String>) {
        let flush = async {
            while let Ok(event) = outbound_rx.try_recv() {
                if event.packet_type == PacketType::Disconnect
                    || event.payload.len() > MAX_REASSEMBLED_PAYLOAD
                {
                    continue;
                }
                self.send(event.packet_type, event.flags, event.payload).await?;
            }
            if let Some(reason) = reason {
                self.send(PacketType::Disconnect, PacketFlags::empty(), Bytes::from(reason))
                    .await?;
            }
            Ok::<(), ConnectionError>(())
        };
        match timeout(FAREWELL_TIMEOUT, flush).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => debug!(error = %e, "farewell not delivered"),
            Err(_) => debug!("farewell timed out"),
        }
    }

    /// Handle one pulled download chunk: send it and queue the next pull, or
    /// end the transfer once the stream is exhausted.
    async fn pump_download(
        &mut self,
        download: &mut Option<DownloadPump>,
        stream: ActiveDownload,
        chunk: Option<DownloadChunk>,
    ) -> Result<(), ConnectionError> {
        let transfer_id = *stream.id().as_bytes();
        match chunk {
            Some(chunk) => {
                *download = Some(DownloadPump::new(stream));
                let data = TransferData {
                    transfer_id,
                    chunk_index: chunk.index,
                    chunk_hash: chunk.hash,
                    data: chunk.data,
                };
                self.send_fragmented(PacketType::FileTransferData, PacketFlags::empty(), data.encode())
                    .await
            }
            None => {
                *download = None;
                let end = TransferEnd {
                    transfer_id,
                    status: TRANSFER_VERIFIED,
                    message: "verified".into(),
                };
                self.send(PacketType::FileTransferEnd, PacketFlags::TRANSFER_END, end.encode())
                    .await
            }
        }
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
        // Bounded queue to the history writer task: never blocks, drops
        // (and counts) when full; actor/detail are truncated by the log.
        self.ctx.history.record_detached(unix_now(), actor.as_deref(), action, &detail);
    }

    async fn send_error(&mut self, message: &str) -> Result<(), ConnectionError> {
        self.send(
            PacketType::Error,
            PacketFlags::SYSTEM_MESSAGE,
            Bytes::copy_from_slice(message.as_bytes()),
        )
        .await
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
            Err(e) => self.send_error(&e.to_string()).await?,
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
            Err(e) => self.send_error(&e.to_string()).await?,
        }
        Ok(())
    }

    /// List `path` for `session` and send it as a `FileListResponse` — the
    /// reply to `FileListRequest` and to a successful tree mutation so the
    /// Files window re-renders. At most `limits::MAX_FILE_LIST_ENTRIES`
    /// entries, and no more than half the reassembly cap in total, so the
    /// reply always fits its `u16` count and one logical payload.
    async fn reply_file_list(&mut self, path: &str, session: &Session) -> Result<(), ConnectionError> {
        match self.ctx.tree.list(path, session).await {
            Ok(entries) => {
                let total = entries.len();
                let mut budget = MAX_REASSEMBLED_PAYLOAD / 2;
                let max_entries = crate::limits::MAX_FILE_LIST_ENTRIES;
                let mut wire = Vec::with_capacity(total.min(max_entries));
                for e in entries {
                    // name (u16 length + bytes) + kind + size
                    let cost = 2 + e.name.len() + 1 + 8;
                    if wire.len() == max_entries || cost > budget {
                        break;
                    }
                    if e.name.len() > u16::MAX as usize {
                        continue; // unencodable; only a pre-validation row could be this long
                    }
                    budget -= cost;
                    wire.push(FileEntry {
                        name: e.name,
                        kind: e.kind.as_u8(),
                        size: e.size,
                    });
                }
                if wire.len() < total {
                    warn!(path, total, sent = wire.len(), "file listing truncated");
                }
                let response = FileListResponse {
                    path: path.to_owned(),
                    entries: wire,
                };
                self.send(
                    PacketType::FileListResponse,
                    PacketFlags::empty(),
                    response.encode(),
                )
                .await?;
            }
            Err(e) => self.send_error(&e.client_message()).await?,
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
            Err(e) => self.send_error(&e.to_string()).await?,
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
            Err(e) => self.send_error(&e.to_string()).await?,
        }
        Ok(())
    }

    /// Send every post in a newsgroup — the reply to `NewsThreadListRequest`
    /// and to a successful post/delete, so the News window re-renders from one
    /// shape. The caller has already passed the read-class check.
    async fn reply_thread_list(&mut self, group_id: Uuid) -> Result<(), ConnectionError> {
        match self.ctx.news.posts(group_id).await {
            Ok(posts) => {
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
            }
            Err(e) => self.send_error(&e.to_string()).await?,
        }
        Ok(())
    }

    /// Same as [`Connection::send`] (which fragments on its own); kept for
    /// the download pump's call site.
    async fn send_fragmented(
        &mut self,
        packet_type: PacketType,
        flags: PacketFlags,
        payload: Bytes,
    ) -> Result<(), ConnectionError> {
        self.send(packet_type, flags, payload).await
    }

    /// Send one logical message, fragmenting it across frames when it's over
    /// the frame cap. A payload over `MAX_REASSEMBLED_PAYLOAD` (more than any
    /// client reassembles) is answered with a short `Error` reply instead, so
    /// handlers can keep using `?`: only a failed or timed-out write
    /// (`WriteTimeout`) is an error.
    async fn send(
        &mut self,
        packet_type: PacketType,
        flags: PacketFlags,
        payload: Bytes,
    ) -> Result<(), ConnectionError> {
        match self.write_message(packet_type, flags, payload).await {
            Err(ConnectionError::MessageTooLarge { len }) => {
                warn!(?packet_type, len, "outbound message too large; sending an error instead");
                self.write_message(
                    PacketType::Error,
                    PacketFlags::SYSTEM_MESSAGE,
                    Bytes::from_static(b"reply too large to send"),
                )
                .await
            }
            other => other,
        }
    }

    /// Frame `payload` (fragmenting as needed) and write it within
    /// `WRITE_TIMEOUT`. Refuses payloads over `MAX_REASSEMBLED_PAYLOAD` with
    /// `MessageTooLarge` before writing anything.
    async fn write_message(
        &mut self,
        packet_type: PacketType,
        flags: PacketFlags,
        payload: Bytes,
    ) -> Result<(), ConnectionError> {
        if payload.len() > MAX_REASSEMBLED_PAYLOAD {
            return Err(ConnectionError::MessageTooLarge { len: payload.len() });
        }
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
        let framed = &mut self.framed;
        let write = async move {
            for frame in frames {
                framed.feed(frame).await?;
            }
            framed.flush().await
        };
        timeout(WRITE_TIMEOUT, write)
            .await
            .map_err(|_| ConnectionError::WriteTimeout)??;
        Ok(())
    }
}

/// Unregisters an authenticated session — leaves its chat rooms and the
/// presence roster, ends the auth session — however the dispatch loop ends.
/// The normal path awaits [`SessionGuard::cleanup`]; if the task panics or
/// is dropped mid-loop, `Drop` hands the same cleanup to a fresh task.
struct SessionGuard {
    ctx: Arc<ServerCtx>,
    session_id: Uuid,
    /// Rooms this connection is in, by name.
    joined: HashMap<String, mpsc::Sender<RoomCommand>>,
    armed: bool,
}

impl SessionGuard {
    async fn cleanup(&mut self) {
        let rooms: Vec<String> = self.joined.keys().cloned().collect();
        unregister_session(&self.ctx, self.session_id, &rooms).await;
        self.joined.clear();
        self.armed = false;
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Stop the session validating right away, even if no runtime is left
        // to run the rest.
        self.ctx.auth.end_session(self.session_id);
        let ctx = self.ctx.clone();
        let session_id = self.session_id;
        let rooms: Vec<String> = self.joined.drain().map(|(room, _)| room).collect();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move { unregister_session(&ctx, session_id, &rooms).await });
        }
    }
}

async fn unregister_session(ctx: &ServerCtx, session_id: Uuid, rooms: &[String]) {
    for room in rooms {
        ctx.rooms.leave(room, session_id).await;
        debug!(room, "left on disconnect");
    }
    ctx.presence.leave(session_id).await;
    ctx.auth.end_session(session_id);
}

/// Per-connection request budgets. They live as long as the connection — not
/// a room membership — so leaving and rejoining a room can't reset them.
struct RateLimits {
    /// Every inbound frame except accepted upload data. Over budget, the
    /// connection is simply read more slowly.
    inbound: FloodGate,
    /// Room chat lines (answered with the "flood protection" warning).
    chat: FloodGate,
    /// Private messages.
    private: FloodGate,
    /// `SetIdentity`: each change is broadcast to every user online.
    identity: FloodGate,
    /// `ChatJoin`: each join is announced to the room.
    join: FloodGate,
    /// `ChatInvite`: each creates a room and pings another user.
    invite: FloodGate,
    /// Topic and room-flag changes, announced to the room.
    room_admin: FloodGate,
}

impl RateLimits {
    fn new() -> Self {
        Self {
            inbound: FloodGate::new(50, 20.0),
            chat: FloodGate::new(5, 1.0),
            private: FloodGate::new(10, 3.0),
            identity: FloodGate::new(3, 0.2),
            join: FloodGate::new(10, 2.0),
            invite: FloodGate::new(3, 0.1),
            room_admin: FloodGate::new(5, 1.0),
        }
    }
}

/// What one pull of a download stream yields: the stream back, plus the
/// next chunk (`None` once complete).
type Pulled = (ActiveDownload, Result<Option<DownloadChunk>, TransferError>);

/// A download being streamed to the client. The pending pull owns the
/// stream and persists across dispatch turns, so a throttle sleep or disk
/// read in progress is never lost when another select branch wins.
struct DownloadPump {
    pull: std::pin::Pin<Box<dyn std::future::Future<Output = Pulled> + Send>>,
}

impl DownloadPump {
    fn new(mut stream: ActiveDownload) -> Self {
        Self {
            pull: Box::pin(async move {
                let chunk = stream.next_chunk().await;
                (stream, chunk)
            }),
        }
    }
}

/// The next pulled chunk of the active download; pending forever if there
/// is none. Cancel-safe: the pull itself lives in the `DownloadPump`.
async fn next_download(download: &mut Option<DownloadPump>) -> Pulled {
    match download {
        Some(pump) => pump.pull.as_mut().await,
        None => std::future::pending().await,
    }
}

async fn sleep_until_opt(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Largest reassembled payload accepted for `packet_type`: upload data gets
/// the full cap, a transfer request room for its resume bitmap, and every
/// other message the control-message cap.
fn reassembly_cap(packet_type: PacketType) -> usize {
    match packet_type {
        PacketType::FileTransferData => MAX_REASSEMBLED_PAYLOAD,
        PacketType::FileTransferStart => MAX_TRANSFER_START_PAYLOAD,
        _ => MAX_CONTROL_PAYLOAD,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Privileges;
    use kdx_crypto::{client_response, hash_password};
    use kdx_protocol::PacketHeader;
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

    /// Core loop: framing, cleanup, kill signal, timeouts, rate limits,
    /// room caps and address redaction.
    mod core_loop {
        use super::*;
        use kdx_protocol::messages::{ChatUserList, PresenceChange, DIRECTION_DOWNLOAD};
        use sha2::Digest;
        use tokio::io::DuplexStream;
        use tokio::task::JoinHandle;
        use tokio::time::Instant;

        type Client = Framed<DuplexStream, KdxCodec>;

        /// Connect over a `capacity`-byte duplex pipe presenting `peer` as
        /// the network address, and log in as `username`.
        async fn connect_as(
            ctx: &Arc<ServerCtx>,
            capacity: usize,
            peer: &str,
            username: &str,
        ) -> (Client, u32, JoinHandle<Result<(), ConnectionError>>, AuthResult) {
            let (client, server) = tokio::io::duplex(capacity);
            let conn = tokio::spawn(
                Connection::new_with_peer(server, ctx.clone(), peer.to_string()).run(),
            );
            let mut client = client_framed(client);
            let mut seq = 0;
            do_handshake(&mut client, &mut seq).await;
            let login = do_login(&mut client, &mut seq, username, "s3cret").await;
            assert!(login.success, "{}", login.message);
            (client, seq, conn, login)
        }

        /// Read frames until one whole logical message is reassembled.
        async fn recv_logical(client: &mut Client, reasm: &mut Reassembler) -> KdxFrame {
            loop {
                let frame = client.next().await.expect("stream open").expect("valid frame");
                if let Some(whole) = reasm.push(frame, MAX_REASSEMBLED_PAYLOAD).unwrap() {
                    return whole;
                }
            }
        }

        /// The next whole message of `packet_type`, skipping everything else.
        async fn recv_type(client: &mut Client, packet_type: PacketType) -> KdxFrame {
            let mut reasm = Reassembler::default();
            loop {
                let frame = recv_logical(client, &mut reasm).await;
                if frame.header.packet_type == packet_type {
                    return frame;
                }
            }
        }

        async fn request(client: &mut Client, seq: &mut u32, packet_type: PacketType, payload: Bytes) {
            client
                .send(client_frame(packet_type, bump(seq), payload))
                .await
                .unwrap();
        }

        async fn ping(client: &mut Client, seq: &mut u32) {
            request(client, seq, PacketType::Ping, Bytes::new()).await;
            recv_type(client, PacketType::Pong).await;
        }

        fn chat_join(room: &str) -> Bytes {
            ChatJoin { room: room.into() }.encode()
        }

        fn error_text(frame: &KdxFrame) -> String {
            assert_eq!(frame.header.packet_type, PacketType::Error);
            String::from_utf8_lossy(&frame.payload).into_owned()
        }

        #[tokio::test]
        async fn send_fragments_large_messages_and_refuses_oversized_ones() {
            let (ctx, _dir) = test_ctx().await;
            let (client, server) = tokio::io::duplex(64 * 1024);
            let mut conn = Connection::new(server, ctx);
            let mut client = client_framed(client);

            let big = Bytes::from(vec![7u8; 40 * 1024]);
            let (sent, got) = tokio::time::timeout(Duration::from_secs(10), async {
                tokio::join!(
                    conn.send(PacketType::Info, PacketFlags::SYSTEM_MESSAGE, big.clone()),
                    recv_type(&mut client, PacketType::Info)
                )
            })
            .await
            .expect("a 40 KiB message must arrive");
            sent.unwrap();
            assert_eq!(got.payload, big);

            // Beyond what any client reassembles: an Error reply instead,
            // and the connection carries on.
            let huge = Bytes::from(vec![0u8; MAX_REASSEMBLED_PAYLOAD + 1]);
            let mut reasm = Reassembler::default();
            let (sent, got) = tokio::join!(
                conn.send(PacketType::Info, PacketFlags::SYSTEM_MESSAGE, huge),
                recv_logical(&mut client, &mut reasm)
            );
            sent.unwrap();
            assert!(error_text(&got).contains("too large"));
        }

        #[tokio::test]
        async fn oversized_identity_and_chat_are_refused_and_peers_survive() {
            let (ctx, _dir) = test_ctx().await;
            let (mut a, mut a_seq, conn_a, _) = connect_as(&ctx, 64 * 1024, "unknown", "phraq").await;
            let (mut b, mut b_seq, conn_b, _) = connect_as(&ctx, 64 * 1024, "unknown", "phraq").await;
            request(&mut a, &mut a_seq, PacketType::ChatJoin, chat_join("lobby")).await;
            request(&mut b, &mut b_seq, PacketType::ChatJoin, chat_join("lobby")).await;
            ping(&mut a, &mut a_seq).await;
            ping(&mut b, &mut b_seq).await;

            // One maximal frame whose PresenceChange broadcast would not fit
            // in a frame.
            let identity = SetIdentity {
                name: "n".repeat(16_350),
                description: String::new(),
            };
            request(&mut a, &mut a_seq, PacketType::SetIdentity, identity.encode()).await;
            let err = recv_type(&mut a, PacketType::Error).await;
            assert!(error_text(&err).contains("name too long"));

            // One maximal frame whose ChatEvent would not fit in a frame.
            let line = ChatSend {
                room: "lobby".into(),
                flags: 0,
                text: "x".repeat(16_370),
            };
            request(&mut a, &mut a_seq, PacketType::ChatMessage, line.encode()).await;
            let err = recv_type(&mut a, PacketType::Error).await;
            assert!(error_text(&err).contains("message too long"));

            // Both connections are alive and still listed.
            ping(&mut b, &mut b_seq).await;
            ping(&mut a, &mut a_seq).await;
            assert_eq!(ctx.presence.list().await.len(), 2);

            for (client, seq) in [(&mut a, &mut a_seq), (&mut b, &mut b_seq)] {
                request(client, seq, PacketType::Disconnect, Bytes::new()).await;
            }
            conn_a.await.unwrap().unwrap();
            conn_b.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn presence_list_larger_than_a_frame_is_delivered() {
            let (ctx, _dir) = test_ctx().await;
            let mut keep = Vec::new();
            for i in 0..600 {
                let (tx, rx) = mpsc::channel(1);
                let kill = ctx
                    .presence
                    .join(
                        Uuid::new_v4(),
                        format!("ghost-user-number-{i:04}"),
                        1,
                        "10.0.0.1:1".into(),
                        false,
                        tx,
                    )
                    .await;
                keep.push((rx, kill));
            }
            let (mut client, mut seq, conn, _) = connect_as(&ctx, 64 * 1024, "unknown", "phraq").await;
            request(&mut client, &mut seq, PacketType::PresenceListRequest, PresenceListRequest.encode())
                .await;
            let frame = recv_type(&mut client, PacketType::PresenceListResponse).await;
            assert!(frame.payload.len() > kdx_protocol::DEFAULT_MAX_FRAME_PAYLOAD as usize);
            let list = PresenceListResponse::decode(&frame.payload).unwrap();
            assert_eq!(list.users.len(), 601);

            ping(&mut client, &mut seq).await;
            request(&mut client, &mut seq, PacketType::Disconnect, Bytes::new()).await;
            conn.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn malformed_packet_still_runs_session_cleanup() {
            let (ctx, _dir) = test_ctx().await;
            let (mut a, mut seq, conn, login) = connect_as(&ctx, 64 * 1024, "unknown", "phraq").await;
            let session_id = Uuid::from_bytes(login.session_id);
            request(&mut a, &mut seq, PacketType::ChatJoin, chat_join("hideout")).await;
            request(&mut a, &mut seq, PacketType::ChatJoin, Bytes::from_static(&[0xFF])).await;
            assert!(conn.await.unwrap().is_err());

            assert!(ctx.presence.list().await.is_empty(), "ghost left in presence");
            assert!(ctx.auth.validate(session_id).is_none(), "session leaked");

            // The room no longer holds the dead member.
            let (mut b, mut b_seq, conn_b, _) = connect_as(&ctx, 64 * 1024, "unknown", "phraq").await;
            request(&mut b, &mut b_seq, PacketType::ChatJoin, chat_join("hideout")).await;
            let frame = recv_type(&mut b, PacketType::ChatUserList).await;
            let list = ChatUserList::decode(&frame.payload).unwrap();
            assert_eq!(list.users, vec!["phraq".to_string()]);
            request(&mut b, &mut b_seq, PacketType::Disconnect, Bytes::new()).await;
            conn_b.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn kick_reaches_a_client_that_stopped_reading() {
            let (ctx, _dir) = test_ctx().await;
            // `_client` stays open but is never read again.
            let (_client, _seq, conn, _) = connect_as(&ctx, 1024, "unknown", "phraq").await;
            tokio::time::pause();
            // Fill the socket, then the connection's event queue.
            for _ in 0..(OUTBOUND_QUEUE + 64) {
                ctx.presence
                    .broadcast_all(Outbound {
                        packet_type: PacketType::Info,
                        flags: PacketFlags::SYSTEM_MESSAGE,
                        payload: Bytes::from(vec![b'x'; 512]),
                    })
                    .await;
            }
            assert_eq!(ctx.presence.disconnect("phraq", "bye").await, 1);
            let start = Instant::now();
            tokio::time::timeout(Duration::from_secs(300), conn)
                .await
                .expect("a stuck, kicked connection must end")
                .unwrap()
                .ok();
            assert!(start.elapsed() <= WRITE_TIMEOUT + FAREWELL_TIMEOUT);
            assert!(ctx.presence.list().await.is_empty());
        }

        /// `test_ctx` with downloads throttled to `rate` bytes/sec.
        async fn throttled_ctx(rate: u64) -> (Arc<ServerCtx>, tempfile::TempDir) {
            let (ctx, dir) = test_ctx().await;
            let mut inner = Arc::try_unwrap(ctx).ok().expect("sole owner of a fresh ctx");
            let pool = kdx_storage::connect(&dir.path().join("test.db")).await.unwrap();
            inner.transfers = TransferManager::new(
                pool,
                crate::transfer::TransferConfig {
                    files_root: dir.path().join("files"),
                    max_upload_bytes_per_sec: 0,
                    max_download_bytes_per_sec: rate,
                },
            )
            .await
            .unwrap();
            (Arc::new(inner), dir)
        }

        async fn seed_file(ctx: &ServerCtx, dir: &std::path::Path, name: &str, len: usize) {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let path = dir.join("files").join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &data).unwrap();
            let sha: [u8; 32] = sha2::Sha256::digest(&data).into();
            let root = ctx.tree.resolve("/").await.unwrap();
            ctx.tree
                .add_file(&root.id, name, len as u64, &sha, path.to_str().unwrap())
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn kick_lands_mid_download_without_waiting_for_it() {
            // 1 MiB at 64 KiB/s: about 15 s of streaming.
            let (ctx, dir) = throttled_ctx(64 * 1024).await;
            seed_file(&ctx, dir.path(), "big.bin", 1024 * 1024).await;
            let (mut client, mut seq, conn, _) = connect_as(&ctx, 256 * 1024, "unknown", "phraq").await;
            let download = TransferRequest {
                direction: DIRECTION_DOWNLOAD,
                path: "/".into(),
                name: "big.bin".into(),
                size: 0,
                chunk_size: 32 * 1024,
                sha256: [0; 32],
                resume_id: [0; 16],
                have_bitmap: vec![],
            };
            request(&mut client, &mut seq, PacketType::FileTransferStart, download.encode()).await;
            let accept = recv_type(&mut client, PacketType::FileTransferStart).await;
            assert_eq!(TransferAccept::decode(&accept.payload).unwrap().total_chunks, 32);

            tokio::time::pause();
            let start = Instant::now();
            let kicker = {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    ctx.presence.disconnect("phraq", "bye").await
                })
            };
            let mut reasm = Reassembler::default();
            let mut chunks = 0;
            loop {
                let frame = recv_logical(&mut client, &mut reasm).await;
                match frame.header.packet_type {
                    PacketType::FileTransferData => chunks += 1,
                    PacketType::Disconnect => {
                        assert_eq!(&frame.payload[..], b"bye");
                        break;
                    }
                    PacketType::FileTransferEnd => panic!("download finished before the kick landed"),
                    _ => {}
                }
            }
            assert_eq!(kicker.await.unwrap(), 1);
            assert!(chunks < 32, "kick waited for the download ({chunks} chunks)");
            assert!(start.elapsed() < Duration::from_secs(3));
            conn.await.unwrap().unwrap();
            assert!(ctx.presence.list().await.is_empty());
        }

        #[tokio::test]
        async fn download_still_completes_when_unthrottled() {
            let (ctx, dir) = test_ctx().await;
            seed_file(&ctx, dir.path(), "small.bin", 100 * 1024).await;
            let (mut client, mut seq, conn, _) = connect_as(&ctx, 64 * 1024, "unknown", "phraq").await;
            let download = TransferRequest {
                direction: DIRECTION_DOWNLOAD,
                path: "/".into(),
                name: "small.bin".into(),
                size: 0,
                chunk_size: 32 * 1024,
                sha256: [0; 32],
                resume_id: [0; 16],
                have_bitmap: vec![],
            };
            request(&mut client, &mut seq, PacketType::FileTransferStart, download.encode()).await;
            let mut reasm = Reassembler::default();
            let mut bytes = 0;
            loop {
                let frame = recv_logical(&mut client, &mut reasm).await;
                match frame.header.packet_type {
                    PacketType::FileTransferData => {
                        bytes += TransferData::decode(&frame.payload).unwrap().data.len();
                    }
                    PacketType::FileTransferEnd => break,
                    _ => {}
                }
            }
            assert_eq!(bytes, 100 * 1024);
            ping(&mut client, &mut seq).await;
            request(&mut client, &mut seq, PacketType::Disconnect, Bytes::new()).await;
            conn.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn reassembly_deadline_is_fixed_when_the_group_opens() {
            let (ctx, _dir) = test_ctx().await;
            let (mut client, mut seq, conn, _) = connect_as(&ctx, 64 * 1024, "unknown", "phraq").await;
            tokio::time::pause();
            let start = Instant::now();
            let fragment = |sequence: u32| KdxFrame {
                header: PacketHeader {
                    version: PROTOCOL_VERSION,
                    packet_type: PacketType::ChatMessage,
                    flags: PacketFlags::FRAGMENTED | PacketFlags::MORE_FRAGMENTS,
                    sequence,
                    length: 4,
                },
                payload: Bytes::from_static(b"abcd"),
            };
            client.send(fragment(bump(&mut seq))).await.unwrap();
            // A trickled fragment must not extend the deadline.
            tokio::time::sleep(Duration::from_secs(20)).await;
            client.send(fragment(bump(&mut seq))).await.unwrap();
            let result = tokio::time::timeout(Duration::from_secs(25), conn)
                .await
                .expect("the group should expire 30 s after it opened");
            assert!(matches!(result.unwrap(), Err(ConnectionError::ReassemblyTimeout)));
            let elapsed = start.elapsed();
            assert!(elapsed >= REASSEMBLY_TIMEOUT && elapsed < REASSEMBLY_TIMEOUT + Duration::from_secs(1));
            assert!(ctx.presence.list().await.is_empty());
        }

        #[tokio::test]
        async fn control_messages_have_a_smaller_reassembly_cap() {
            let (ctx, _dir) = test_ctx().await;
            let (mut client, mut seq, conn, _) = connect_as(&ctx, 256 * 1024, "unknown", "phraq").await;
            let frames = kdx_protocol::fragment(
                PacketType::Ping,
                PacketFlags::empty(),
                Bytes::from(vec![0u8; MAX_CONTROL_PAYLOAD + 1]),
                kdx_protocol::DEFAULT_MAX_FRAME_PAYLOAD,
                || bump(&mut seq),
            );
            for frame in frames {
                if client.send(frame).await.is_err() {
                    break;
                }
            }
            assert!(matches!(
                conn.await.unwrap(),
                Err(ConnectionError::Protocol(ProtocolError::ReassemblyTooLarge { .. }))
            ));
            assert!(ctx.presence.list().await.is_empty());
        }

        #[tokio::test]
        async fn idle_session_is_closed_after_the_session_ttl() {
            let (ctx, _dir) = test_ctx().await; // 60 s session TTL
            let (mut client, mut seq, conn, login) = connect_as(&ctx, 64 * 1024, "unknown", "phraq").await;
            let session_id = Uuid::from_bytes(login.session_id);
            tokio::time::pause();
            // Pings keep it alive well past one TTL.
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_secs(40)).await;
                ping(&mut client, &mut seq).await;
            }
            let start = Instant::now();
            let bye = tokio::time::timeout(
                Duration::from_secs(300),
                recv_type(&mut client, PacketType::Disconnect),
            )
            .await
            .expect("an idle session must be closed");
            assert_eq!(&bye.payload[..], b"idle timeout");
            assert!(start.elapsed() >= Duration::from_secs(59));
            assert!(matches!(conn.await.unwrap(), Err(ConnectionError::IdleTimeout)));
            assert!(ctx.presence.list().await.is_empty());
            assert!(ctx.auth.validate(session_id).is_none());
        }

        #[tokio::test]
        async fn inbound_flood_is_paced_not_dropped() {
            let (ctx, _dir) = test_ctx().await;
            let (mut client, mut seq, conn, _) = connect_as(&ctx, 256 * 1024, "unknown", "phraq").await;
            tokio::time::pause();
            let start = Instant::now();
            for _ in 0..70 {
                client
                    .feed(client_frame(PacketType::Ping, bump(&mut seq), Bytes::new()))
                    .await
                    .unwrap();
            }
            client.flush().await.unwrap();
            for _ in 0..70 {
                recv_type(&mut client, PacketType::Pong).await;
            }
            // 50 ride the burst; the other 20 are read at 20/s.
            let elapsed = start.elapsed();
            assert!(elapsed >= Duration::from_millis(950), "{elapsed:?}");
            request(&mut client, &mut seq, PacketType::Disconnect, Bytes::new()).await;
            conn.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn identity_changes_are_rate_limited() {
            let (ctx, _dir) = test_ctx().await;
            let (mut a, mut a_seq, conn_a, _) = connect_as(&ctx, 64 * 1024, "unknown", "phraq").await;
            let (mut b, mut b_seq, conn_b, _) = connect_as(&ctx, 64 * 1024, "unknown", "phraq").await;
            tokio::time::pause();
            for i in 0..5 {
                let identity = SetIdentity {
                    name: format!("nick{i}"),
                    description: String::new(),
                };
                request(&mut a, &mut a_seq, PacketType::SetIdentity, identity.encode()).await;
            }
            for _ in 0..2 {
                let err = recv_type(&mut a, PacketType::Error).await;
                assert!(error_text(&err).contains("slow down"));
            }
            // Everything the presence actor broadcast is queued for b before
            // this round-trip returns; b writes queued events ahead of the
            // Pong.
            ctx.presence.list().await;
            request(&mut b, &mut b_seq, PacketType::Ping, Bytes::new()).await;
            let mut reasm = Reassembler::default();
            let mut renames = 0;
            loop {
                let frame = recv_logical(&mut b, &mut reasm).await;
                match frame.header.packet_type {
                    PacketType::PresenceChange => {
                        let change = PresenceChange::decode(&frame.payload).unwrap();
                        if change.entry.name.starts_with("nick") {
                            renames += 1;
                        }
                    }
                    PacketType::Pong => break,
                    _ => {}
                }
            }
            assert_eq!(renames, 3, "only the burst should be broadcast");
            for (client, seq) in [(&mut a, &mut a_seq), (&mut b, &mut b_seq)] {
                request(client, seq, PacketType::Disconnect, Bytes::new()).await;
            }
            conn_a.await.unwrap().unwrap();
            conn_b.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn chat_flood_gate_survives_leaving_and_rejoining() {
            let (ctx, _dir) = test_ctx().await;
            let (mut client, mut seq, conn, _) = connect_as(&ctx, 256 * 1024, "unknown", "phraq").await;
            tokio::time::pause();
            let line = |text: &str| {
                ChatSend {
                    room: "lobby".into(),
                    flags: 0,
                    text: text.into(),
                }
                .encode()
            };
            request(&mut client, &mut seq, PacketType::ChatJoin, chat_join("lobby")).await;
            for i in 0..5 {
                request(&mut client, &mut seq, PacketType::ChatMessage, line(&format!("spam {i}"))).await;
            }
            // Leaving and rejoining used to hand out a fresh flood gate.
            let leave = ChatLeave {
                room: "lobby".into(),
            };
            request(&mut client, &mut seq, PacketType::ChatLeave, leave.encode()).await;
            request(&mut client, &mut seq, PacketType::ChatJoin, chat_join("lobby")).await;
            request(&mut client, &mut seq, PacketType::ChatMessage, line("one more")).await;
            let warning = recv_type(&mut client, PacketType::Warning).await;
            assert!(String::from_utf8_lossy(&warning.payload).contains("flood"));
            request(&mut client, &mut seq, PacketType::Disconnect, Bytes::new()).await;
            conn.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn joined_rooms_per_connection_are_capped() {
            let (ctx, _dir) = test_ctx().await;
            let (mut client, mut seq, conn, _) = connect_as(&ctx, 1024 * 1024, "unknown", "phraq").await;
            tokio::time::pause();
            let cap = crate::limits::MAX_JOINED_ROOMS_PER_CONNECTION;
            for i in 0..=cap {
                request(&mut client, &mut seq, PacketType::ChatJoin, chat_join(&format!("room-{i}"))).await;
                // Stay under the join rate limit.
                tokio::time::sleep(Duration::from_millis(600)).await;
            }
            request(&mut client, &mut seq, PacketType::Ping, Bytes::new()).await;
            let mut errors = Vec::new();
            let mut reasm = Reassembler::default();
            loop {
                let frame = recv_logical(&mut client, &mut reasm).await;
                match frame.header.packet_type {
                    PacketType::Error => errors.push(error_text(&frame)),
                    PacketType::Pong => break,
                    _ => {}
                }
            }
            assert_eq!(errors.len(), 1, "{errors:?}");
            assert!(errors[0].contains("too many chat rooms"));
            request(&mut client, &mut seq, PacketType::Disconnect, Bytes::new()).await;
            conn.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn addresses_are_only_shown_to_user_kick_holders() {
            let (ctx, _dir) = admin_test_ctx().await;
            let (mut sysop, mut s_seq, conn_s, _) = connect_as(&ctx, 64 * 1024, "10.0.0.1:1111", "sysop").await;
            let (mut plain, mut p_seq, conn_p, _) = connect_as(&ctx, 64 * 1024, "10.0.0.9:9999", "plain").await;

            // The admin sees the plain user's address in the join broadcast.
            let change = recv_type(&mut sysop, PacketType::PresenceChange).await;
            let change = PresenceChange::decode(&change.payload).unwrap();
            assert_eq!(change.entry.username, "plain");
            assert_eq!(change.entry.address, "10.0.0.9:9999");

            // The plain user sees no addresses: roster, user info, broadcasts.
            request(&mut plain, &mut p_seq, PacketType::PresenceListRequest, PresenceListRequest.encode())
                .await;
            let frame = recv_type(&mut plain, PacketType::PresenceListResponse).await;
            let roster = PresenceListResponse::decode(&frame.payload).unwrap();
            assert_eq!(roster.users.len(), 2);
            assert!(roster.users.iter().all(|u| u.address.is_empty()), "{roster:?}");

            let info = UserInfoRequest {
                username: "sysop".into(),
            };
            request(&mut plain, &mut p_seq, PacketType::UserInfoRequest, info.encode()).await;
            let frame = recv_type(&mut plain, PacketType::UserInfoResponse).await;
            assert!(UserInfoResponse::decode(&frame.payload).unwrap().entry.address.is_empty());

            let identity = SetIdentity {
                name: "The Sysop".into(),
                description: String::new(),
            };
            request(&mut sysop, &mut s_seq, PacketType::SetIdentity, identity.encode()).await;
            let frame = recv_type(&mut plain, PacketType::PresenceChange).await;
            let change = PresenceChange::decode(&frame.payload).unwrap();
            assert_eq!(change.entry.name, "The Sysop");
            assert!(change.entry.address.is_empty());

            // The admin still sees them everywhere.
            let info = UserInfoRequest {
                username: "plain".into(),
            };
            request(&mut sysop, &mut s_seq, PacketType::UserInfoRequest, info.encode()).await;
            let frame = recv_type(&mut sysop, PacketType::UserInfoResponse).await;
            assert_eq!(UserInfoResponse::decode(&frame.payload).unwrap().entry.address, "10.0.0.9:9999");
            request(&mut sysop, &mut s_seq, PacketType::ConnectionListRequest, ConnectionListRequest.encode())
                .await;
            let frame = recv_type(&mut sysop, PacketType::ConnectionListResponse).await;
            let conns = ConnectionListResponse::decode(&frame.payload).unwrap();
            assert!(conns.connections.iter().any(|c| c.address == "10.0.0.9:9999"));

            for (client, seq) in [(&mut sysop, &mut s_seq), (&mut plain, &mut p_seq)] {
                request(client, seq, PacketType::Disconnect, Bytes::new()).await;
            }
            conn_s.await.unwrap().unwrap();
            conn_p.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn shutdown_notice_is_flushed_and_the_stop_is_not_lost() {
            let (ctx, _dir) = admin_test_ctx().await;
            let (mut sysop, mut seq, conn, _) = connect_as(&ctx, 64 * 1024, "unknown", "sysop").await;
            let shutdown = AdminShutdown {
                message: "goodnight".into(),
            };
            request(&mut sysop, &mut seq, PacketType::AdminShutdown, shutdown.encode()).await;
            // The notice is flushed ahead of the Disconnect.
            let mut reasm = Reassembler::default();
            let mut saw_notice = false;
            loop {
                let frame = recv_logical(&mut sysop, &mut reasm).await;
                match frame.header.packet_type {
                    PacketType::Info if &frame.payload[..] == b"goodnight" => saw_notice = true,
                    PacketType::Disconnect => break,
                    _ => {}
                }
            }
            assert!(saw_notice);
            conn.await.unwrap().unwrap();
            // Nobody was parked in `notified()` when the admin asked; the
            // stop must still be waiting for the accept loop.
            tokio::time::timeout(Duration::from_secs(5), ctx.shutdown.notified())
                .await
                .expect("shutdown request was lost");
        }
    }
}
