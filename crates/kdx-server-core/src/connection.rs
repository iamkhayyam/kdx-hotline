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
use crate::auth::policy::{self, Refusal};
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
/// Cap on a reassembled logical payload (shared with clients).
pub const MAX_REASSEMBLED_PAYLOAD: usize = kdx_protocol::MAX_REASSEMBLED_PAYLOAD;
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
pub const MAX_CONTROL_PAYLOAD: usize = kdx_protocol::MAX_CONTROL_PAYLOAD;
/// Cap on a reassembled inbound `FileTransferStart`, which carries a resume
/// bitmap that can outgrow `MAX_CONTROL_PAYLOAD` for large files.
pub const MAX_TRANSFER_START_PAYLOAD: usize = kdx_protocol::MAX_TRANSFER_START_PAYLOAD;
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
    /// Server-wide brute-force throttle for logins (per peer IP and per
    /// peer IP + username).
    pub login_limiter: crate::auth::LoginLimiter,
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
    /// This connection's TLS exporter value (`kdx_crypto::TLS_EXPORTER_LABEL`)
    /// that login proofs are bound to. All zeros for streams without TLS.
    channel_binding: [u8; kdx_crypto::CHANNEL_BINDING_LEN],
    #[cfg(test)]
    hooks: TestHooks,
}

/// Fault and timing injection for this module's tests.
#[cfg(test)]
#[derive(Default)]
struct TestHooks {
    /// Hold every upload's `finish` until this is notified.
    finish_gate: Option<Arc<Notify>>,
    /// Fail the upload chunk with this index as a disk error would.
    fail_chunk: Option<u32>,
}

/// Disconnect reason for a session whose address the IP rules deny.
const ADDRESS_DENIED: &str = "your address is no longer allowed on this server";

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
            channel_binding: [0u8; kdx_crypto::CHANNEL_BINDING_LEN],
            #[cfg(test)]
            hooks: TestHooks::default(),
        }
    }

    /// Bind logins on this connection to its TLS session: `binding` is the
    /// session's `export_keying_material(32, kdx_crypto::TLS_EXPORTER_LABEL,
    /// None)`, which the client reads from its own end. `kdxd`'s listener
    /// must call this; without it (in-memory tests) the binding is all
    /// zeros and a real TLS client's proof won't verify.
    pub fn with_channel_binding(mut self, binding: [u8; kdx_crypto::CHANNEL_BINDING_LEN]) -> Self {
        self.channel_binding = binding;
        self
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
    /// `HandshakeResp` carrying the feature intersection. The reply is under
    /// the same timeout as the read, so a peer that never reads can't park
    /// the connection here.
    async fn handshake(&mut self) -> Result<(), ConnectionError> {
        timeout(HANDSHAKE_TIMEOUT, self.handshake_exchange())
            .await
            .map_err(|_| ConnectionError::HandshakeTimeout)?
    }

    async fn handshake_exchange(&mut self) -> Result<(), ConnectionError> {
        let frame = self
            .framed
            .next()
            .await
            .ok_or(ConnectionError::PeerClosed)??;

        if frame.header.packet_type != PacketType::HandshakeInit {
            return Err(ConnectionError::UnexpectedPacket {
                expected: "HandshakeInit",
                got: frame.header.packet_type,
            });
        }
        let init = HandshakeInit::decode(&frame.payload)?;
        debug!(version = init.version, features = init.features, "handshake init");
        if init.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(init.version).into());
        }

        let resp = HandshakeResp {
            version: PROTOCOL_VERSION,
            features: init.features & SERVER_FEATURES,
        };
        self.send(PacketType::HandshakeResp, PacketFlags::empty(), resp.encode())
            .await?;
        Ok(())
    }

    /// Challenge-response login: a SCRAM-style proof bound to this
    /// connection's TLS channel (see `kdx_crypto::scram`). Returns `false` on
    /// clean disconnect, `true` once a session is established. Ping/Pong
    /// stays available so clients can keep the connection warm at a login
    /// prompt.
    ///
    /// The whole phase — reads *and* writes (Pongs, challenges, results) —
    /// must finish within `AUTH_TIMEOUT`, so a peer that stops reading can't
    /// park the connection in a blocked send.
    async fn authenticate(&mut self) -> Result<bool, ConnectionError> {
        let deadline = tokio::time::Instant::now() + AUTH_TIMEOUT;
        timeout_at(deadline, self.authenticate_until_done())
            .await
            .map_err(|_| ConnectionError::AuthTimeout)?
    }

    async fn authenticate_until_done(&mut self) -> Result<bool, ConnectionError> {
        let peer_ip = self.peer_ip();
        let mut failures: u8 = 0;

        loop {
            let frame = self
                .framed
                .next()
                .await
                .ok_or(ConnectionError::PeerClosed)??;

            match frame.header.packet_type {
                PacketType::Ping => {
                    self.send(PacketType::Pong, PacketFlags::empty(), frame.payload)
                        .await?;
                }
                PacketType::Disconnect => return Ok(false),
                PacketType::AuthRequest => {
                    let username = AuthRequest::decode(&frame.payload)?.username;

                    // Refusals answered straight away (no challenge round,
                    // no DB work). Each still costs one of this connection's
                    // attempts; throttled ones aren't audited, so a blocked
                    // source can't flood the history log.
                    let shown =
                        crate::limits::truncate_utf8(&username, crate::limits::MAX_USERNAME_LEN);
                    let refusal = if let Err(wait) = self.ctx.login_limiter.check(peer_ip, shown) {
                        Some(format!(
                            "too many failed login attempts; try again in {}s",
                            wait.as_secs().max(1)
                        ))
                    } else if username.len() > crate::limits::MAX_USERNAME_LEN {
                        self.ctx.login_limiter.record_failure(peer_ip, shown);
                        self.record_history(
                            Some(shown.to_owned()),
                            "login_failed",
                            format!("peer={}, username too long", self.peer_addr),
                        );
                        Some("invalid credentials".to_string())
                    } else {
                        None
                    };
                    if let Some(message) = refusal {
                        failures += 1;
                        self.send_auth_failure(message).await?;
                        if failures >= MAX_AUTH_ATTEMPTS {
                            return Err(ConnectionError::TooManyAuthAttempts);
                        }
                        continue;
                    }

                    let (data, pending) =
                        self.ctx.auth.begin(&username, self.channel_binding).await?;
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
                    let response_frame = self
                        .framed
                        .next()
                        .await
                        .ok_or(ConnectionError::PeerClosed)??;
                    if response_frame.header.packet_type != PacketType::AuthResponse {
                        return Err(ConnectionError::UnexpectedPacket {
                            expected: "AuthResponse",
                            got: response_frame.header.packet_type,
                        });
                    }
                    let response = AuthResponse::decode(&response_frame.payload)?;

                    match self.ctx.auth.complete(pending, &response.response).await {
                        Ok(verified) => {
                            let session = verified.session;
                            // Register the session now (unless the server is
                            // full), but keep it only once the result (and
                            // greeting) actually went out: on a send error or
                            // the auth timeout the guard unregisters it, so
                            // nothing leaks.
                            let cap = self.user_cap_for(&session).await;
                            let ctx = self.ctx.clone();
                            let Some(registration) = ctx.auth.admit(&session, cap) else {
                                failures += 1;
                                self.send_auth_failure("server is full".into()).await?;
                                if failures >= MAX_AUTH_ATTEMPTS {
                                    return Err(ConnectionError::TooManyAuthAttempts);
                                }
                                continue;
                            };
                            let result = AuthResult {
                                success: true,
                                session_id: *session.id.as_bytes(),
                                class: session.class as u8,
                                message: format!("welcome, {}", session.username),
                                server_signature: verified.server_signature,
                            };
                            self.send(PacketType::AuthResult, PacketFlags::empty(), result.encode())
                                .await?;
                            let greeting = self.ctx.settings.greeting().await;
                            if !greeting.is_empty() {
                                self.send(
                                    PacketType::Info,
                                    PacketFlags::SYSTEM_MESSAGE,
                                    Bytes::copy_from_slice(greeting.as_bytes()),
                                )
                                .await?;
                            }
                            registration.keep();
                            self.ctx.login_limiter.record_success(peer_ip, &username);
                            debug!(user = %session.username, "authenticated");
                            self.record_history(
                                Some(session.username.clone()),
                                "login",
                                format!("peer={}", self.peer_addr),
                            );
                            self.session = Some(session);
                            return Ok(true);
                        }
                        Err(crate::auth::AuthError::InvalidCredentials) => {
                            failures += 1;
                            self.ctx.login_limiter.record_failure(peer_ip, &username);
                            self.record_history(
                                Some(username.clone()),
                                "login_failed",
                                format!("peer={}", self.peer_addr),
                            );
                            self.send_auth_failure("invalid credentials".into()).await?;
                            if failures >= MAX_AUTH_ATTEMPTS {
                                return Err(ConnectionError::TooManyAuthAttempts);
                            }
                        }
                        // Correct password but the account is banned: refuse
                        // the login. It still counts as a failed attempt
                        // (here and in the limiter), so a banned user can't
                        // loop logins — each a DB read and history write —
                        // for free.
                        Err(crate::auth::AuthError::Banned { until, reason }) => {
                            failures += 1;
                            self.ctx.login_limiter.record_failure(peer_ip, &username);
                            let message = ban_message(until, &reason);
                            let reason = crate::limits::truncate_utf8(
                                &reason,
                                crate::limits::MAX_REASON_LEN,
                            );
                            self.record_history(
                                Some(username.clone()),
                                "login_banned",
                                format!("peer={}, reason={}", self.peer_addr, reason),
                            );
                            self.send_auth_failure(message).await?;
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

    /// Send a failed `AuthResult` (no session, no server signature).
    async fn send_auth_failure(&mut self, message: String) -> Result<(), ConnectionError> {
        let result = AuthResult {
            success: false,
            session_id: [0u8; 16],
            class: 0,
            message,
            server_signature: [0u8; 32],
        };
        self.send(
            PacketType::AuthResult,
            PacketFlags::empty(),
            result.encode(),
        )
        .await
    }

    /// The `max_users` cap on registered sessions that applies to
    /// `session`'s login (`None` = no cap). 0 means unlimited, and accounts
    /// with SERVER_ADMIN may always log in, so an operator can't be locked
    /// out of a full server.
    async fn user_cap_for(&self, session: &Session) -> Option<usize> {
        let max_users = self.ctx.settings.snapshot().await.max_users as usize;
        (max_users != 0 && !session.privileges.contains(Privileges::SERVER_ADMIN))
            .then_some(max_users)
    }

    /// Why a session that has just joined presence must not go on, if
    /// anything changed while its login was in flight. A login can sit
    /// between challenge and proof for up to `AUTH_TIMEOUT`, and demotion
    /// kicks, bans and IP-rule enforcement only reach presence entries.
    /// Every such change is written to the database before its kick is
    /// sent, and `presence.join` returns only once we're in the roster, so
    /// this re-read sees every change whose kick missed us; any later kick
    /// reaches our kill signal. Fails closed.
    async fn stale_login_reason(&self, session: &Session) -> Option<String> {
        const RECHECK_FAILED: &str = "internal server error; please reconnect";
        match self.ctx.roles.account_state(&session.username).await {
            Ok(Some(stored))
                if stored.account_id == session.account_id
                    && stored.class == session.class
                    && stored.effective() == session.privileges => {}
            Ok(_) => return Some(policy::PRIVILEGES_CHANGED.to_string()),
            Err(e) => {
                warn!(error = %e, "could not re-check a new session's account");
                return Some(RECHECK_FAILED.to_string());
            }
        }
        match self.ctx.auth.active_ban(&session.account_id).await {
            Ok(None) => {}
            Ok(Some((until, reason))) => return Some(ban_message(until, &reason)),
            Err(e) => {
                warn!(error = %e, "could not re-check a new session's bans");
                return Some(RECHECK_FAILED.to_string());
            }
        }
        if let Some(ip) = crate::ip_rules::parse_peer_ip(&self.peer_addr) {
            if let crate::ip_rules::Verdict::Deny { .. } = self.ctx.ip_rules.match_ip(ip).await {
                return Some(ADDRESS_DENIED.to_string());
            }
        }
        None
    }

    /// The peer's IP, for the login limiter. Streams without a network peer
    /// (tests) share the unspecified address.
    fn peer_ip(&self) -> std::net::IpAddr {
        self.peer_addr
            .parse::<std::net::SocketAddr>()
            .map(|addr| addr.ip())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
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
        if let Some(reason) = self.stale_login_reason(&session).await {
            debug!(user = %session.username, %reason, "login went stale while in flight");
            self.farewell(&mut outbound_rx, Some(reason)).await;
            guard.cleanup().await;
            return Ok(());
        }

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
        // One upload at a time per connection, in one of three places: in
        // `upload` between chunks; in `chunk_write` while a chunk is being
        // throttled and stored; in `finishing` once every chunk is in and it
        // is being verified and filed. The slow parts run as select branches
        // (or a task) so Pings, kicks and events keep flowing meanwhile.
        let mut upload: Option<ActiveUpload> = None;
        let mut chunk_write: Option<ChunkWrite> = None;
        let mut finishing: Option<Finishing> = None;
        // The last upload the server ended. Chunks (and a cancel) the client
        // still had in flight for it are dropped without an `Error`.
        let mut ended_upload: Option<[u8; 16]> = None;
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
        // The rest of an oversized fragment group, being skipped.
        let mut skipping: Option<Skipping> = None;

        enum Next {
            Killed(Option<String>),
            Event(Outbound),
            Frame(Option<Result<KdxFrame, ProtocolError>>),
            ReassemblyTimedOut,
            IdleTimedOut,
            ChunkWritten(Box<Written>),
            Finished([u8; 16], Result<(), TransferError>),
            Download(Box<Pulled>),
        }

        loop {
            // While a chunk is being settled the client's next frames wait in
            // the socket: their answers must follow the chunk's `Error`, if
            // any (the client pairs them up by order). Idleness is judged
            // only while frames are being read, and a frame that is already
            // waiting beats the idle deadline (it is polled first).
            let reading = chunk_write.is_none();
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
                    written = next_written(&mut chunk_write) => Next::ChunkWritten(Box::new(written)),
                    next = async {
                        if let Some(at) = throttled_until {
                            tokio::time::sleep_until(at).await;
                        }
                        framed.next().await
                    }, if reading => Next::Frame(next),
                    _ = tokio::time::sleep_until(idle_deadline), if reading => Next::IdleTimedOut,
                    (transfer_id, result) = next_finished(&mut finishing) => {
                        Next::Finished(transfer_id, result)
                    }
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
                Next::ChunkWritten(written) => {
                    chunk_write = None;
                    let (active, result) = *written;
                    match result {
                        Ok(false) => upload = Some(active), // more chunks to come
                        Ok(true) => finishing = Some(self.start_finish(active)),
                        // Recoverable per-chunk problems: report, let the
                        // client resend.
                        Err(
                            e @ (TransferError::ChunkHashMismatch
                            | TransferError::BadChunkIndex
                            | TransferError::BadChunkLength),
                        ) => {
                            upload = Some(active);
                            self.send_error(&e.to_string()).await?;
                        }
                        // A server-side failure (disk, database): end this
                        // attempt but keep the upload resumable.
                        Err(e) => {
                            warn!(error = %e, "upload chunk could not be stored");
                            let transfer_id = *active.id().as_bytes();
                            self.ctx.transfers.release(active).await;
                            ended_upload = Some(transfer_id);
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
                    continue;
                }
                Next::Finished(transfer_id, result) => {
                    finishing = None;
                    ended_upload = Some(transfer_id);
                    let (status, message) = upload_outcome(result);
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
                    continue;
                }
                Next::Download(pulled) => {
                    let (stream, chunk) = *pulled;
                    match chunk {
                        Ok(chunk) => self.pump_download(&mut download, stream, chunk).await?,
                        // A read failure (I/O error, a blob shorter than
                        // recorded) ends this download, not the session.
                        Err(e) => {
                            warn!(error = %e, "download aborted");
                            download = None;
                            let end = TransferEnd {
                                transfer_id: *stream.id().as_bytes(),
                                status: kdx_protocol::messages::TRANSFER_ABORTED,
                                message: format!("download failed: {}", e.client_message()),
                            };
                            self.send(
                                PacketType::FileTransferEnd,
                                PacketFlags::TRANSFER_END,
                                end.encode(),
                            )
                            .await?;
                        }
                    }
                    continue;
                }
                Next::Frame(item) => item,
            };

            let Some(frame) = frame_or_eof.transpose()? else {
                break Ok(()); // clean EOF
            };

            // Any inbound frame is activity.
            idle_deadline = tokio::time::Instant::now() + idle_timeout;
            // Everything but an accepted upload's traffic spends inbound
            // budget. That traffic is its data frames plus the Ping barrier
            // the client sends after each chunk (to correlate per-chunk
            // errors); pacing those would cap uploads at ~20 chunks/s. A
            // Ping is a same-size echo, so exempting it amplifies nothing.
            let upload_traffic = upload.is_some()
                && matches!(
                    frame.header.packet_type,
                    PacketType::FileTransferData | PacketType::Ping
                );
            if !upload_traffic {
                rate.inbound.allow();
            }

            let pushed = self.reassemble(frame, &mut skipping).await?;
            if !self.reassembler.is_reassembling() && skipping.is_none() {
                reassembly_deadline = None;
            } else if reassembly_deadline.is_none() {
                reassembly_deadline = Some(tokio::time::Instant::now() + REASSEMBLY_TIMEOUT);
            }
            let Some(frame) = pushed else {
                continue; // mid-group fragment, or a refused oversized message
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
                        Ok(_) => self.reply_tree_changed(&req.path, &session).await?,
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
                            self.reply_tree_changed(&parent, &session).await?;
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
                        Ok(()) => self.reply_tree_changed(&req.dest_path, &session).await?,
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
                        Ok(_) => self.reply_tree_changed(&req.dest_path, &session).await?,
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
                    // One download stream per connection, like uploads: a
                    // second request must not silently replace the first.
                    if download.is_some() {
                        self.send_error("a download is already active").await?;
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
                    // (`chunk_write` is always empty while frames are read.)
                    if upload.is_some() || finishing.is_some() {
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
                            if active.is_complete() {
                                // Nothing left for the client to send (an
                                // empty file, or a resume of an upload whose
                                // chunks all arrived): verify and file it.
                                finishing = Some(self.start_finish(active));
                            } else {
                                upload = Some(active);
                            }
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
                    // An upload the server already ended (aborted, or all
                    // chunks in and being finished): the client sent these
                    // before it heard; one `TransferEnd` said it all.
                    let ended = ended_upload == Some(data.transfer_id)
                        || finishing
                            .as_ref()
                            .is_some_and(|f| f.transfer_id == data.transfer_id);
                    // (Checked after the live upload: a resume can reuse the
                    // id of an attempt the server aborted.)
                    match upload.as_ref() {
                        Some(active) if data.transfer_id == *active.id().as_bytes() => {}
                        _ if ended => continue,
                        Some(_) => {
                            self.send_error("unknown transfer id").await?;
                            continue;
                        }
                        None => {
                            self.send_error("no active transfer").await?;
                            continue;
                        }
                    }
                    let active = upload.take().expect("matched above");
                    chunk_write = Some(self.write_chunk(active, data));
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
                            // Or the client is cancelling a download: stop
                            // pumping it (dropping the stream frees its slot).
                            if download
                                .as_ref()
                                .is_some_and(|pump| pump.transfer_id == end.transfer_id)
                            {
                                debug!(status = end.status, "client cancelled its download");
                                download = None;
                            } else if ended_upload == Some(end.transfer_id)
                                || finishing
                                    .as_ref()
                                    .is_some_and(|f| f.transfer_id == end.transfer_id)
                            {
                                // Crossed with the server's own end of it
                                // (verifying can't be called off half-way);
                                // the client hears the outcome either way.
                                debug!(
                                    status = end.status,
                                    "client ended an upload the server ended"
                                );
                            } else {
                                self.send_error("no matching active transfer").await?;
                            }
                        }
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

    /// Feed one inbound frame to the reassembler. A fragment group over its
    /// type's cap is not buffered: the rest of it is skipped and the whole
    /// message answered with one `Error`, which keeps the client's
    /// request/answer pairing intact and the session up.
    async fn reassemble(
        &mut self,
        frame: KdxFrame,
        skipping: &mut Option<Skipping>,
    ) -> Result<Option<KdxFrame>, ConnectionError> {
        let header = frame.header;
        let more = header.flags.contains(PacketFlags::MORE_FRAGMENTS);
        match skipping.as_mut() {
            Some(skip) => {
                // Only the rest of that group may follow, in order.
                if !header.flags.contains(PacketFlags::FRAGMENTED)
                    || header.packet_type != skip.packet_type
                {
                    return Err(ProtocolError::FragmentInterleaved.into());
                }
                if header.sequence != skip.next_sequence {
                    return Err(ProtocolError::FragmentOutOfOrder {
                        expected: skip.next_sequence,
                        got: header.sequence,
                    }
                    .into());
                }
                if more {
                    skip.next_sequence = header.sequence.wrapping_add(1);
                    return Ok(None);
                }
                *skipping = None;
            }
            None => match self
                .reassembler
                .push(frame, reassembly_cap(header.packet_type))
            {
                Ok(pushed) => return Ok(pushed),
                Err(ProtocolError::ReassemblyTooLarge { .. }) => {
                    self.reassembler.abort();
                    if more {
                        *skipping = Some(Skipping {
                            packet_type: header.packet_type,
                            next_sequence: header.sequence.wrapping_add(1),
                        });
                        return Ok(None);
                    }
                }
                Err(e) => return Err(e.into()),
            },
        }
        // The whole oversized message has gone by: one answer for it.
        debug!(packet_type = ?header.packet_type, "refused an oversized message");
        let limit = reassembly_cap(header.packet_type);
        self.send_error(&format!("message too large (the limit is {limit} bytes)"))
            .await?;
        Ok(None)
    }

    /// Settle one upload chunk (throttle, verify, store) as a select branch
    /// of the dispatch loop. The future owns the upload until it is done.
    fn write_chunk(&self, mut active: ActiveUpload, data: TransferData) -> ChunkWrite {
        let ctx = self.ctx.clone();
        #[cfg(test)]
        let fault = self.hooks.fail_chunk == Some(data.chunk_index);
        Box::pin(async move {
            #[cfg(test)]
            if fault {
                let injected = std::io::Error::other("injected chunk write failure");
                return (active, Err(TransferError::Io(injected)));
            }
            let result = ctx
                .transfers
                .write_chunk(&mut active, data.chunk_index, &data.chunk_hash, &data.data)
                .await;
            (active, result)
        })
    }

    /// Verify and file an upload whose chunks have all arrived, on its own
    /// task: hashing a big file can take minutes, during which the dispatch
    /// loop keeps answering. The task runs to completion even if this
    /// connection goes away meanwhile, since `finish` stopped half-way could
    /// leave a filed entry without its bytes.
    fn start_finish(&self, active: ActiveUpload) -> Finishing {
        let transfer_id = *active.id().as_bytes();
        let ctx = self.ctx.clone();
        #[cfg(test)]
        let gate = self.hooks.finish_gate.clone();
        let task = tokio::spawn(async move {
            #[cfg(test)]
            if let Some(gate) = gate {
                gate.notified().await;
            }
            ctx.transfers.finish(&ctx.tree, active).await
        });
        Finishing { transfer_id, task }
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

    /// Report a refused or failed admin request: a policy refusal goes to the
    /// client verbatim; an internal failure is logged here and the client
    /// gets only a generic message (STORE-9).
    async fn send_refusal(&mut self, refusal: Refusal) -> Result<(), ConnectionError> {
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
            .disconnect_denied(&self.ctx.presence, ADDRESS_DENIED, &actor)
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

    /// The reply to a successful tree change (new folder, move, alias,
    /// delete): the changed folder's listing, so the Files window
    /// re-renders. The change has happened, so the reply must not look like
    /// a failure: where the caller may not list that folder (write-only
    /// access, or it changed again meanwhile), an empty listing of it.
    async fn reply_tree_changed(&mut self, path: &str, session: &Session) -> Result<(), ConnectionError> {
        if let Err(e) = self.ctx.tree.list(path, session).await {
            debug!(path, error = %e, "changed folder is not listable; replying with an empty listing");
            let response = FileListResponse {
                path: path.to_owned(),
                entries: Vec::new(),
            };
            return self
                .send(PacketType::FileListResponse, PacketFlags::empty(), response.encode())
                .await;
        }
        self.reply_file_list(path, session).await
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
    /// The stream's wire transfer id, so a client `TransferEnd` can cancel it.
    transfer_id: [u8; 16],
    pull: std::pin::Pin<Box<dyn std::future::Future<Output = Pulled> + Send>>,
}

impl DownloadPump {
    fn new(mut stream: ActiveDownload) -> Self {
        Self {
            transfer_id: *stream.id().as_bytes(),
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

/// What settling one upload chunk yields: the upload back, and whether every
/// chunk has now arrived.
type Written = (ActiveUpload, Result<bool, TransferError>);

/// An upload chunk being settled (see [`Connection::write_chunk`]).
type ChunkWrite = std::pin::Pin<Box<dyn std::future::Future<Output = Written> + Send>>;

/// An upload being verified and filed (see [`Connection::start_finish`]).
struct Finishing {
    transfer_id: [u8; 16],
    task: tokio::task::JoinHandle<Result<(), TransferError>>,
}

/// The rest of a fragment group that went over its cap, being skipped.
struct Skipping {
    packet_type: PacketType,
    next_sequence: u32,
}

/// The settled chunk write; pending forever if there is none. Cancel-safe:
/// the write itself lives in `write`.
async fn next_written(write: &mut Option<ChunkWrite>) -> Written {
    match write {
        Some(write) => write.as_mut().await,
        None => std::future::pending().await,
    }
}

/// The outcome of the upload being finished; pending forever if there is
/// none. Cancel-safe: the work runs on its own task.
async fn next_finished(finishing: &mut Option<Finishing>) -> ([u8; 16], Result<(), TransferError>) {
    match finishing {
        Some(finishing) => {
            let result = (&mut finishing.task)
                .await
                .unwrap_or_else(|e| Err(TransferError::Io(std::io::Error::other(e))));
            (finishing.transfer_id, result)
        }
        None => std::future::pending().await,
    }
}

/// `TransferEnd` status and message for a finished upload.
fn upload_outcome(result: Result<(), TransferError>) -> (u8, String) {
    match result {
        Ok(()) => (TRANSFER_VERIFIED, "verified".to_string()),
        Err(TransferError::FileHashMismatch) => {
            (TRANSFER_HASH_MISMATCH, "file hash mismatch".to_string())
        }
        // Name taken / folder gone meanwhile, or a server failure: the
        // upload has been discarded; tell the client, stay up.
        Err(e) => {
            warn!(error = %e, "upload could not be filed");
            (
                kdx_protocol::messages::TRANSFER_ABORTED,
                format!("upload not filed: {}", e.client_message()),
            )
        }
    }
}

/// What a banned account is told (at login, or when a ban lands while its
/// login is in flight).
fn ban_message(until: i64, reason: &str) -> String {
    let reason = crate::limits::truncate_utf8(reason, crate::limits::MAX_REASON_LEN);
    if reason.is_empty() {
        format!("banned until {until}")
    } else {
        format!("banned until {until}: {reason}")
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
    // Shared with clients so they refuse to send what we'd reject.
    kdx_protocol::max_request_payload(packet_type)
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
    use kdx_crypto::{client_proof, hash_password, AuthContext};
    use kdx_protocol::PacketHeader;
    use kdx_storage::accounts;

    async fn test_ctx() -> (Arc<ServerCtx>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = kdx_storage::connect(&dir.path().join("test.db"))
            .await
            .unwrap();
        let phc = hash_password("s3cret").unwrap();
        accounts::create(&pool, "phraq", &phc, 2, 0, 0).await.unwrap();
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
            login_limiter: crate::auth::LoginLimiter::new(),
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

    /// Run one login round; returns the AuthResult. A successful result's
    /// server signature is verified. Duplex streams have no TLS session, so
    /// both ends use the all-zero channel binding.
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

        let proof = client_proof(
            password,
            &AuthContext {
                username,
                challenge: &challenge.challenge,
                salt: &challenge.salt,
                params: kdx_crypto::KdfParams {
                    m_cost: challenge.m_cost,
                    t_cost: challenge.t_cost,
                    p_cost: challenge.p_cost,
                },
                channel_binding: &[0u8; kdx_crypto::CHANNEL_BINDING_LEN],
            },
        )
        .unwrap();
        client
            .send(client_frame(
                PacketType::AuthResponse,
                bump(seq),
                AuthResponse {
                    response: proof.proof,
                }
                .encode(),
            ))
            .await
            .unwrap();

        let result_frame = client.next().await.unwrap().unwrap();
        assert_eq!(result_frame.header.packet_type, PacketType::AuthResult);
        let result = AuthResult::decode(&result_frame.payload).unwrap();
        if result.success {
            assert!(
                proof.verify_server_signature(&result.server_signature),
                "server signature did not verify"
            );
        }
        result
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

    /// Send a bare `AuthRequest` and return the server's next frame.
    async fn send_auth_request(
        client: &mut Framed<tokio::io::DuplexStream, KdxCodec>,
        seq: &mut u32,
        username: &str,
    ) -> KdxFrame {
        let request = AuthRequest {
            username: username.into(),
        };
        client
            .send(client_frame(
                PacketType::AuthRequest,
                bump(seq),
                request.encode(),
            ))
            .await
            .unwrap();
        client.next().await.unwrap().unwrap()
    }

    /// One failed login round with a bogus proof (no Argon2 on our side).
    async fn fail_login(
        client: &mut Framed<tokio::io::DuplexStream, KdxCodec>,
        seq: &mut u32,
        username: &str,
    ) -> AuthResult {
        let frame = send_auth_request(client, seq, username).await;
        assert_eq!(frame.header.packet_type, PacketType::AuthChallenge);
        client
            .send(client_frame(
                PacketType::AuthResponse,
                bump(seq),
                AuthResponse {
                    response: [0u8; 32],
                }
                .encode(),
            ))
            .await
            .unwrap();
        let frame = client.next().await.unwrap().unwrap();
        assert_eq!(frame.header.packet_type, PacketType::AuthResult);
        AuthResult::decode(&frame.payload).unwrap()
    }

    /// Poll the history log until it holds at least `n` events (login
    /// paths record through the detached writer). The writer merges
    /// identical events that land in one batch into a single row whose
    /// detail ends in ` (xN)`; expand those back into N events so tests
    /// count what happened, not how it was batched.
    async fn wait_for_history(ctx: &ServerCtx, n: usize) -> Vec<crate::history::HistoryEntry> {
        for _ in 0..200 {
            ctx.history.flush().await;
            let mut events = Vec::new();
            for entry in ctx.history.recent(100).await.unwrap() {
                let (detail, count) = match entry.detail.rsplit_once('(') {
                    Some((head, tail)) if tail.starts_with('x') && tail.ends_with(')') => {
                        match tail[1..tail.len() - 1].parse::<usize>() {
                            Ok(count) => (head.trim_end().to_string(), count),
                            Err(_) => (entry.detail.clone(), 1),
                        }
                    }
                    _ => (entry.detail.clone(), 1),
                };
                for _ in 0..count {
                    let mut event = entry.clone();
                    event.detail = detail.clone();
                    events.push(event);
                }
            }
            if events.len() >= n {
                return events;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("history never reached {n} events");
    }

    #[tokio::test]
    async fn oversized_username_is_refused_before_any_lookup() {
        let (ctx, _dir) = test_ctx().await;
        let (client, server) = tokio::io::duplex(64 * 1024);
        let conn = tokio::spawn(Connection::new(server, ctx.clone()).run());
        let mut client = client_framed(client);
        let mut seq = 0;
        do_handshake(&mut client, &mut seq).await;

        let huge = "x".repeat(10_000);
        for _ in 0..MAX_AUTH_ATTEMPTS {
            // Refused outright: no challenge round, and each one counts.
            let frame = send_auth_request(&mut client, &mut seq, &huge).await;
            assert_eq!(frame.header.packet_type, PacketType::AuthResult);
            let result = AuthResult::decode(&frame.payload).unwrap();
            assert!(!result.success);
        }
        assert!(matches!(
            conn.await.unwrap().unwrap_err(),
            ConnectionError::TooManyAuthAttempts
        ));

        // The audit rows carry a bounded actor, not the 10 KB name.
        let entries = wait_for_history(&ctx, MAX_AUTH_ATTEMPTS as usize).await;
        for entry in &entries {
            assert_eq!(entry.action, "login_failed");
            let actor = entry.actor.as_deref().unwrap_or_default();
            assert!(
                actor.len() <= crate::limits::MAX_USERNAME_LEN,
                "{} bytes",
                actor.len()
            );
        }
    }

    #[tokio::test]
    async fn banned_attempts_count_toward_the_attempt_limit() {
        let (ctx, _dir) = test_ctx().await;
        let id = ctx.auth.account_id("phraq").await.unwrap().unwrap();
        let until = unix_now() as i64 + 10_000;
        ctx.auth.set_ban(&id, until, "spam", "sysop").await.unwrap();

        let (client, server) = tokio::io::duplex(8192);
        let conn = tokio::spawn(
            Connection::new_with_peer(server, ctx.clone(), "10.0.0.9:1234".into()).run(),
        );
        let mut client = client_framed(client);
        let mut seq = 0;
        do_handshake(&mut client, &mut seq).await;
        for _ in 0..MAX_AUTH_ATTEMPTS {
            let result = do_login(&mut client, &mut seq, "phraq", "s3cret").await;
            assert!(!result.success);
            assert!(
                result.message.starts_with("banned until"),
                "{}",
                result.message
            );
        }
        // Correct password or not, a banned account can't loop logins.
        assert!(matches!(
            conn.await.unwrap().unwrap_err(),
            ConnectionError::TooManyAuthAttempts
        ));
        let entries = wait_for_history(&ctx, MAX_AUTH_ATTEMPTS as usize).await;
        assert!(entries
            .iter()
            .all(|e| e.action == "login_banned" && e.detail.contains("peer=10.0.0.9:1234")));
    }

    #[tokio::test]
    async fn failed_logins_are_throttled_and_logged_with_the_peer() {
        let (ctx, _dir) = test_ctx().await;
        let peer = "10.0.0.9:1234";
        let ip: std::net::IpAddr = "10.0.0.9".parse().unwrap();
        // Failures on the wire land in the shared limiter (not just the
        // per-connection counter).
        let (client, server) = tokio::io::duplex(8192);
        let conn = tokio::spawn(Connection::new_with_peer(server, ctx.clone(), peer.into()).run());
        let mut client = client_framed(client);
        let mut seq = 0;
        do_handshake(&mut client, &mut seq).await;
        for _ in 0..MAX_AUTH_ATTEMPTS {
            assert!(!fail_login(&mut client, &mut seq, "phraq").await.success);
        }
        assert!(conn.await.unwrap().is_err());
        assert_eq!(
            ctx.login_limiter.failure_count(ip, "phraq"),
            MAX_AUTH_ATTEMPTS as u32
        );

        // More failures from that address (as further connections would add)
        // put the pair into a long backoff — no wall-clock race in the test.
        for _ in 0..9 {
            ctx.login_limiter.record_failure(ip, "phraq");
        }

        // Now even the right password from that address is refused without a
        // challenge round...
        let (client, server) = tokio::io::duplex(8192);
        let conn = tokio::spawn(Connection::new_with_peer(server, ctx.clone(), peer.into()).run());
        let mut client = client_framed(client);
        let mut seq = 0;
        do_handshake(&mut client, &mut seq).await;
        let frame = send_auth_request(&mut client, &mut seq, "phraq").await;
        assert_eq!(frame.header.packet_type, PacketType::AuthResult);
        let refused = AuthResult::decode(&frame.payload).unwrap();
        assert!(!refused.success);
        assert!(
            refused.message.contains("too many failed login attempts"),
            "{}",
            refused.message
        );
        drop(client);
        let _ = conn.await;

        // ...while the same account from another address still gets in.
        let (client, server) = tokio::io::duplex(8192);
        let conn = tokio::spawn(
            Connection::new_with_peer(server, ctx.clone(), "10.0.0.10:1".into()).run(),
        );
        let mut client = client_framed(client);
        let mut seq = 0;
        do_handshake(&mut client, &mut seq).await;
        assert!(do_login(&mut client, &mut seq, "phraq", "s3cret").await.success);
        client
            .send(client_frame(PacketType::Disconnect, bump(&mut seq), Bytes::new()))
            .await
            .unwrap();
        conn.await.unwrap().unwrap();

        // Three failures and one login are audited, each with its source
        // (throttled refusals are not, so they can't flood the log).
        let entries = wait_for_history(&ctx, 4).await;
        let failed: Vec<_> = entries
            .iter()
            .filter(|e| e.action == "login_failed")
            .collect();
        assert_eq!(failed.len(), MAX_AUTH_ATTEMPTS as usize);
        assert!(failed
            .iter()
            .all(|e| e.detail.contains("peer=10.0.0.9:1234")));
        assert!(entries
            .iter()
            .any(|e| e.action == "login" && e.detail.contains("peer=10.0.0.10:1")));
    }

    #[tokio::test]
    async fn auth_phase_deadline_covers_blocked_writes() {
        let (ctx, _dir) = test_ctx().await;
        // Pause only after the DB is set up (sqlx dislikes a paused clock);
        // nothing below touches the database.
        tokio::time::pause();
        let (client, server) = tokio::io::duplex(1024);
        let conn = tokio::spawn(Connection::new(server, ctx).run());
        let mut client = client_framed(client);
        let mut seq = 0;
        do_handshake(&mut client, &mut seq).await;

        // Flood Pings and never read a Pong: the server blocks writing Pongs
        // into the full pipe. The auth deadline must still end it.
        let flood = tokio::spawn(async move {
            loop {
                let ping = client_frame(
                    PacketType::Ping,
                    bump(&mut seq),
                    Bytes::from(vec![7u8; 512]),
                );
                if client.send(ping).await.is_err() {
                    break;
                }
            }
        });
        let outcome = tokio::time::timeout(AUTH_TIMEOUT * 2, conn)
            .await
            .expect("connection outlived the auth deadline");
        // Whichever bound trips first (the 30 s per-write timeout or the
        // 60 s auth deadline), the stalled pre-auth connection must end.
        assert!(matches!(
            outcome.unwrap().unwrap_err(),
            ConnectionError::AuthTimeout | ConnectionError::WriteTimeout
        ));
        flood.abort();
    }

    #[tokio::test]
    async fn undeliverable_login_does_not_leak_a_session() {
        let (ctx, _dir) = test_ctx().await;
        let (client, server) = tokio::io::duplex(8192);
        let conn = tokio::spawn(Connection::new(server, ctx.clone()).run());
        let mut client = client_framed(client);
        let mut seq = 0;
        do_handshake(&mut client, &mut seq).await;

        // Answer the challenge correctly, then vanish before the result.
        let frame = send_auth_request(&mut client, &mut seq, "phraq").await;
        let challenge = AuthChallenge::decode(&frame.payload).unwrap();
        let proof = client_proof(
            "s3cret",
            &AuthContext {
                username: "phraq",
                challenge: &challenge.challenge,
                salt: &challenge.salt,
                params: kdx_crypto::KdfParams {
                    m_cost: challenge.m_cost,
                    t_cost: challenge.t_cost,
                    p_cost: challenge.p_cost,
                },
                channel_binding: &[0u8; kdx_crypto::CHANNEL_BINDING_LEN],
            },
        )
        .unwrap();
        client
            .send(client_frame(
                PacketType::AuthResponse,
                bump(&mut seq),
                AuthResponse {
                    response: proof.proof,
                }
                .encode(),
            ))
            .await
            .unwrap();
        drop(client);

        assert!(conn.await.unwrap().is_err());
        assert_eq!(ctx.auth.live_session_count(), 0);
    }

    #[tokio::test]
    async fn full_server_refuses_logins_but_not_admins() {
        let (ctx, _dir) = admin_test_ctx().await;
        ctx.settings
            .update("Test Server".into(), String::new(), String::new(), 1)
            .await
            .unwrap();

        let (client1, server1) = tokio::io::duplex(8192);
        let conn1 = tokio::spawn(Connection::new(server1, ctx.clone()).run());
        let mut client1 = client_framed(client1);
        let mut seq1 = 0;
        do_handshake(&mut client1, &mut seq1).await;
        assert!(do_login(&mut client1, &mut seq1, "plain", "s3cret").await.success);

        // A second ordinary login gets a clean refusal...
        let (client2, server2) = tokio::io::duplex(8192);
        let conn2 = tokio::spawn(Connection::new(server2, ctx.clone()).run());
        let mut client2 = client_framed(client2);
        let mut seq2 = 0;
        do_handshake(&mut client2, &mut seq2).await;
        let full = do_login(&mut client2, &mut seq2, "plain", "s3cret").await;
        assert!(!full.success);
        assert_eq!(full.message, "server is full");
        // ...but an admin still gets in.
        let admin = do_login(&mut client2, &mut seq2, "sysop", "s3cret").await;
        assert!(admin.success, "{}", admin.message);
        assert_eq!(ctx.auth.live_session_count(), 2);

        for (mut client, mut seq, conn) in [(client1, seq1, conn1), (client2, seq2, conn2)] {
            client
                .send(client_frame(PacketType::Disconnect, bump(&mut seq), Bytes::new()))
                .await
                .unwrap();
            conn.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn handshake_rejects_other_protocol_versions_in_the_payload() {
        let (ctx, _dir) = test_ctx().await;
        let (client, server) = tokio::io::duplex(4096);
        let conn = tokio::spawn(Connection::new(server, ctx).run());
        let mut client = client_framed(client);
        let init = HandshakeInit {
            version: 1,
            features: 0,
        };
        client
            .send(client_frame(PacketType::HandshakeInit, 0, init.encode()))
            .await
            .unwrap();
        assert!(matches!(
            conn.await.unwrap().unwrap_err(),
            ConnectionError::Protocol(ProtocolError::UnsupportedVersion(1))
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
        accounts::create(&pool, "sysop", &phc, 3, 0, 0).await.unwrap();
        accounts::create(&pool, "plain", &phc, 1, 0, 0).await.unwrap();
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
            login_limiter: crate::auth::LoginLimiter::new(),
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

    // Seam review #3: a tree change into a folder the caller may write but
    // not read succeeds, and the reply says so (an empty listing), instead
    // of an Error that makes the client retry into "name already exists".
    #[tokio::test]
    async fn tree_changes_into_a_write_only_folder_are_acknowledged() {
        let (ctx, _dir) = admin_test_ctx().await;
        seed(&ctx, "power", 2, Privileges::empty()).await;
        let (mut sysop, mut sseq, sysop_conn) = connect_as(&ctx, "sysop", "unknown").await;
        for (name, read) in [("inbox", BaseClass::Admin), ("pub", BaseClass::Guest)] {
            let create = FileCreateFolder {
                path: "/".into(),
                name: name.into(),
                kind: kdx_protocol::messages::KIND_DIR,
                min_read_class: read as u8,
                min_write_class: BaseClass::PowerUser as u8,
                owner: None,
            };
            let frame =
                send_and_recv(&mut sysop, &mut sseq, PacketType::FileCreateFolder, create.encode()).await;
            assert_eq!(frame.header.packet_type, PacketType::FileListResponse);
        }
        let pub_dir = ctx.tree.resolve("/pub").await.unwrap();
        for name in ["x", "y"] {
            ctx.tree.add_file(&pub_dir.id, name, 1, &[0u8; 32], "/nonexistent").await.unwrap();
        }
        hang_up(sysop, sseq, sysop_conn).await;

        let (mut power, mut seq, conn) = connect_as(&ctx, "power", "unknown").await;
        let changes = [
            (
                PacketType::FileMove,
                FileMove { path: "/pub/x".into(), dest_path: "/inbox".into() }.encode(),
            ),
            (
                PacketType::FileAlias,
                FileAlias { source_path: "/pub/y".into(), dest_path: "/inbox".into() }.encode(),
            ),
            (
                PacketType::FileCreateFolder,
                FileCreateFolder {
                    path: "/inbox".into(),
                    name: "sub".into(),
                    kind: kdx_protocol::messages::KIND_DIR,
                    min_read_class: 0,
                    min_write_class: 2,
                    owner: None,
                }
                .encode(),
            ),
        ];
        for (packet_type, payload) in changes {
            let frame = send_and_recv(&mut power, &mut seq, packet_type, payload).await;
            assert_eq!(
                frame.header.packet_type,
                PacketType::FileListResponse,
                "{packet_type:?} succeeded but was answered with {:?}",
                String::from_utf8_lossy(&frame.payload)
            );
            let listing = FileListResponse::decode(&frame.payload).unwrap();
            assert_eq!(listing.path, "/inbox");
            assert!(listing.entries.is_empty(), "nothing about /inbox may leak");
        }
        for path in ["/inbox/x", "/inbox/y", "/inbox/sub"] {
            assert!(ctx.tree.resolve(path).await.is_ok(), "{path} was not created");
        }
        // Where the caller can read the folder, the reply is its listing.
        let create = FileCreateFolder {
            path: "/pub".into(),
            name: "new".into(),
            kind: kdx_protocol::messages::KIND_DIR,
            min_read_class: 0,
            min_write_class: 2,
            owner: None,
        };
        let frame = send_and_recv(&mut power, &mut seq, PacketType::FileCreateFolder, create.encode()).await;
        let listing = FileListResponse::decode(&frame.payload).unwrap();
        assert_eq!(listing.path, "/pub");
        let names: Vec<_> = listing.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["new", "y"]);
        hang_up(power, seq, conn).await;
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
        /// the network address, and log in as `username`. Returns once the
        /// dispatch loop answers a Ping, so the server's post-login database
        /// work is done (tests may pause the clock next; sqlx misbehaves
        /// under a paused clock).
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
            ping(&mut client, &mut seq).await;
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
            rate_limited_ctx(0, rate).await
        }

        /// `test_ctx` with uploads and downloads throttled (bytes/sec).
        async fn rate_limited_ctx(upload: u64, download: u64) -> (Arc<ServerCtx>, tempfile::TempDir) {
            let (ctx, dir) = test_ctx().await;
            let mut inner = Arc::try_unwrap(ctx).ok().expect("sole owner of a fresh ctx");
            let pool = kdx_storage::connect(&dir.path().join("test.db")).await.unwrap();
            inner.transfers = TransferManager::new(
                pool,
                crate::transfer::TransferConfig {
                    files_root: dir.path().join("files"),
                    max_upload_bytes_per_sec: upload,
                    max_download_bytes_per_sec: download,
                },
            )
            .await
            .unwrap();
            (Arc::new(inner), dir)
        }

        /// `connect_as` with test hooks installed on the server side.
        async fn connect_hooked(
            ctx: &Arc<ServerCtx>,
            username: &str,
            hooks: TestHooks,
        ) -> (Client, u32, JoinHandle<Result<(), ConnectionError>>) {
            let (client, server) = tokio::io::duplex(1024 * 1024);
            let mut conn = Connection::new(server, ctx.clone());
            conn.hooks = hooks;
            let conn = tokio::spawn(conn.run());
            let mut client = client_framed(client);
            let mut seq = 0;
            do_handshake(&mut client, &mut seq).await;
            let login = do_login(&mut client, &mut seq, username, "s3cret").await;
            assert!(login.success, "{}", login.message);
            (client, seq, conn)
        }

        /// Start uploading `data` to `/name` in `chunk_size` chunks; returns
        /// the transfer id.
        async fn start_upload(
            client: &mut Client,
            seq: &mut u32,
            name: &str,
            data: &[u8],
            chunk_size: u32,
        ) -> [u8; 16] {
            let upload = TransferRequest {
                direction: kdx_protocol::messages::DIRECTION_UPLOAD,
                path: "/".into(),
                name: name.into(),
                size: data.len() as u64,
                chunk_size,
                sha256: sha2::Sha256::digest(data).into(),
                resume_id: [0; 16],
                have_bitmap: vec![],
            };
            request(client, seq, PacketType::FileTransferStart, upload.encode()).await;
            let accept = recv_type(client, PacketType::FileTransferStart).await;
            TransferAccept::decode(&accept.payload).unwrap().transfer_id
        }

        /// Send chunk `index` of `data` as a client does: fragmented, then
        /// its Ping barrier (token = the index).
        async fn send_chunk(
            client: &mut Client,
            seq: &mut u32,
            transfer_id: [u8; 16],
            data: &[u8],
            chunk_size: usize,
            index: u32,
        ) {
            let start = index as usize * chunk_size;
            let bytes = &data[start..(start + chunk_size).min(data.len())];
            let chunk = TransferData {
                transfer_id,
                chunk_index: index,
                chunk_hash: sha2::Sha256::digest(bytes).into(),
                data: Bytes::copy_from_slice(bytes),
            };
            let frames = kdx_protocol::fragment(
                PacketType::FileTransferData,
                PacketFlags::empty(),
                chunk.encode(),
                kdx_protocol::DEFAULT_MAX_FRAME_PAYLOAD,
                || bump(seq),
            );
            for frame in frames {
                client.feed(frame).await.unwrap();
            }
            let barrier = Bytes::copy_from_slice(&index.to_be_bytes());
            client
                .feed(client_frame(PacketType::Ping, bump(seq), barrier))
                .await
                .unwrap();
            client.flush().await.unwrap();
        }

        fn upload_data(len: usize) -> Vec<u8> {
            (0..len).map(|i| (i % 251) as u8).collect()
        }

        #[tokio::test]
        async fn pings_and_requests_are_answered_while_an_upload_finishes() {
            let (ctx, _dir) = test_ctx().await;
            let gate = Arc::new(Notify::new());
            let hooks = TestHooks {
                finish_gate: Some(gate.clone()),
                ..TestHooks::default()
            };
            let (mut client, mut seq, conn) = connect_hooked(&ctx, "phraq", hooks).await;
            let data = upload_data(8192);
            let id = start_upload(&mut client, &mut seq, "up.bin", &data, 4096).await;
            for index in 0..2 {
                send_chunk(&mut client, &mut seq, id, &data, 4096, index).await;
            }

            // Every chunk is in and verifying is held at the gate (think: a
            // 16 GiB hash on a slow disk). The barriers still come back...
            let mut reasm = Reassembler::default();
            let mut pongs = 0;
            while pongs < 2 {
                let frame = tokio::time::timeout(
                    Duration::from_secs(5),
                    recv_logical(&mut client, &mut reasm),
                )
                .await
                .expect("barrier Pongs must not wait for the verification");
                match frame.header.packet_type {
                    PacketType::Pong => pongs += 1,
                    PacketType::FileTransferEnd => panic!("finished before the gate opened"),
                    PacketType::Error => panic!("chunk refused: {}", error_text(&frame)),
                    _ => {}
                }
            }
            // ...and so do keepalives and ordinary requests.
            ping(&mut client, &mut seq).await;
            request(&mut client, &mut seq, PacketType::PresenceListRequest, PresenceListRequest.encode())
                .await;
            recv_type(&mut client, PacketType::PresenceListResponse).await;
            // A second upload must wait for this one.
            let again = TransferRequest {
                direction: kdx_protocol::messages::DIRECTION_UPLOAD,
                path: "/".into(),
                name: "other.bin".into(),
                size: 1,
                chunk_size: 4096,
                sha256: [0; 32],
                resume_id: [0; 16],
                have_bitmap: vec![],
            };
            request(&mut client, &mut seq, PacketType::FileTransferStart, again.encode()).await;
            let refused = recv_type(&mut client, PacketType::Error).await;
            assert_eq!(error_text(&refused), "a transfer is already active");

            // Once verified, the outcome arrives on its own.
            gate.notify_one();
            let end = recv_type(&mut client, PacketType::FileTransferEnd).await;
            let end = TransferEnd::decode(&end.payload).unwrap();
            assert_eq!((end.transfer_id, end.status), (id, TRANSFER_VERIFIED));
            assert_eq!(ctx.tree.resolve("/up.bin").await.unwrap().size, 8192);
            request(&mut client, &mut seq, PacketType::Disconnect, Bytes::new()).await;
            conn.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn a_kick_lands_mid_verification_and_the_upload_is_still_filed() {
            let (ctx, _dir) = test_ctx().await;
            let gate = Arc::new(Notify::new());
            let hooks = TestHooks {
                finish_gate: Some(gate.clone()),
                ..TestHooks::default()
            };
            let (mut client, mut seq, conn) = connect_hooked(&ctx, "phraq", hooks).await;
            let data = upload_data(4096);
            let id = start_upload(&mut client, &mut seq, "up.bin", &data, 4096).await;
            send_chunk(&mut client, &mut seq, id, &data, 4096, 0).await;
            recv_type(&mut client, PacketType::Pong).await;

            assert_eq!(ctx.presence.disconnect("phraq", "bye").await, 1);
            let bye = tokio::time::timeout(
                Duration::from_secs(5),
                recv_type(&mut client, PacketType::Disconnect),
            )
            .await
            .expect("a kick must not wait for the verification");
            assert_eq!(&bye.payload[..], b"bye");
            conn.await.unwrap().unwrap();

            // Verifying runs to completion without the connection.
            gate.notify_one();
            let filed = tokio::time::timeout(Duration::from_secs(10), async {
                while ctx.tree.resolve("/up.bin").await.is_err() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await;
            assert!(filed.is_ok(), "the verified upload was never filed");
        }

        #[tokio::test]
        async fn a_kick_does_not_wait_for_the_upload_throttle() {
            // 1 KiB/s with a 64 s burst: a 160 KiB chunk waits 96 s.
            let (ctx, _dir) = rate_limited_ctx(1024, 0).await;
            let (mut client, mut seq, conn, _) = connect_as(&ctx, 1024 * 1024, "unknown", "phraq").await;
            let data = upload_data(160 * 1024);
            let id = start_upload(&mut client, &mut seq, "slow.bin", &data, 256 * 1024).await;

            tokio::time::pause();
            let start = Instant::now();
            send_chunk(&mut client, &mut seq, id, &data, 256 * 1024, 0).await;
            let kicker = {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    ctx.presence.disconnect("phraq", "bye").await
                })
            };
            let bye = recv_type(&mut client, PacketType::Disconnect).await;
            assert_eq!(&bye.payload[..], b"bye");
            assert_eq!(kicker.await.unwrap(), 1);
            assert!(start.elapsed() < Duration::from_secs(5), "{:?}", start.elapsed());
            conn.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn a_waiting_frame_beats_an_overdue_idle_deadline() {
            // 1 KiB/s with a 64 s burst: a 160 KiB chunk waits 96 s, past the
            // 60 s idle timeout, while its barrier Ping sits unread.
            let (ctx, _dir) = rate_limited_ctx(1024, 0).await;
            // Keep `finish` (database work) out of the paused stretch.
            let gate = Arc::new(Notify::new());
            let hooks = TestHooks {
                finish_gate: Some(gate.clone()),
                ..TestHooks::default()
            };
            let (mut client, mut seq, conn) = connect_hooked(&ctx, "phraq", hooks).await;
            let data = upload_data(160 * 1024);
            let id = start_upload(&mut client, &mut seq, "slow.bin", &data, 256 * 1024).await;

            tokio::time::pause();
            let start = Instant::now();
            send_chunk(&mut client, &mut seq, id, &data, 256 * 1024, 0).await;
            let mut reasm = Reassembler::default();
            loop {
                let frame = recv_logical(&mut client, &mut reasm).await;
                match frame.header.packet_type {
                    PacketType::Pong => break,
                    PacketType::Disconnect => {
                        panic!("closed: {}", String::from_utf8_lossy(&frame.payload))
                    }
                    _ => {}
                }
            }
            assert!(start.elapsed() >= Duration::from_secs(90), "{:?}", start.elapsed());

            tokio::time::resume();
            gate.notify_one();
            let end = recv_type(&mut client, PacketType::FileTransferEnd).await;
            assert_eq!(TransferEnd::decode(&end.payload).unwrap().status, TRANSFER_VERIFIED);
            request(&mut client, &mut seq, PacketType::Disconnect, Bytes::new()).await;
            conn.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn chunks_in_flight_for_an_aborted_upload_get_no_errors() {
            let (ctx, _dir) = test_ctx().await;
            let hooks = TestHooks {
                fail_chunk: Some(1),
                ..TestHooks::default()
            };
            let (mut client, mut seq, conn) = connect_hooked(&ctx, "phraq", hooks).await;
            let data = upload_data(4 * 4096);
            let id = start_upload(&mut client, &mut seq, "up.bin", &data, 4096).await;
            // The client pipelines its window: every chunk (and its barrier)
            // is out before it hears that chunk 1 could not be stored.
            for index in 0..4 {
                send_chunk(&mut client, &mut seq, id, &data, 4096, index).await;
            }
            let mut reasm = Reassembler::default();
            let mut seen: Vec<String> = Vec::new();
            while seen.iter().filter(|s| s.starts_with("pong")).count() < 4 {
                let frame = recv_logical(&mut client, &mut reasm).await;
                match frame.header.packet_type {
                    PacketType::Pong => {
                        let token = u32::from_be_bytes(frame.payload[..].try_into().unwrap());
                        seen.push(format!("pong {token}"));
                    }
                    PacketType::FileTransferEnd => {
                        let end = TransferEnd::decode(&frame.payload).unwrap();
                        assert_eq!(end.transfer_id, id);
                        assert_eq!(end.status, kdx_protocol::messages::TRANSFER_ABORTED);
                        seen.push("end".into());
                    }
                    PacketType::Error => seen.push(format!("error {}", error_text(&frame))),
                    _ => {}
                }
            }
            // One TransferEnd, ahead of the failed chunk's barrier, and no
            // "no active transfer" error per chunk still in flight.
            assert_eq!(seen, ["pong 0", "end", "pong 1", "pong 2", "pong 3"]);
            request(&mut client, &mut seq, PacketType::Disconnect, Bytes::new()).await;
            conn.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn a_download_read_error_ends_only_the_transfer() {
            let (ctx, dir) = test_ctx().await;
            // The blob on disk is shorter than the size recorded for it.
            let path = dir.path().join("files").join("short.bin");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, vec![1u8; 10 * 1024]).unwrap();
            let root = ctx.tree.resolve("/").await.unwrap();
            ctx.tree
                .add_file(&root.id, "short.bin", 100 * 1024, &[7; 32], path.to_str().unwrap())
                .await
                .unwrap();

            let (mut client, mut seq, conn, _) = connect_as(&ctx, 256 * 1024, "unknown", "phraq").await;
            let download = TransferRequest {
                direction: DIRECTION_DOWNLOAD,
                path: "/".into(),
                name: "short.bin".into(),
                size: 0,
                chunk_size: 32 * 1024,
                sha256: [0; 32],
                resume_id: [0; 16],
                have_bitmap: vec![],
            };
            request(&mut client, &mut seq, PacketType::FileTransferStart, download.encode()).await;
            let accept = recv_type(&mut client, PacketType::FileTransferStart).await;
            let id = TransferAccept::decode(&accept.payload).unwrap().transfer_id;
            let end = recv_type(&mut client, PacketType::FileTransferEnd).await;
            let end = TransferEnd::decode(&end.payload).unwrap();
            assert_eq!(end.transfer_id, id);
            assert_eq!(end.status, kdx_protocol::messages::TRANSFER_ABORTED);
            // The session carries on.
            ping(&mut client, &mut seq).await;
            assert_eq!(ctx.presence.list().await.len(), 1);
            request(&mut client, &mut seq, PacketType::Disconnect, Bytes::new()).await;
            conn.await.unwrap().unwrap();
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
        async fn second_download_is_refused_and_cancel_stops_the_stream() {
            // 1 MiB at 64 KiB/s keeps the first download streaming for ~15 s.
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
            let transfer_id = TransferAccept::decode(&accept.payload).unwrap().transfer_id;

            // A second download on the same connection is refused, and the
            // first keeps streaming.
            request(&mut client, &mut seq, PacketType::FileTransferStart, download.encode()).await;
            let refused = recv_type(&mut client, PacketType::Error).await;
            assert_eq!(&refused.payload[..], b"a download is already active");

            // The client cancels: no more chunks, no TransferEnd, no Error.
            let cancel = TransferEnd {
                transfer_id,
                status: kdx_protocol::messages::TRANSFER_ABORTED,
                message: "cancelled".into(),
            };
            request(&mut client, &mut seq, PacketType::FileTransferEnd, cancel.encode()).await;
            let ping = client_frame(PacketType::Ping, bump(&mut seq), Bytes::from_static(b"after"));
            client.send(ping).await.unwrap();
            let mut reasm = Reassembler::default();
            let mut chunks_after_cancel = 0;
            loop {
                let frame = recv_logical(&mut client, &mut reasm).await;
                match frame.header.packet_type {
                    PacketType::Pong if &frame.payload[..] == b"after" => break,
                    // At most the chunk already in flight when the cancel landed.
                    PacketType::FileTransferData => chunks_after_cancel += 1,
                    PacketType::FileTransferEnd => panic!("cancelled download still finished"),
                    PacketType::Error => panic!("cancel was refused: {:?}", frame.payload),
                    _ => {}
                }
            }
            assert!(chunks_after_cancel <= 2, "{chunks_after_cancel} chunks after cancel");

            // The slot is free again: a new download starts.
            request(&mut client, &mut seq, PacketType::FileTransferStart, download.encode()).await;
            recv_type(&mut client, PacketType::FileTransferStart).await;
            client
                .send(client_frame(PacketType::Disconnect, bump(&mut seq), Bytes::new()))
                .await
                .unwrap();
            conn.await.unwrap().unwrap();
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

        /// `payload` as a fragmented `packet_type` message.
        fn fragmented(seq: &mut u32, packet_type: PacketType, payload: Bytes) -> Vec<KdxFrame> {
            kdx_protocol::fragment(
                packet_type,
                PacketFlags::empty(),
                payload,
                kdx_protocol::DEFAULT_MAX_FRAME_PAYLOAD,
                || bump(seq),
            )
        }

        /// A control message well past its cap: the cap trips mid-group.
        fn oversized_group(seq: &mut u32) -> Vec<KdxFrame> {
            let payload = Bytes::from(vec![b'x'; MAX_CONTROL_PAYLOAD + 20_000]);
            fragmented(seq, PacketType::ChatMessage, payload)
        }

        #[tokio::test]
        async fn control_messages_over_their_cap_get_an_error_not_a_disconnect() {
            let (ctx, _dir) = test_ctx().await;
            let (mut client, mut seq, conn, _) = connect_as(&ctx, 256 * 1024, "unknown", "phraq").await;
            // Over the cap by a lot (it trips mid-group, the rest is skipped),
            // and a longest-possible chat line, over it by a few bytes on
            // its last fragment.
            let line = ChatSend {
                room: "lobby".into(),
                flags: 0,
                text: "x".repeat(u16::MAX as usize),
            };
            let mut frames = oversized_group(&mut seq);
            frames.extend(fragmented(&mut seq, PacketType::ChatMessage, line.encode()));
            for frame in frames {
                client.feed(frame).await.unwrap();
            }
            let barrier = client_frame(PacketType::Ping, bump(&mut seq), Bytes::from_static(b"after"));
            client.feed(barrier).await.unwrap();
            client.flush().await.unwrap();

            // One Error per message, then the barrier's Pong.
            let mut reasm = Reassembler::default();
            let mut errors = Vec::new();
            loop {
                let frame = recv_logical(&mut client, &mut reasm).await;
                match frame.header.packet_type {
                    PacketType::Error => errors.push(error_text(&frame)),
                    PacketType::Pong => {
                        assert_eq!(&frame.payload[..], b"after");
                        break;
                    }
                    _ => {}
                }
            }
            assert_eq!(errors.len(), 2, "{errors:?}");
            assert!(errors.iter().all(|e| e.contains("too large")), "{errors:?}");
            ping(&mut client, &mut seq).await;
            assert_eq!(ctx.presence.list().await.len(), 1);
            request(&mut client, &mut seq, PacketType::Disconnect, Bytes::new()).await;
            conn.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn a_frame_cutting_into_a_skipped_group_is_still_fatal() {
            let (ctx, _dir) = test_ctx().await;
            let (mut client, mut seq, conn, _) = connect_as(&ctx, 256 * 1024, "unknown", "phraq").await;
            let mut frames = oversized_group(&mut seq);
            frames.truncate(frames.len() - 1); // the group never ends...
            for frame in frames {
                client.feed(frame).await.unwrap();
            }
            // ...before something else arrives.
            let ping = client_frame(PacketType::Ping, bump(&mut seq), Bytes::new());
            client.feed(ping).await.unwrap();
            client.flush().await.unwrap();
            assert!(matches!(
                conn.await.unwrap(),
                Err(ConnectionError::Protocol(ProtocolError::FragmentInterleaved))
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
        async fn upload_chunk_barriers_are_not_paced() {
            // The client follows every upload chunk with a Ping barrier; with
            // an upload active those must not be throttled like a flood.
            let (ctx, _dir) = test_ctx().await;
            let (mut client, mut seq, conn, _) = connect_as(&ctx, 256 * 1024, "unknown", "phraq").await;
            let data = vec![5u8; 64 * 1024];
            let upload = TransferRequest {
                direction: kdx_protocol::messages::DIRECTION_UPLOAD,
                path: "/".into(),
                name: "up.bin".into(),
                size: data.len() as u64,
                chunk_size: 4096,
                sha256: sha2::Sha256::digest(&data).into(),
                resume_id: [0; 16],
                have_bitmap: vec![],
            };
            request(&mut client, &mut seq, PacketType::FileTransferStart, upload.encode()).await;
            recv_type(&mut client, PacketType::FileTransferStart).await;

            tokio::time::pause();
            let start = Instant::now();
            for _ in 0..200 {
                client
                    .feed(client_frame(PacketType::Ping, bump(&mut seq), Bytes::new()))
                    .await
                    .unwrap();
            }
            client.flush().await.unwrap();
            for _ in 0..200 {
                recv_type(&mut client, PacketType::Pong).await;
            }
            // Paced, 150 pings past the burst would take 7.5 s.
            let elapsed = start.elapsed();
            assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
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

    // ---- logins in flight (L-A, L-B, L-D) ----

    /// Answer the `AuthChallenge` in `challenge` with `password`'s proof and
    /// return the server's `AuthResult`.
    async fn answer_challenge(
        client: &mut Client,
        seq: &mut u32,
        username: &str,
        password: &str,
        challenge: &KdxFrame,
    ) -> AuthResult {
        assert_eq!(challenge.header.packet_type, PacketType::AuthChallenge);
        let challenge = AuthChallenge::decode(&challenge.payload).unwrap();
        let proof = client_proof(
            password,
            &AuthContext {
                username,
                challenge: &challenge.challenge,
                salt: &challenge.salt,
                params: kdx_crypto::KdfParams {
                    m_cost: challenge.m_cost,
                    t_cost: challenge.t_cost,
                    p_cost: challenge.p_cost,
                },
                channel_binding: &[0u8; kdx_crypto::CHANNEL_BINDING_LEN],
            },
        )
        .unwrap();
        let response = AuthResponse {
            response: proof.proof,
        };
        client
            .send(client_frame(PacketType::AuthResponse, bump(seq), response.encode()))
            .await
            .unwrap();
        let frame = client.next().await.unwrap().unwrap();
        assert_eq!(frame.header.packet_type, PacketType::AuthResult);
        AuthResult::decode(&frame.payload).unwrap()
    }

    /// The reason in the server's next `Disconnect`, skipping other frames.
    async fn disconnect_reason(client: &mut Client) -> String {
        loop {
            let frame = timeout(Duration::from_secs(5), client.next())
                .await
                .expect("the server should close promptly")
                .expect("stream open")
                .expect("valid frame");
            if frame.header.packet_type == PacketType::Disconnect {
                return String::from_utf8_lossy(&frame.payload).into_owned();
            }
        }
    }

    /// Start a login on a fresh connection from `peer` and stop at the
    /// challenge, as a client sitting on its proof would.
    async fn pending_login(
        ctx: &Arc<ServerCtx>,
        peer: &str,
        username: &str,
    ) -> (Client, u32, ConnTask, KdxFrame) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let conn = tokio::spawn(
            Connection::new_with_peer(server, ctx.clone(), peer.to_string()).run(),
        );
        let mut client = client_framed(client);
        let mut seq = 0;
        do_handshake(&mut client, &mut seq).await;
        let challenge = send_auth_request(&mut client, &mut seq, username).await;
        (client, seq, conn, challenge)
    }

    #[tokio::test]
    async fn demotion_while_a_login_is_pending_applies_to_it() {
        let (ctx, _dir) = admin_test_ctx().await;
        seed(&ctx, "deputy", 3, Privileges::empty()).await;
        let (mut client, mut seq, conn, challenge) = pending_login(&ctx, "unknown", "deputy").await;

        // Demoted while the proof is outstanding: the kick reaches no one.
        ctx.auth.update_account("deputy", 1, 0, 0).await.unwrap();
        assert_eq!(ctx.presence.disconnect("deputy", policy::PRIVILEGES_CHANGED).await, 0);

        let result = answer_challenge(&mut client, &mut seq, "deputy", "s3cret", &challenge).await;
        assert!(result.success, "{}", result.message);
        assert_eq!(result.class, BaseClass::User as u8);
        let frame = send_and_recv(
            &mut client,
            &mut seq,
            PacketType::ServerSettingsRequest,
            ServerSettingsRequest.encode(),
        )
        .await;
        assert_eq!(frame.header.packet_type, PacketType::Error, "admin rights survived the demotion");
        hang_up(client, seq, conn).await;
    }

    #[tokio::test]
    async fn deny_rule_while_a_login_is_pending_closes_it() {
        let (ctx, _dir) = admin_test_ctx().await;
        let (mut client, mut seq, conn, challenge) = pending_login(&ctx, "10.0.0.5:1", "plain").await;

        // The rule lands while the proof is outstanding; enforcing it on
        // live sessions can't reach this one yet.
        ctx.ip_rules
            .create(10, crate::ip_rules::Action::Deny, "10.0.0.0/8", "abuse", "sysop", unix_now())
            .await
            .unwrap();
        let kicked = ctx.ip_rules.disconnect_denied(&ctx.presence, ADDRESS_DENIED, "sysop").await;
        assert!(kicked.is_empty());

        let result = answer_challenge(&mut client, &mut seq, "plain", "s3cret", &challenge).await;
        assert!(result.success, "{}", result.message);
        assert_eq!(disconnect_reason(&mut client).await, ADDRESS_DENIED);
        conn.await.unwrap().unwrap();
        assert!(ctx.presence.list().await.is_empty());
        assert_eq!(ctx.auth.live_session_count(), 0);
    }

    /// A session as `AuthManager::complete` builds it (password "s3cret").
    async fn verified_session(ctx: &ServerCtx, username: &str) -> Session {
        let binding = [0u8; kdx_crypto::CHANNEL_BINDING_LEN];
        let (data, pending) = ctx.auth.begin(username, binding).await.unwrap();
        let proof = client_proof(
            "s3cret",
            &AuthContext {
                username,
                challenge: &data.challenge,
                salt: &data.salt,
                params: data.params,
                channel_binding: &binding,
            },
        )
        .unwrap();
        ctx.auth.complete(pending, &proof.proof).await.unwrap().session
    }

    #[tokio::test]
    async fn changes_between_proof_and_presence_are_caught_on_joining() {
        let (ctx, _dir) = admin_test_ctx().await;
        seed(&ctx, "deputy", 3, Privileges::empty()).await;
        seed(&ctx, "helper", 1, Privileges::empty()).await;
        // Sessions built by `complete`, before the changes below land.
        let plain = verified_session(&ctx, "plain").await;
        let deputy = verified_session(&ctx, "deputy").await;
        let helper = verified_session(&ctx, "helper").await;
        let (_client, server) = tokio::io::duplex(1024);
        let conn = Connection::new_with_peer(server, ctx.clone(), "192.0.2.7:1".into());
        for session in [&plain, &deputy, &helper] {
            assert_eq!(conn.stale_login_reason(session).await, None);
        }

        // Banned, demoted, or granted a role in that window.
        let id = ctx.auth.account_id("plain").await.unwrap().unwrap();
        ctx.auth
            .set_ban(&id, unix_now() as i64 + 1000, "spam", "sysop")
            .await
            .unwrap();
        let reason = conn.stale_login_reason(&plain).await.unwrap();
        assert!(reason.starts_with("banned until") && reason.ends_with("spam"), "{reason}");
        ctx.auth.update_account("deputy", 1, 0, 0).await.unwrap();
        assert_eq!(
            conn.stale_login_reason(&deputy).await.as_deref(),
            Some(policy::PRIVILEGES_CHANGED)
        );
        let role = ctx
            .roles
            .create("Mod", Privileges::USER_KICK, 5, None)
            .await
            .unwrap();
        let helper_id = ctx.auth.account_id("helper").await.unwrap().unwrap();
        ctx.roles.assign(&helper_id, role.id).await.unwrap();
        assert_eq!(
            conn.stale_login_reason(&helper).await.as_deref(),
            Some(policy::PRIVILEGES_CHANGED)
        );
    }

    #[tokio::test]
    async fn max_users_keeps_counting_sessions_older_than_the_ttl() {
        let (ctx, dir) = test_ctx().await;
        let mut inner = Arc::try_unwrap(ctx).ok().expect("sole owner of a fresh ctx");
        let pool = kdx_storage::connect(&dir.path().join("test.db")).await.unwrap();
        // A tiny session TTL that every session below outlives at once. (The
        // connection's idle timeout has a 60 s floor, so they stay online.)
        inner.auth = AuthManager::new(pool, Duration::from_millis(1));
        let ctx = Arc::new(inner);
        ctx.settings
            .update("Test Server".into(), String::new(), String::new(), 1)
            .await
            .unwrap();

        let (client1, server1) = tokio::io::duplex(8192);
        let conn1 = tokio::spawn(Connection::new(server1, ctx.clone()).run());
        let mut client1 = client_framed(client1);
        let mut seq1 = 0;
        do_handshake(&mut client1, &mut seq1).await;
        let first = do_login(&mut client1, &mut seq1, "phraq", "s3cret").await;
        assert!(first.success);
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Age doesn't end a live session (expiring it here, or in a periodic
        // sweep, used to drop it from the `max_users` count).
        assert!(ctx.auth.validate(Uuid::from_bytes(first.session_id)).is_some());
        assert_eq!(ctx.auth.live_session_count(), 1);

        let (client2, server2) = tokio::io::duplex(8192);
        let conn2 = tokio::spawn(Connection::new(server2, ctx.clone()).run());
        let mut client2 = client_framed(client2);
        let mut seq2 = 0;
        do_handshake(&mut client2, &mut seq2).await;
        let second = do_login(&mut client2, &mut seq2, "phraq", "s3cret").await;
        assert!(!second.success);
        assert_eq!(second.message, "server is full");

        drop(client2);
        let _ = conn2.await;
        hang_up(client1, seq1, conn1).await;
    }

    #[tokio::test]
    async fn shutdown_reaches_a_login_in_flight() {
        let (ctx, _dir) = test_ctx().await;
        let (mut client, mut seq, conn, challenge) = pending_login(&ctx, "unknown", "phraq").await;
        // The server starts shutting down while the proof is outstanding.
        assert_eq!(ctx.presence.disconnect_all("goodnight").await, 0);

        let result = answer_challenge(&mut client, &mut seq, "phraq", "s3cret", &challenge).await;
        assert!(result.success, "{}", result.message);
        assert_eq!(disconnect_reason(&mut client).await, "goodnight");
        conn.await.unwrap().unwrap();
        assert_eq!(ctx.auth.live_session_count(), 0);
    }
}
