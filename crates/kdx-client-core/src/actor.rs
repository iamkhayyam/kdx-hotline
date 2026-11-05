//! The connection actor: one task owning the TLS socket. It is the sole
//! reader and writer of the stream, owns the sequence counter, correlates
//! request/response pairs, drives the one active transfer, and turns
//! unsolicited server frames into events.
//!
//! # Request correlation
//!
//! The wire carries no request ids, but the server handles one connection's
//! requests strictly in order and writes each request's direct answer
//! before it reads the next request. Server-pushed events (chat, presence,
//! user lists, topics, invitations, Info/Warning broadcasts, transfer data)
//! never use a reply packet type or `Error`. So the actor keeps ONE queue,
//! [`Pending`], of everything it is owed, in send order:
//!
//! - **Requests** (`Pending::Reply`) always get exactly one answer: their
//!   reply type, or `Error`. An answer pops the head of the queue, which
//!   must be a request expecting that type (anything else is a protocol
//!   violation and closes the connection). An `Error` fails only the head.
//! - **Fire-and-forget commands** (join, leave, chat, topic, room flags,
//!   private message, invite, identity, broadcast, kick, shutdown, upload
//!   chunks, transfer abort) get either nothing or one `Error` (and some an
//!   `Info` ack, which stays an event). Because "nothing" can't be waited
//!   for, each one is followed by a `Ping` barrier carrying a token
//!   (`Pending::Barrier`): the server answers `[Error] Pong(token)`, so an
//!   `Error` that arrives while a barrier is at the head belongs to that
//!   barrier's command, and the `Pong` retires it. Keepalive pings are
//!   barriers with no command.
//! - An `Error` with nothing attributable at the head is unsolicited; like
//!   every `Error` it is also surfaced as `Event::ServerError` — except the
//!   refusals of chunks of an upload that has already ended (one per chunk
//!   still in flight), which only repeat the upload's own failure.
//! - Every request is checked against the server's reassembly cap for its
//!   type (`kdx_protocol::max_request_payload`) before it is written: the
//!   server drops the connection over an oversized message, so it fails
//!   only its caller here instead.
//!
//! Fire-and-forget calls still resolve as soon as they are written (their
//! errors arrive as `Event::ServerError`, as before), except where the
//! caller needs the outcome: `join` resolves when its barrier returns (with
//! the server's `Error`, if it refused), and `invite_to_chat` also waits for
//! the new room's id.
//!
//! A password change is two ordinary requests, issued one after the other
//! by `ClientHandle::change_password` (which runs the Argon2 work outside
//! the actor): `PasswordChangeBegin`, answered by `PasswordChangeChallenge`
//! or `Error`, then `PasswordChangeProof`, answered by
//! `PasswordChangeResult` or `Error`. The actor attaches the logged-in
//! username and the channel binding to the challenge, since the proof is
//! bound to both. Neither request is ever sent before login (the server
//! would treat it as a protocol violation during authentication).

use std::collections::{HashSet, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use bitvec::prelude::*;
use bytes::Bytes;
use futures_util::{FutureExt, SinkExt, StreamExt};
use kdx_crypto::{AuthContext, ClientProof, KdfParams};
use kdx_protocol::messages::{
    AccountSetPassword, PasswordChangeBegin, PasswordChangeChallenge, PasswordChangeProof,
    PasswordChangeResult,
};
use kdx_protocol::messages::{
    AccountCreate, AccountListRequest, AccountListResponse, AccountRolesRequest,
    AccountRolesResponse, AccountUpdate, AdminDisconnect, AuthChallenge, AuthRequest, AuthResponse,
    AdminBroadcast, AdminShutdown, AuthResult, BanListRequest, BanListResponse, BanRemove,
    ChatEvent, ChatInvite, ChatInvited, ChatJoin,
    ChatLeave, ChatSend, ChatTopic, ChatUserList, FileCatalogGenerated, FileCreateFolder,
    FileDelete, FileGenerateCatalog,
    ChatRoomFlags as WireChatRoomFlags, ConnectionListRequest, ConnectionListResponse, FileAlias,
    FileListRequest, FileMove, FileSearchRequest, FileSearchResponse, HistoryListRequest,
    HistoryListResponse, IpRuleCreate, IpRuleDelete, IpRuleListRequest, IpRuleListResponse,
    NewsPostCreate,
    NewsPostDelete, NewsThreadListRequest, NewsThreadListResponse, NewsgroupCreate,
    NewsgroupDelete, NewsgroupListRequest, NewsgroupListResponse, NewsgroupUpdate,
    ServerSettingsRequest, ServerSettingsResponse,
    ServerSettingsUpdate, TrackerListRequest, TrackerListResponse,
    FileInfoRequest, FileInfoResponse, FileListResponse, PresenceChange,
    PresenceListRequest, PresenceListResponse, PrivateMessage,
    PrivateSend, RoleAssign, RoleCreate, RoleDelete, RoleListRequest, RoleListResponse,
    RoleUnassign, RoleUpdate, SetIdentity, TransferAccept, TransferData, TransferEnd,
    TransferRequest,
    UserInfoRequest, UserInfoResponse, DIRECTION_DOWNLOAD, DIRECTION_UPLOAD, TRANSFER_ABORTED,
    TRANSFER_VERIFIED,
};
use kdx_protocol::{
    KdxCodec, KdxFrame, PacketFlags, PacketHeader, PacketType, Reassembler, PROTOCOL_VERSION,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{interval_at, sleep_until, Duration, Instant, MissedTickBehavior};
use tokio_util::codec::Framed;
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::config::{
    DEFAULT_KEEPALIVE, DEFAULT_REQUEST_TIMEOUT, DEFAULT_WRITE_TIMEOUT,
};
use crate::error::ClientError;
use crate::event::{
    AccountSummary, BanList, Direction, Event, FileSearchEntry, HistoryEntry, IpRule, NewsPost,
    NewsgroupInfo, PresenceUser, RoleInfo, ServerSettings, TrackerServer,
};
use crate::handle::{ChangeChallenge, ClientHandle, Command, Password, Session};
use crate::transfer::{
    bitmap_bytes, choose_chunk_size, chunk_len, create_transfers_dir, hash_download,
    prepare_upload, progress_bitmap, publish_download, validate_geometry, ChunkBitmap,
    PartialPaths, PreparedUpload, Publish, Sidecar, DEFAULT_CHUNK_SIZE,
};

#[cfg(test)]
mod tests;

/// Largest server message we reassemble.
const MAX_REASSEMBLED: usize = kdx_protocol::MAX_REASSEMBLED_PAYLOAD;
/// How long the courtesy `Disconnect` frame may take on the way out.
const GOODBYE_TIMEOUT: Duration = Duration::from_millis(500);
/// At most this many progress events per second per transfer (plus a
/// final one).
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);
/// Progress-event bitmaps are downsampled to at most this many bits.
const PROGRESS_MAX_BITS: usize = 1024;
/// Persist download resume state every this many chunks…
const SIDECAR_EVERY_CHUNKS: u32 = 64;
/// …or at least this often while chunks are arriving.
const SIDECAR_EVERY: Duration = Duration::from_secs(2);
/// Upload chunks in flight (written but not yet acknowledged by their
/// barrier `Pong`), bounded by bytes.
const UPLOAD_WINDOW_BYTES: u64 = 4 * 1024 * 1024;
/// A download is retried once for chunks the server skipped (e.g. because
/// a stale resume bitmap claimed them) before giving up.
const MAX_DOWNLOAD_ROUNDS: u8 = 2;
/// Cap on outstanding requests + barriers; a server that stops answering
/// while staying chatty can't grow the queue without bound.
const MAX_PENDING: usize = 4096;
/// Cap on invitations waiting for their room id.
const MAX_PENDING_INVITES: usize = 64;
/// How many abandoned transfer ids to remember (their late data / end
/// frames are ignored instead of being taken for the current transfer's).
const MAX_ABANDONED: usize = 16;

/// Knobs the actor needs from `ClientConfig`.
#[derive(Debug, Clone)]
pub(crate) struct ActorOptions {
    pub keepalive: Duration,
    pub request_timeout: Duration,
    pub write_timeout: Duration,
    /// `host:port`, recorded in download sidecars so a resume is only
    /// attempted against the same server.
    pub server_id: String,
    /// Where partial downloads and their resume sidecars live
    /// (`<data_dir>/transfers`). Downloads are refused without one: nothing
    /// is ever staged beside the destination.
    pub transfers_dir: Option<PathBuf>,
    /// How a verified download is moved into place (tests force the copy
    /// fallbacks).
    pub publish: Publish,
}

impl Default for ActorOptions {
    fn default() -> Self {
        Self {
            keepalive: DEFAULT_KEEPALIVE,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            server_id: String::new(),
            transfers_dir: None,
            publish: Publish::Auto,
        }
    }
}

/// A login in flight: which step we're waiting for and who to answer.
struct PendingLogin {
    username: String,
    /// Taken (and wiped on drop) as soon as the proof is computed.
    password: Option<Password>,
    /// Our proof, kept to check the server's signature in `AuthResult`.
    proof: Option<ClientProof>,
    phase: LoginPhase,
    reply: oneshot::Sender<Result<Session, ClientError>>,
}

enum LoginPhase {
    AwaitingChallenge,
    AwaitingResult,
}

type Reply<T> = oneshot::Sender<Result<T, ClientError>>;

/// A request waiting for its one reply (or `Error`).
enum Waiter {
    FileList(Reply<FileListResponse>),
    FileInfo(Reply<FileInfoResponse>),
    Catalog(Reply<u32>),
    Search(Reply<Vec<FileSearchEntry>>),
    Users(Reply<Vec<PresenceUser>>),
    UserInfo(Reply<PresenceUser>),
    Servers(Reply<Vec<TrackerServer>>),
    Settings(Reply<ServerSettings>),
    History(Reply<Vec<HistoryEntry>>),
    IpRules(Reply<Vec<IpRule>>),
    Connections(Reply<Vec<PresenceUser>>),
    Roles(Reply<Vec<RoleInfo>>),
    AccountRoles(Reply<Vec<String>>),
    Accounts(Reply<Vec<AccountSummary>>),
    Newsgroups(Reply<Vec<NewsgroupInfo>>),
    Thread(Reply<Vec<NewsPost>>),
    /// `BanListRequest` and `BanRemove`, both answered by a `BanListResponse`.
    Bans(Reply<BanList>),
    PasswordChallenge(Reply<ChangeChallenge>),
    PasswordChanged(Reply<PasswordChangeResult>),
    /// A `FileTransferStart` request, answered by a `TransferAccept` (sent
    /// as `FileTransferStart`) or `Error`. The caller's reply lives in the
    /// transfer itself; this is that transfer's generation.
    TransferStart(u64),
}

impl Waiter {
    fn expects(&self) -> PacketType {
        match self {
            Waiter::FileList(_) => PacketType::FileListResponse,
            Waiter::FileInfo(_) => PacketType::FileInfoResponse,
            Waiter::Catalog(_) => PacketType::FileCatalogGenerated,
            Waiter::Search(_) => PacketType::FileSearchResponse,
            Waiter::Users(_) => PacketType::PresenceListResponse,
            Waiter::UserInfo(_) => PacketType::UserInfoResponse,
            Waiter::Servers(_) => PacketType::TrackerListResponse,
            Waiter::Settings(_) => PacketType::ServerSettingsResponse,
            Waiter::History(_) => PacketType::HistoryListResponse,
            Waiter::IpRules(_) => PacketType::IpRuleListResponse,
            Waiter::Connections(_) => PacketType::ConnectionListResponse,
            Waiter::Roles(_) => PacketType::RoleListResponse,
            Waiter::AccountRoles(_) => PacketType::AccountRolesResponse,
            Waiter::Accounts(_) => PacketType::AccountListResponse,
            Waiter::Newsgroups(_) => PacketType::NewsgroupListResponse,
            Waiter::Thread(_) => PacketType::NewsThreadListResponse,
            Waiter::Bans(_) => PacketType::BanListResponse,
            Waiter::PasswordChallenge(_) => PacketType::PasswordChangeChallenge,
            Waiter::PasswordChanged(_) => PacketType::PasswordChangeResult,
            Waiter::TransferStart(_) => PacketType::FileTransferStart,
        }
    }

    fn fail(self, err: ClientError) {
        match self {
            Waiter::FileList(tx) => drop(tx.send(Err(err))),
            Waiter::FileInfo(tx) => drop(tx.send(Err(err))),
            Waiter::Catalog(tx) => drop(tx.send(Err(err))),
            Waiter::Search(tx) => drop(tx.send(Err(err))),
            Waiter::Users(tx) => drop(tx.send(Err(err))),
            Waiter::UserInfo(tx) => drop(tx.send(Err(err))),
            Waiter::Servers(tx) => drop(tx.send(Err(err))),
            Waiter::Settings(tx) => drop(tx.send(Err(err))),
            Waiter::History(tx) => drop(tx.send(Err(err))),
            Waiter::IpRules(tx) => drop(tx.send(Err(err))),
            Waiter::Connections(tx) => drop(tx.send(Err(err))),
            Waiter::Roles(tx) => drop(tx.send(Err(err))),
            Waiter::AccountRoles(tx) => drop(tx.send(Err(err))),
            Waiter::Accounts(tx) => drop(tx.send(Err(err))),
            Waiter::Newsgroups(tx) => drop(tx.send(Err(err))),
            Waiter::Thread(tx) => drop(tx.send(Err(err))),
            Waiter::Bans(tx) => drop(tx.send(Err(err))),
            Waiter::PasswordChallenge(tx) => drop(tx.send(Err(err))),
            Waiter::PasswordChanged(tx) => drop(tx.send(Err(err))),
            Waiter::TransferStart(_) => {}
        }
    }
}

/// Something the server owes us, in send order. See the module docs.
enum Pending {
    Reply(Waiter),
    Barrier { token: u64, quiet: Option<Quiet> },
}

/// The fire-and-forget command a barrier stands behind.
struct Quiet {
    kind: QuietKind,
    /// The `Error` the server answered it with, if any.
    error: Option<String>,
    /// A caller waiting for the outcome: answered when the barrier returns,
    /// with `Ok` or the server's `Error`.
    reply: Option<Reply<()>>,
}

impl Quiet {
    fn new(kind: QuietKind) -> Self {
        Self {
            kind,
            error: None,
            reply: None,
        }
    }
}

#[derive(Clone)]
enum QuietKind {
    Plain,
    /// A `ChatJoin`. `forget` is the room if this join added it to
    /// `known_rooms` (dropped again if the server refuses).
    Join { forget: Option<String> },
    Invite(u64),
    UploadChunk { gen: u64, len: u64, index: u32 },
}

/// An invitation waiting for its outcome and its room id.
struct InviteWait {
    id: u64,
    reply: Option<Reply<String>>,
    /// The server answered with an `Error` (the caller already got it).
    failed: bool,
    /// The barrier behind the invite has come back.
    settled: bool,
    room: Option<String>,
}

/// What to do with a download's on-disk state when it fails.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cleanup {
    /// Keep (and refresh) the resume sidecar and data for a later retry.
    Keep,
    /// The partial data is worthless: delete it and the sidecar.
    Discard,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Hashing the local file (uploads only).
    Preparing,
    /// Request written; waiting for the server's accept.
    AwaitingAccept { deadline: Instant },
    /// Accepted; data flowing.
    Running,
    /// All data received; verifying the whole-file hash, then moving the
    /// verified file to its destination (downloads only).
    Verifying,
}

/// The single active transfer, if any.
struct Transfer {
    /// Distinguishes this transfer from earlier ones whose late replies,
    /// barriers or blocking jobs may still arrive.
    gen: u64,
    reply: Option<Reply<()>>,
    cancel: Arc<AtomicBool>,
    stage: Stage,
    job: Job,
}

enum Job {
    Upload(UploadJob),
    Download(DownloadJob),
}

struct UploadJob {
    remote_dir: String,
    name: String,
    file: Option<tokio::fs::File>,
    size: u64,
    modified: Option<SystemTime>,
    sha256: [u8; 32],
    chunk_size: u32,
    total: u32,
    id: [u8; 16],
    /// Chunks the server already had at accept time.
    skip: ChunkBitmap,
    /// Chunks the server has acknowledged (plus `skip`).
    done: ChunkBitmap,
    next: u32,
    in_flight_bytes: u64,
    last_progress: Option<Instant>,
}

struct DownloadJob {
    remote_path: String,
    /// The destination; written only once, by the verified file.
    local: PathBuf,
    /// The partial's bytes and resume sidecar (in the transfers directory).
    /// Boxed to keep `Job`'s variants of similar size.
    partial: Box<PartialPaths>,
    expected_size: Option<u64>,
    requested_chunk: u32,
    /// Resume state that matched this server, remote path and destination
    /// at request time; consumed (and checked against the accept) on the
    /// first accept.
    resume: Option<Sidecar>,
    /// Geometry has been accepted at least once (identity known).
    accepted: bool,
    round: u8,
    file: Option<tokio::fs::File>,
    id: [u8; 16],
    size: u64,
    chunk_size: u32,
    total: u32,
    sha256: [u8; 32],
    have: ChunkBitmap,
    last_progress: Option<Instant>,
    unsaved_chunks: u32,
    last_sidecar: Instant,
    sidecar_task: Option<JoinHandle<()>>,
}

/// Blocking-pool work the actor is waiting on, polled from its select loop
/// so the actor stays responsive meanwhile.
enum Blocking {
    UploadPrep {
        gen: u64,
        task: JoinHandle<Result<PreparedUpload, ClientError>>,
    },
    Verify {
        gen: u64,
        task: JoinHandle<Result<[u8; 32], ClientError>>,
    },
    /// Moving a verified download to its destination (a copy can take a
    /// while across filesystems).
    Publish {
        gen: u64,
        task: JoinHandle<Result<(), ClientError>>,
    },
}

enum BlockingDone {
    UploadPrep(u64, Result<PreparedUpload, ClientError>),
    Verify(u64, Result<[u8; 32], ClientError>),
    Publish(u64, Result<(), ClientError>),
}

async fn poll_blocking(slot: &mut Option<Blocking>) -> BlockingDone {
    fn flat<T>(r: Result<Result<T, ClientError>, tokio::task::JoinError>) -> Result<T, ClientError> {
        r.unwrap_or_else(|e| Err(ClientError::Transfer(format!("internal error: {e}"))))
    }
    match slot {
        Some(Blocking::UploadPrep { gen, task }) => BlockingDone::UploadPrep(*gen, flat(task.await)),
        Some(Blocking::Verify { gen, task }) => BlockingDone::Verify(*gen, flat(task.await)),
        Some(Blocking::Publish { gen, task }) => BlockingDone::Publish(*gen, flat(task.await)),
        None => std::future::pending().await,
    }
}

/// Resolve once a disconnect has been requested (or every handle is gone).
async fn wait_shutdown(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Why a write didn't happen.
#[derive(Debug)]
pub(crate) enum SendError {
    /// The socket is unusable; the connection must close.
    Fatal(io::Error),
    /// This one request can't be sent (e.g. too large); nothing was
    /// written and the session is unaffected.
    Rejected(ClientError),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::Fatal(e) => write!(f, "{e}"),
            SendError::Rejected(e) => write!(f, "{e}"),
        }
    }
}

impl From<SendError> for ClientError {
    fn from(e: SendError) -> Self {
        match e {
            SendError::Fatal(e) => ClientError::Io(e),
            SendError::Rejected(e) => e,
        }
    }
}

pub(crate) struct Actor<S> {
    framed: Framed<S, KdxCodec>,
    commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
    opts: ActorOptions,
    shutdown: watch::Receiver<bool>,
    /// Held until `spawn` hands it to the `ClientHandle`.
    shutdown_tx: Option<watch::Sender<bool>>,
    reasm: Reassembler,
    seq: u32,
    login: Option<PendingLogin>,
    /// A login succeeded on this connection; another one is refused (the
    /// server has no answer for a second `AuthRequest`).
    authenticated: bool,
    /// The username that logged in (password-change proofs are bound to it).
    username: Option<String>,
    pending: VecDeque<Pending>,
    next_token: u64,
    invites: VecDeque<InviteWait>,
    next_invite: u64,
    /// Rooms this client joined itself (so their user lists aren't taken
    /// for a fresh invitation room).
    known_rooms: HashSet<String>,
    transfer: Option<Transfer>,
    /// TLS exporter value login proofs are bound to (see `kdx_crypto::scram`).
    channel_binding: [u8; kdx_crypto::CHANNEL_BINDING_LEN],
    next_gen: u64,
    /// Server transfer ids we gave up on; see `MAX_ABANDONED`.
    abandoned: VecDeque<[u8; 16]>,
    blocking: Option<Blocking>,
    last_inbound: Instant,
    /// Set when the connection must close but the code that noticed can't
    /// return the error; checked at the top of every loop turn.
    dead: Option<String>,
    /// Tearing down: don't write anything else.
    closing: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Actor<S> {
    pub(crate) fn new(
        framed: Framed<S, KdxCodec>,
        commands: mpsc::Receiver<Command>,
        events: mpsc::Sender<Event>,
    ) -> Self {
        let (shutdown_tx, shutdown) = watch::channel(false);
        Self {
            framed,
            commands,
            events,
            opts: ActorOptions::default(),
            shutdown,
            shutdown_tx: Some(shutdown_tx),
            reasm: Reassembler::default(),
            seq: 0,
            login: None,
            authenticated: false,
            username: None,
            pending: VecDeque::new(),
            next_token: 0,
            invites: VecDeque::new(),
            next_invite: 0,
            known_rooms: HashSet::new(),
            transfer: None,
            channel_binding: [0u8; kdx_crypto::CHANNEL_BINDING_LEN],
            next_gen: 0,
            abandoned: VecDeque::new(),
            blocking: None,
            last_inbound: Instant::now(),
            dead: None,
            closing: false,
        }
    }

    /// Bind logins to the TLS session: `binding` is this connection's
    /// `export_keying_material(32, kdx_crypto::TLS_EXPORTER_LABEL, None)`.
    /// Without it (in-memory tests) the binding is all zeros.
    pub(crate) fn with_channel_binding(
        mut self,
        binding: [u8; kdx_crypto::CHANNEL_BINDING_LEN],
    ) -> Self {
        self.channel_binding = binding;
        self
    }

    pub(crate) fn with_options(mut self, opts: ActorOptions) -> Self {
        self.opts = opts;
        self
    }

    /// Start the actor under supervision and return the handle that drives
    /// it. If the actor task panics, the supervisor still emits
    /// `Event::Disconnected` so the application learns the session is gone.
    pub(crate) fn spawn(mut self, commands: mpsc::Sender<Command>) -> ClientHandle
    where
        S: Send + 'static,
    {
        let shutdown = self
            .shutdown_tx
            .take()
            .unwrap_or_else(|| {
                let (tx, rx) = watch::channel(false);
                self.shutdown = rx;
                tx
            });
        let handle = ClientHandle {
            tx: commands,
            shutdown: Arc::new(shutdown),
            request_timeout: self.opts.request_timeout,
            password_change: Arc::default(),
        };
        let events = self.events.clone();
        let task = tokio::spawn(self.run());
        tokio::spawn(async move {
            if let Err(e) = task.await {
                if e.is_panic() {
                    error!("connection actor panicked");
                    let _ = events
                        .send(Event::Disconnected {
                            reason: "internal error".into(),
                        })
                        .await;
                }
            }
        });
        handle
    }

    pub(crate) async fn run(mut self) {
        let start = Instant::now() + self.opts.keepalive;
        let mut keepalive = interval_at(start, self.opts.keepalive);
        keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
        self.last_inbound = Instant::now();

        let reason = loop {
            if let Some(reason) = self.dead.take() {
                break reason;
            }
            let idle_deadline = self.last_inbound + self.opts.keepalive * 2;
            let accept_deadline = self.accept_deadline();
            let can_send_chunk = self.upload_can_send();
            let blocking_active = self.blocking.is_some();

            tokio::select! {
                _ = wait_shutdown(&mut self.shutdown) => {
                    self.goodbye().await;
                    break "disconnected".to_string();
                }
                cmd = self.commands.recv() => {
                    match cmd {
                        None => {
                            self.goodbye().await;
                            break "disconnected".to_string();
                        }
                        Some(cmd) => {
                            if let Err(SendError::Fatal(e)) = self.handle_command(cmd).await {
                                break format!("write failed: {e}");
                            }
                        }
                    }
                }
                frame = self.framed.next() => {
                    match frame {
                        Some(Ok(frame)) => {
                            if let Err(reason) = self.on_frame(frame).await {
                                break reason;
                            }
                        }
                        Some(Err(e)) => break format!("stream error: {e}"),
                        None => break "connection closed by server".to_string(),
                    }
                }
                _ = keepalive.tick() => {
                    // No pings mid-login: the server expects the very next
                    // packet after its challenge to be our response.
                    if self.login.is_none() {
                        if let Err(e) = self.send_barrier(None).await {
                            break format!("keepalive write failed: {e}");
                        }
                    }
                }
                _ = sleep_until(idle_deadline) => {
                    // Something may already be buffered while we were busy;
                    // only a server that has sent nothing at all is dead.
                    match self.framed.next().now_or_never() {
                        Some(Some(Ok(frame))) => {
                            if let Err(reason) = self.on_frame(frame).await {
                                break reason;
                            }
                        }
                        Some(Some(Err(e))) => break format!("stream error: {e}"),
                        Some(None) => break "connection closed by server".to_string(),
                        None => break "server stopped responding".to_string(),
                    }
                }
                done = poll_blocking(&mut self.blocking), if blocking_active => {
                    self.blocking = None;
                    self.on_blocking_done(done).await;
                }
                _ = std::future::ready(()), if can_send_chunk => {
                    self.send_next_chunk().await;
                }
                _ = sleep_until(accept_deadline.unwrap_or(idle_deadline)), if accept_deadline.is_some() => {
                    let err = ClientError::Timeout("the server did not accept the transfer".into());
                    self.fail_transfer(err, Cleanup::Keep).await;
                }
            }
        };

        // A write abandoned because the user asked to disconnect is just
        // that: a disconnect.
        let reason = if *self.shutdown.borrow() {
            "disconnected".to_string()
        } else {
            reason
        };
        self.closing = true;
        // Fail any outstanding waiters, then announce the disconnect.
        if let Some(login) = self.login.take() {
            let _ = login.reply.send(Err(ClientError::Disconnected));
        }
        for pending in self.pending.drain(..) {
            match pending {
                Pending::Reply(waiter) => waiter.fail(ClientError::Disconnected),
                Pending::Barrier {
                    quiet: Some(Quiet {
                        reply: Some(reply), ..
                    }),
                    ..
                } => drop(reply.send(Err(ClientError::Disconnected))),
                Pending::Barrier { .. } => {}
            }
        }
        for invite in self.invites.drain(..) {
            if let Some(reply) = invite.reply {
                let _ = reply.send(Err(ClientError::Disconnected));
            }
        }
        self.fail_transfer(ClientError::Disconnected, Cleanup::Keep).await;
        let events = self.events.clone();
        drop(self); // close the socket before (possibly) waiting on the UI
        let _ = events.send(Event::Disconnected { reason }).await;
    }

    async fn on_frame(&mut self, frame: KdxFrame) -> Result<(), String> {
        self.last_inbound = Instant::now();
        match self.reasm.push(frame, MAX_REASSEMBLED) {
            Ok(Some(full)) => self
                .handle_frame(full)
                .await
                .map_err(|e| format!("protocol error: {e}")),
            Ok(None) => Ok(()), // mid-fragment
            Err(e) => Err(format!("framing error: {e}")),
        }
    }

    async fn handle_command(&mut self, cmd: Command) -> Result<(), SendError> {
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
                if self.authenticated {
                    let _ = reply.send(Err(ClientError::InvalidInput("already logged in".into())));
                    return Ok(());
                }
                self.send(
                    PacketType::AuthRequest,
                    AuthRequest {
                        username: username.clone(),
                    }
                    .encode(),
                )
                .await?;
                self.login = Some(PendingLogin {
                    username,
                    password: Some(password),
                    proof: None,
                    phase: LoginPhase::AwaitingChallenge,
                    reply,
                });
            }
            Command::Join { room, reply } => {
                // The server answers a join with nothing (admitted) or an
                // Error (refused), so the caller waits for the barrier.
                let forget = self.known_rooms.insert(room.clone()).then(|| room.clone());
                let quiet = Quiet {
                    reply: Some(reply),
                    ..Quiet::new(QuietKind::Join { forget })
                };
                self.send_answered(PacketType::ChatJoin, ChatJoin { room }.encode(), quiet)
                    .await?;
            }
            Command::Leave { room, reply } => {
                self.known_rooms.remove(&room);
                self.quiet(PacketType::ChatLeave, ChatLeave { room }.encode(), reply)
                    .await?;
            }
            Command::SendChat {
                room,
                flags,
                text,
                reply,
            } => {
                let msg = ChatSend { room, flags, text };
                self.quiet(PacketType::ChatMessage, msg.encode(), reply).await?;
            }
            Command::SetTopic { room, topic, reply } => {
                let msg = ChatTopic { room, topic };
                self.quiet(PacketType::ChatTopicSet, msg.encode(), reply).await?;
            }
            Command::ListFiles { path, reply } => {
                let msg = FileListRequest { path };
                self.request(PacketType::FileListRequest, msg.encode(), Waiter::FileList(reply))
                    .await?;
            }
            Command::CreateFolder {
                path,
                name,
                kind,
                min_read_class,
                min_write_class,
                owner,
                reply,
            } => {
                let msg = FileCreateFolder {
                    path,
                    name,
                    kind,
                    min_read_class,
                    min_write_class,
                    owner,
                };
                self.request(PacketType::FileCreateFolder, msg.encode(), Waiter::FileList(reply))
                    .await?;
            }
            Command::DeletePath { path, reply } => {
                let msg = FileDelete { path };
                self.request(PacketType::FileDelete, msg.encode(), Waiter::FileList(reply))
                    .await?;
            }
            Command::MovePath {
                path,
                dest_path,
                reply,
            } => {
                let msg = FileMove { path, dest_path };
                self.request(PacketType::FileMove, msg.encode(), Waiter::FileList(reply))
                    .await?;
            }
            Command::GetFileInfo { path, reply } => {
                let msg = FileInfoRequest { path };
                self.request(PacketType::FileInfoRequest, msg.encode(), Waiter::FileInfo(reply))
                    .await?;
            }
            Command::SetIdentity { name, description } => {
                let msg = SetIdentity { name, description };
                let quiet = Quiet::new(QuietKind::Plain);
                match self.send_quiet(PacketType::SetIdentity, msg.encode(), quiet).await {
                    Err(SendError::Fatal(e)) => return Err(SendError::Fatal(e)),
                    Err(SendError::Rejected(e)) => warn!("identity not sent: {e}"),
                    Ok(()) => {}
                }
            }
            Command::AliasPath {
                source_path,
                dest_path,
                reply,
            } => {
                let msg = FileAlias { source_path, dest_path };
                self.request(PacketType::FileAlias, msg.encode(), Waiter::FileList(reply))
                    .await?;
            }
            Command::GenerateCatalog { reply } => {
                let msg = FileGenerateCatalog;
                self.request(PacketType::FileGenerateCatalog, msg.encode(), Waiter::Catalog(reply))
                    .await?;
            }
            Command::SearchFiles { query, reply } => {
                let msg = FileSearchRequest { query };
                self.request(PacketType::FileSearchRequest, msg.encode(), Waiter::Search(reply))
                    .await?;
            }
            Command::ListUsers { reply } => {
                let msg = PresenceListRequest;
                self.request(PacketType::PresenceListRequest, msg.encode(), Waiter::Users(reply))
                    .await?;
            }
            Command::ListServers { filter, reply } => {
                let msg = TrackerListRequest { filter };
                self.request(PacketType::TrackerListRequest, msg.encode(), Waiter::Servers(reply))
                    .await?;
            }
            Command::GetServerSettings { reply } => {
                let msg = ServerSettingsRequest;
                let waiter = Waiter::Settings(reply);
                self.request(PacketType::ServerSettingsRequest, msg.encode(), waiter)
                    .await?;
            }
            Command::UpdateServerSettings {
                name,
                description,
                greeting,
                max_users,
                reply,
            } => {
                let msg = ServerSettingsUpdate {
                    name,
                    description,
                    greeting,
                    max_users,
                };
                let waiter = Waiter::Settings(reply);
                self.request(PacketType::ServerSettingsUpdate, msg.encode(), waiter)
                    .await?;
            }
            Command::Broadcast { text, reply } => {
                let msg = AdminBroadcast { text };
                self.quiet(PacketType::AdminBroadcast, msg.encode(), reply).await?;
            }
            Command::ShutdownServer { message, reply } => {
                let msg = AdminShutdown { message };
                self.quiet(PacketType::AdminShutdown, msg.encode(), reply).await?;
            }
            Command::ListHistory { limit, reply } => {
                let msg = HistoryListRequest { limit };
                self.request(PacketType::HistoryListRequest, msg.encode(), Waiter::History(reply))
                    .await?;
            }
            Command::ListIpRules { reply } => {
                let msg = IpRuleListRequest;
                self.request(PacketType::IpRuleListRequest, msg.encode(), Waiter::IpRules(reply))
                    .await?;
            }
            Command::CreateIpRule {
                position,
                action,
                cidr,
                note,
                reply,
            } => {
                let msg = IpRuleCreate {
                    position,
                    action,
                    cidr,
                    note,
                };
                self.request(PacketType::IpRuleCreate, msg.encode(), Waiter::IpRules(reply))
                    .await?;
            }
            Command::DeleteIpRule { id, reply } => {
                let msg = IpRuleDelete { id };
                self.request(PacketType::IpRuleDelete, msg.encode(), Waiter::IpRules(reply))
                    .await?;
            }
            Command::ListConnections { reply } => {
                let msg = ConnectionListRequest;
                let waiter = Waiter::Connections(reply);
                self.request(PacketType::ConnectionListRequest, msg.encode(), waiter)
                    .await?;
            }
            Command::SetRoomFlags {
                room,
                min_class_join,
                interview_mode,
                reply,
            } => {
                let msg = WireChatRoomFlags {
                    room,
                    min_class_join,
                    interview_mode,
                };
                // Fire-and-forget over the wire: server acks by broadcasting
                // a room-system message to every joined member (including
                // us). No dedicated response, matching how ChatTopicSet
                // already works.
                self.quiet(PacketType::ChatRoomFlags, msg.encode(), reply).await?;
            }
            Command::GetUserInfo { username, reply } => {
                let msg = UserInfoRequest { username };
                self.request(PacketType::UserInfoRequest, msg.encode(), Waiter::UserInfo(reply))
                    .await?;
            }
            Command::SendPrivate { to, text, reply } => {
                let msg = PrivateSend { to, text };
                self.quiet(PacketType::PrivateSend, msg.encode(), reply).await?;
            }
            Command::InviteToChat { to, reply } => self.start_invite(to, reply).await?,
            Command::Upload {
                local,
                remote_dir,
                reply,
            } => self.start_upload(local, remote_dir, reply),
            Command::Download {
                remote_path,
                local,
                expected_size,
                reply,
            } => self.start_download(remote_path, local, expected_size, reply).await?,
            Command::CancelTransfer { reply } => {
                let active = self.transfer.is_some();
                if active {
                    let err = ClientError::Transfer("cancelled".into());
                    self.fail_transfer(err, Cleanup::Keep).await;
                }
                let _ = reply.send(Ok(active));
            }
            Command::ListRoles { reply } => {
                let msg = RoleListRequest;
                self.request(PacketType::RoleListRequest, msg.encode(), Waiter::Roles(reply))
                    .await?;
            }
            Command::CreateRole {
                name,
                privileges,
                rank,
                color,
                reply,
            } => {
                let msg = RoleCreate {
                    name,
                    privileges,
                    rank,
                    color,
                };
                self.request(PacketType::RoleCreate, msg.encode(), Waiter::Roles(reply))
                    .await?;
            }
            Command::UpdateRole {
                id,
                name,
                privileges,
                rank,
                color,
                reply,
            } => {
                let Some(id) = parse_role_id(&id) else {
                    let _ = reply.send(Err(ClientError::InvalidInput("bad role id".into())));
                    return Ok(());
                };
                let msg = RoleUpdate {
                    id,
                    name,
                    privileges,
                    rank,
                    color,
                };
                self.request(PacketType::RoleUpdate, msg.encode(), Waiter::Roles(reply))
                    .await?;
            }
            Command::DeleteRole { id, reply } => {
                let Some(id) = parse_role_id(&id) else {
                    let _ = reply.send(Err(ClientError::InvalidInput("bad role id".into())));
                    return Ok(());
                };
                let msg = RoleDelete { id };
                self.request(PacketType::RoleDelete, msg.encode(), Waiter::Roles(reply))
                    .await?;
            }
            Command::AssignRole {
                username,
                role_id,
                reply,
            } => {
                let Some(role_id) = parse_role_id(&role_id) else {
                    let _ = reply.send(Err(ClientError::InvalidInput("bad role id".into())));
                    return Ok(());
                };
                let msg = RoleAssign { username, role_id };
                self.request(PacketType::RoleAssign, msg.encode(), Waiter::Roles(reply))
                    .await?;
            }
            Command::UnassignRole {
                username,
                role_id,
                reply,
            } => {
                let Some(role_id) = parse_role_id(&role_id) else {
                    let _ = reply.send(Err(ClientError::InvalidInput("bad role id".into())));
                    return Ok(());
                };
                let msg = RoleUnassign { username, role_id };
                self.request(PacketType::RoleUnassign, msg.encode(), Waiter::Roles(reply))
                    .await?;
            }
            Command::AccountRoles { username, reply } => {
                let msg = AccountRolesRequest { username };
                let waiter = Waiter::AccountRoles(reply);
                self.request(PacketType::AccountRolesRequest, msg.encode(), waiter)
                    .await?;
            }
            Command::DisconnectUser {
                username,
                reason,
                ban_secs,
                reply,
            } => {
                let msg = AdminDisconnect {
                    username,
                    reason,
                    ban_secs,
                };
                self.quiet(PacketType::AdminDisconnect, msg.encode(), reply).await?;
            }
            Command::ListAccounts { reply } => {
                let msg = AccountListRequest;
                self.request(PacketType::AccountListRequest, msg.encode(), Waiter::Accounts(reply))
                    .await?;
            }
            Command::CreateAccount {
                username,
                credential,
                base_class,
                granted,
                revoked,
                reply,
            } => {
                let msg = AccountCreate {
                    username,
                    credential,
                    base_class,
                    granted,
                    revoked,
                };
                self.request(PacketType::AccountCreate, msg.encode(), Waiter::Accounts(reply))
                    .await?;
            }
            Command::UpdateAccount {
                username,
                base_class,
                granted,
                revoked,
                reply,
            } => {
                let msg = AccountUpdate {
                    username,
                    base_class,
                    granted,
                    revoked,
                };
                self.request(PacketType::AccountUpdate, msg.encode(), Waiter::Accounts(reply))
                    .await?;
            }
            Command::SetAccountPassword {
                username,
                credential,
                reply,
            } => {
                let msg = AccountSetPassword {
                    username,
                    credential,
                };
                let waiter = Waiter::Accounts(reply);
                self.request(PacketType::AccountSetPassword, msg.encode(), waiter)
                    .await?;
            }
            Command::BeginPasswordChange { reply } => {
                if !self.authenticated {
                    let _ = reply.send(Err(ClientError::InvalidInput("log in first".into())));
                    return Ok(());
                }
                let waiter = Waiter::PasswordChallenge(reply);
                self.request(PacketType::PasswordChangeBegin, PasswordChangeBegin.encode(), waiter)
                    .await?;
            }
            Command::FinishPasswordChange {
                proof,
                credential,
                reply,
            } => {
                if !self.authenticated {
                    let _ = reply.send(Err(ClientError::InvalidInput("log in first".into())));
                    return Ok(());
                }
                let msg = PasswordChangeProof { proof, credential };
                let waiter = Waiter::PasswordChanged(reply);
                self.request(PacketType::PasswordChangeProof, msg.encode(), waiter)
                    .await?;
            }
            Command::ListNewsgroups { reply } => {
                let msg = NewsgroupListRequest;
                let waiter = Waiter::Newsgroups(reply);
                self.request(PacketType::NewsgroupListRequest, msg.encode(), waiter)
                    .await?;
            }
            Command::CreateNewsgroup {
                name,
                description,
                min_read_class,
                min_post_class,
                reply,
            } => {
                let msg = NewsgroupCreate {
                    name,
                    description,
                    min_read_class,
                    min_post_class,
                };
                let waiter = Waiter::Newsgroups(reply);
                self.request(PacketType::NewsgroupCreate, msg.encode(), waiter)
                    .await?;
            }
            Command::ListThread {
                newsgroup_id,
                reply,
            } => {
                let Some(newsgroup_id) = parse_role_id(&newsgroup_id) else {
                    let _ = reply.send(Err(ClientError::InvalidInput("bad newsgroup id".into())));
                    return Ok(());
                };
                let msg = NewsThreadListRequest { newsgroup_id };
                let waiter = Waiter::Thread(reply);
                self.request(PacketType::NewsThreadListRequest, msg.encode(), waiter)
                    .await?;
            }
            Command::CreatePost {
                newsgroup_id,
                parent_id,
                subject,
                body,
                reply,
            } => {
                let Some(newsgroup_id) = parse_role_id(&newsgroup_id) else {
                    let _ = reply.send(Err(ClientError::InvalidInput("bad newsgroup id".into())));
                    return Ok(());
                };
                // Empty parent = new thread → all-zeros sentinel.
                let parent_id = if parent_id.is_empty() {
                    [0u8; 16]
                } else {
                    match parse_role_id(&parent_id) {
                        Some(id) => id,
                        None => {
                            let _ = reply.send(Err(ClientError::InvalidInput("bad parent id".into())));
                            return Ok(());
                        }
                    }
                };
                let msg = NewsPostCreate {
                    newsgroup_id,
                    parent_id,
                    subject,
                    body,
                };
                self.request(PacketType::NewsPostCreate, msg.encode(), Waiter::Thread(reply))
                    .await?;
            }
            Command::DeletePost { post_id, reply } => {
                let Some(post_id) = parse_role_id(&post_id) else {
                    let _ = reply.send(Err(ClientError::InvalidInput("bad post id".into())));
                    return Ok(());
                };
                let msg = NewsPostDelete { post_id };
                self.request(PacketType::NewsPostDelete, msg.encode(), Waiter::Thread(reply))
                    .await?;
            }
            // Both answered by a BanListResponse (or an Error).
            Command::ListBans { reply } => {
                let msg = BanListRequest;
                self.request(PacketType::BanListRequest, msg.encode(), Waiter::Bans(reply))
                    .await?;
            }
            Command::RemoveBan { username, reply } => {
                let msg = BanRemove { username };
                self.request(PacketType::BanRemove, msg.encode(), Waiter::Bans(reply))
                    .await?;
            }
            // Both answered by a NewsgroupListResponse (or an Error).
            Command::UpdateNewsgroup {
                id,
                name,
                description,
                min_read_class,
                min_post_class,
                reply,
            } => {
                let Some(id) = parse_role_id(&id) else {
                    let _ = reply.send(Err(ClientError::InvalidInput("bad newsgroup id".into())));
                    return Ok(());
                };
                let msg = NewsgroupUpdate {
                    id,
                    name,
                    description,
                    min_read_class,
                    min_post_class,
                };
                let waiter = Waiter::Newsgroups(reply);
                self.request(PacketType::NewsgroupUpdate, msg.encode(), waiter)
                    .await?;
            }
            Command::DeleteNewsgroup { id, reply } => {
                let Some(id) = parse_role_id(&id) else {
                    let _ = reply.send(Err(ClientError::InvalidInput("bad newsgroup id".into())));
                    return Ok(());
                };
                let msg = NewsgroupDelete { id };
                let waiter = Waiter::Newsgroups(reply);
                self.request(PacketType::NewsgroupDelete, msg.encode(), waiter)
                    .await?;
            }
        }
        Ok(())
    }

    // ---- request/barrier plumbing -------------------------------------

    fn push_pending(&mut self, pending: Pending) {
        if self.pending.len() >= MAX_PENDING {
            self.dead = Some("server is not answering requests".into());
        }
        self.pending.push_back(pending);
    }

    /// Send a request that gets exactly one reply-or-Error and queue its
    /// waiter. A request that can't be sent fails only its caller.
    async fn request(
        &mut self,
        packet_type: PacketType,
        payload: Bytes,
        waiter: Waiter,
    ) -> Result<(), SendError> {
        match self.send(packet_type, payload).await {
            Ok(()) => {
                self.push_pending(Pending::Reply(waiter));
                Ok(())
            }
            Err(SendError::Rejected(e)) => {
                waiter.fail(e);
                Ok(())
            }
            Err(SendError::Fatal(e)) => {
                waiter.fail(ClientError::Disconnected);
                Err(SendError::Fatal(e))
            }
        }
    }

    /// Send a fire-and-forget command followed by its barrier, resolving
    /// `reply` once both are written.
    async fn quiet(
        &mut self,
        packet_type: PacketType,
        payload: Bytes,
        reply: Reply<()>,
    ) -> Result<(), SendError> {
        match self
            .send_quiet(packet_type, payload, Quiet::new(QuietKind::Plain))
            .await
        {
            Ok(()) => {
                let _ = reply.send(Ok(()));
                Ok(())
            }
            Err(SendError::Rejected(e)) => {
                let _ = reply.send(Err(e));
                Ok(())
            }
            Err(SendError::Fatal(e)) => {
                let _ = reply.send(Err(ClientError::Disconnected));
                Err(SendError::Fatal(e))
            }
        }
    }

    /// Send a fire-and-forget command whose caller (`quiet.reply`) waits for
    /// the outcome: answered when its barrier returns, or now if it can't
    /// be sent.
    async fn send_answered(
        &mut self,
        packet_type: PacketType,
        payload: Bytes,
        mut quiet: Quiet,
    ) -> Result<(), SendError> {
        match self.send(packet_type, payload).await {
            // A barrier that can't be written drops `quiet`, and with it the
            // reply: the caller sees `Disconnected`.
            Ok(()) => self.send_barrier(Some(quiet)).await,
            Err(SendError::Rejected(e)) => {
                if let Some(reply) = quiet.reply.take() {
                    let _ = reply.send(Err(e));
                }
                Ok(())
            }
            Err(SendError::Fatal(e)) => {
                if let Some(reply) = quiet.reply.take() {
                    let _ = reply.send(Err(ClientError::Disconnected));
                }
                Err(SendError::Fatal(e))
            }
        }
    }

    async fn send_quiet(
        &mut self,
        packet_type: PacketType,
        payload: Bytes,
        quiet: Quiet,
    ) -> Result<(), SendError> {
        self.send(packet_type, payload).await?;
        self.send_barrier(Some(quiet)).await
    }

    /// Write a `Ping(token)` and queue the barrier it stands for.
    async fn send_barrier(&mut self, quiet: Option<Quiet>) -> Result<(), SendError> {
        self.next_token = self.next_token.wrapping_add(1);
        let token = self.next_token;
        self.send(PacketType::Ping, Bytes::copy_from_slice(&token.to_be_bytes()))
            .await?;
        self.push_pending(Pending::Barrier { token, quiet });
        Ok(())
    }

    /// Pop the request at the head of the queue, which must be waiting for
    /// a `packet_type` reply.
    fn take_reply(&mut self, packet_type: PacketType) -> Result<Waiter, ClientError> {
        let head_matches = matches!(
            self.pending.front(),
            Some(Pending::Reply(w)) if w.expects() == packet_type
        );
        match self.pending.pop_front() {
            Some(Pending::Reply(waiter)) if head_matches => Ok(waiter),
            other => {
                if let Some(other) = other {
                    self.pending.push_front(other);
                }
                Err(protocol_violation(format!("unexpected {packet_type:?}")))
            }
        }
    }

    async fn on_pong(&mut self, payload: &[u8]) -> Result<(), ClientError> {
        let Some(Pending::Barrier { token, quiet }) = self.pending.pop_front() else {
            return Err(protocol_violation("unexpected Pong"));
        };
        if payload != token.to_be_bytes() {
            warn!("Pong token mismatch");
        }
        let Some(quiet) = quiet else {
            return Ok(());
        };
        match quiet.kind {
            QuietKind::Plain => {}
            QuietKind::Join { forget } => {
                if let (Some(room), Some(_)) = (forget, &quiet.error) {
                    self.known_rooms.remove(&room);
                }
            }
            QuietKind::Invite(id) => self.invite_settled(id).await,
            QuietKind::UploadChunk { gen, len, index } => {
                self.upload_chunk_acked(gen, len, index, quiet.error.is_none())
                    .await
            }
        }
        if let Some(reply) = quiet.reply {
            let _ = reply.send(match quiet.error {
                None => Ok(()),
                Some(text) => Err(ClientError::Server(text)),
            });
        }
        Ok(())
    }

    async fn on_error(&mut self, payload: &[u8]) -> Result<(), ClientError> {
        let text = String::from_utf8_lossy(payload).into_owned();
        match self.pending.front_mut() {
            Some(Pending::Reply(_)) => {
                if let Some(Pending::Reply(waiter)) = self.pending.pop_front() {
                    match waiter {
                        Waiter::TransferStart(gen) => {
                            if self.is_current(gen) {
                                let err = ClientError::Transfer(text.clone());
                                self.fail_transfer(err, Cleanup::Keep).await;
                            }
                        }
                        waiter => waiter.fail(ClientError::Server(text.clone())),
                    }
                }
            }
            Some(Pending::Barrier {
                quiet: Some(quiet), ..
            }) if quiet.error.is_none() => {
                quiet.error = Some(text.clone());
                match quiet.kind.clone() {
                    QuietKind::Plain | QuietKind::Join { .. } => {}
                    QuietKind::Invite(id) => self.invite_refused(id, &text),
                    QuietKind::UploadChunk { gen, .. } => {
                        if !self.is_current(gen) {
                            // A chunk of an upload that has already ended
                            // (server abort, earlier chunk refused, cancel):
                            // every chunk still in flight gets the same
                            // refusal, which says nothing new.
                            debug!("error for a chunk of a finished upload: {text}");
                            return Ok(());
                        }
                        let err = ClientError::Transfer(text.clone());
                        self.fail_transfer(err, Cleanup::Keep).await;
                    }
                }
            }
            // Nothing attributable is waiting: an unsolicited error.
            _ => {}
        }
        self.emit(Event::ServerError { text }).await;
        Ok(())
    }

    // ---- private-chat invitations -------------------------------------

    async fn start_invite(&mut self, to: String, reply: Reply<String>) -> Result<(), SendError> {
        if self.invites.len() >= MAX_PENDING_INVITES {
            let _ = reply.send(Err(ClientError::InvalidInput(
                "too many invitations in flight".into(),
            )));
            return Ok(());
        }
        self.next_invite += 1;
        let id = self.next_invite;
        match self
            .send_quiet(
                PacketType::ChatInvite,
                ChatInvite { to }.encode(),
                Quiet::new(QuietKind::Invite(id)),
            )
            .await
        {
            Ok(()) => {
                self.invites.push_back(InviteWait {
                    id,
                    reply: Some(reply),
                    failed: false,
                    settled: false,
                    room: None,
                });
                Ok(())
            }
            Err(SendError::Rejected(e)) => {
                let _ = reply.send(Err(e));
                Ok(())
            }
            Err(SendError::Fatal(e)) => {
                let _ = reply.send(Err(ClientError::Disconnected));
                Err(SendError::Fatal(e))
            }
        }
    }

    /// The server refused invitation `id`. Tell the caller now, but keep the
    /// entry until its barrier returns: the server may already have created
    /// (and torn down) the room, whose member list would otherwise be taken
    /// for a later invitation's room.
    fn invite_refused(&mut self, id: u64, text: &str) {
        if let Some(invite) = self.invites.iter_mut().find(|i| i.id == id) {
            invite.failed = true;
            if let Some(reply) = invite.reply.take() {
                let _ = reply.send(Err(ClientError::Server(text.to_string())));
            }
        }
    }

    async fn invite_settled(&mut self, id: u64) {
        if let Some(invite) = self.invites.iter_mut().find(|i| i.id == id) {
            invite.settled = true;
        }
        self.resolve_invites();
    }

    /// The server put us in a private room we didn't join ourselves: that is
    /// the room of the oldest invitation still waiting for one.
    fn on_fresh_private_room(&mut self, room: &str) {
        let Some(invite) = self
            .invites
            .iter_mut()
            .find(|i| i.room.is_none() && !(i.failed && i.settled))
        else {
            return;
        };
        invite.room = Some(room.to_string());
        if !invite.failed {
            self.known_rooms.insert(room.to_string());
        }
        self.resolve_invites();
    }

    fn resolve_invites(&mut self) {
        self.invites.retain_mut(|invite| {
            if !invite.settled {
                return true;
            }
            if invite.failed {
                return false;
            }
            match (&invite.room, invite.reply.take()) {
                (Some(room), Some(reply)) => {
                    let _ = reply.send(Ok(room.clone()));
                    false
                }
                (Some(_), None) => false,
                // Accepted but its room hasn't shown up yet; drop it if the
                // caller has given up.
                (None, Some(reply)) if reply.is_closed() => false,
                (None, reply) => {
                    invite.reply = reply;
                    true
                }
            }
        });
    }

    // ---- inbound frames -------------------------------------------------

    async fn handle_frame(&mut self, frame: KdxFrame) -> Result<(), ClientError> {
        match frame.header.packet_type {
            PacketType::AuthChallenge => self.on_auth_challenge(&frame.payload).await?,
            PacketType::AuthResult => self.on_auth_result(&frame.payload)?,
            PacketType::ChatMessage => {
                let ev = ChatEvent::decode(&frame.payload)?;
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
                if list.room.starts_with("priv-") && !self.known_rooms.contains(&list.room) {
                    self.on_fresh_private_room(&list.room);
                }
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
                if let Waiter::FileList(tx) = self.take_reply(PacketType::FileListResponse)? {
                    let _ = tx.send(Ok(response));
                }
            }
            PacketType::FileInfoResponse => {
                let response = FileInfoResponse::decode(&frame.payload)?;
                if let Waiter::FileInfo(tx) = self.take_reply(PacketType::FileInfoResponse)? {
                    let _ = tx.send(Ok(response));
                }
            }
            PacketType::FileCatalogGenerated => {
                let response = FileCatalogGenerated::decode(&frame.payload)?;
                if let Waiter::Catalog(tx) = self.take_reply(PacketType::FileCatalogGenerated)? {
                    let _ = tx.send(Ok(response.count));
                }
            }
            PacketType::FileSearchResponse => {
                let response = FileSearchResponse::decode(&frame.payload)?;
                if let Waiter::Search(tx) = self.take_reply(PacketType::FileSearchResponse)? {
                    let _ = tx.send(Ok(response.entries.into_iter().map(Into::into).collect()));
                }
            }
            PacketType::PresenceListResponse => {
                let response = PresenceListResponse::decode(&frame.payload)?;
                if let Waiter::Users(tx) = self.take_reply(PacketType::PresenceListResponse)? {
                    let _ = tx.send(Ok(response.users.into_iter().map(Into::into).collect()));
                }
            }
            PacketType::UserInfoResponse => {
                let response = UserInfoResponse::decode(&frame.payload)?;
                if let Waiter::UserInfo(tx) = self.take_reply(PacketType::UserInfoResponse)? {
                    let _ = tx.send(Ok(response.entry.into()));
                }
            }
            PacketType::TrackerListResponse => {
                let response = TrackerListResponse::decode(&frame.payload)?;
                if let Waiter::Servers(tx) = self.take_reply(PacketType::TrackerListResponse)? {
                    let _ = tx.send(Ok(response.servers.into_iter().map(Into::into).collect()));
                }
            }
            PacketType::ServerSettingsResponse => {
                let response = ServerSettingsResponse::decode(&frame.payload)?;
                if let Waiter::Settings(tx) = self.take_reply(PacketType::ServerSettingsResponse)? {
                    let _ = tx.send(Ok(response.into()));
                }
            }
            PacketType::HistoryListResponse => {
                let response = HistoryListResponse::decode(&frame.payload)?;
                if let Waiter::History(tx) = self.take_reply(PacketType::HistoryListResponse)? {
                    let _ = tx.send(Ok(response.entries.into_iter().map(Into::into).collect()));
                }
            }
            PacketType::IpRuleListResponse => {
                let response = IpRuleListResponse::decode(&frame.payload)?;
                if let Waiter::IpRules(tx) = self.take_reply(PacketType::IpRuleListResponse)? {
                    let _ = tx.send(Ok(response.rules.into_iter().map(Into::into).collect()));
                }
            }
            PacketType::ConnectionListResponse => {
                let response = ConnectionListResponse::decode(&frame.payload)?;
                if let Waiter::Connections(tx) = self.take_reply(PacketType::ConnectionListResponse)? {
                    let _ = tx.send(Ok(response
                        .connections
                        .into_iter()
                        .map(Into::into)
                        .collect()));
                }
            }
            PacketType::RoleListResponse => {
                let response = RoleListResponse::decode(&frame.payload)?;
                if let Waiter::Roles(tx) = self.take_reply(PacketType::RoleListResponse)? {
                    let _ = tx.send(Ok(response.roles.into_iter().map(Into::into).collect()));
                }
            }
            PacketType::AccountRolesResponse => {
                let response = AccountRolesResponse::decode(&frame.payload)?;
                if let Waiter::AccountRoles(tx) = self.take_reply(PacketType::AccountRolesResponse)? {
                    let _ = tx.send(Ok(response
                        .role_ids
                        .into_iter()
                        .map(|id| Uuid::from_bytes(id).to_string())
                        .collect()));
                }
            }
            PacketType::AccountListResponse => {
                let response = AccountListResponse::decode(&frame.payload)?;
                if let Waiter::Accounts(tx) = self.take_reply(PacketType::AccountListResponse)? {
                    let _ = tx.send(Ok(response
                        .accounts
                        .into_iter()
                        .map(Into::into)
                        .collect()));
                }
            }
            PacketType::NewsgroupListResponse => {
                let response = NewsgroupListResponse::decode(&frame.payload)?;
                if let Waiter::Newsgroups(tx) = self.take_reply(PacketType::NewsgroupListResponse)? {
                    let _ = tx.send(Ok(response.groups.into_iter().map(Into::into).collect()));
                }
            }
            PacketType::NewsThreadListResponse => {
                let response = NewsThreadListResponse::decode(&frame.payload)?;
                if let Waiter::Thread(tx) = self.take_reply(PacketType::NewsThreadListResponse)? {
                    let _ = tx.send(Ok(response.posts.into_iter().map(Into::into).collect()));
                }
            }
            PacketType::BanListResponse => {
                let response = BanListResponse::decode(&frame.payload)?;
                if let Waiter::Bans(tx) = self.take_reply(PacketType::BanListResponse)? {
                    let _ = tx.send(Ok(response.into()));
                }
            }
            PacketType::PasswordChangeChallenge => {
                let challenge = PasswordChangeChallenge::decode(&frame.payload)?;
                let waiter = self.take_reply(PacketType::PasswordChangeChallenge)?;
                if let Waiter::PasswordChallenge(tx) = waiter {
                    let username = self.username.clone().unwrap_or_default();
                    let _ = tx.send(Ok(ChangeChallenge {
                        challenge,
                        username,
                        channel_binding: self.channel_binding,
                    }));
                }
            }
            PacketType::PasswordChangeResult => {
                let result = PasswordChangeResult::decode(&frame.payload)?;
                if let Waiter::PasswordChanged(tx) = self.take_reply(PacketType::PasswordChangeResult)? {
                    let _ = tx.send(Ok(result));
                }
            }
            PacketType::PresenceChange => {
                let change = PresenceChange::decode(&frame.payload)?;
                self.emit(Event::Presence {
                    user: change.entry.into(),
                    online: change.online,
                })
                .await;
            }
            PacketType::PrivateMessage => {
                let msg = PrivateMessage::decode(&frame.payload)?;
                self.emit(Event::PrivateMessage {
                    from: msg.from,
                    to: msg.to,
                    timestamp: msg.timestamp,
                    text: msg.text,
                })
                .await;
            }
            PacketType::ChatInvited => {
                let invited = ChatInvited::decode(&frame.payload)?;
                self.emit(Event::ChatInvited {
                    from: invited.from,
                    room: invited.room,
                })
                .await;
            }
            PacketType::FileTransferStart => self.on_transfer_accept(&frame.payload).await?,
            PacketType::FileTransferData => self.on_transfer_data(&frame.payload).await?,
            PacketType::FileTransferEnd => self.on_transfer_end(&frame.payload).await?,
            PacketType::Warning => {
                self.emit(Event::ServerWarning {
                    text: String::from_utf8_lossy(&frame.payload).into_owned(),
                })
                .await;
            }
            PacketType::Error => self.on_error(&frame.payload).await?,
            PacketType::Info => {
                self.emit(Event::ServerInfo {
                    text: String::from_utf8_lossy(&frame.payload).into_owned(),
                })
                .await;
            }
            PacketType::Disconnect => {
                // The server is closing us (admin disconnect / ban). Surface
                // the reason as an error; the socket close that follows yields
                // the terminal Disconnected event on its own.
                let text = String::from_utf8_lossy(&frame.payload).into_owned();
                let text = if text.is_empty() {
                    "disconnected by the server".to_string()
                } else {
                    format!("disconnected by the server: {text}")
                };
                self.emit(Event::ServerError { text }).await;
            }
            PacketType::Pong => self.on_pong(&frame.payload).await?,
            other => debug!(packet_type = ?other, "unhandled inbound packet"),
        }
        Ok(())
    }

    // ---- transfers: common ------------------------------------------------

    fn next_generation(&mut self) -> u64 {
        self.next_gen += 1;
        self.next_gen
    }

    fn is_current(&self, gen: u64) -> bool {
        self.transfer.as_ref().is_some_and(|t| t.gen == gen)
    }

    fn accept_deadline(&self) -> Option<Instant> {
        match self.transfer.as_ref()?.stage {
            Stage::AwaitingAccept { deadline } => Some(deadline),
            _ => None,
        }
    }

    /// Tell the server we're abandoning `transfer_id` (a server that
    /// supports it releases the slot / stops streaming; older servers just
    /// answer with an `Error`, which the barrier absorbs).
    async fn send_abort(&mut self, transfer_id: [u8; 16]) {
        if self.abandoned.len() >= MAX_ABANDONED {
            self.abandoned.pop_front();
        }
        self.abandoned.push_back(transfer_id);
        if self.closing {
            return;
        }
        let end = TransferEnd {
            transfer_id,
            status: TRANSFER_ABORTED,
            message: "cancelled by client".into(),
        };
        let quiet = Quiet::new(QuietKind::Plain);
        if let Err(SendError::Fatal(e)) = self
            .send_quiet(PacketType::FileTransferEnd, end.encode(), quiet)
            .await
        {
            self.dead = Some(format!("write failed: {e}"));
        }
    }

    /// End the active transfer with `err`: stop its background work, tell
    /// the server, settle its on-disk state per `cleanup`, and answer the
    /// caller. No-op when nothing is active.
    async fn fail_transfer(&mut self, err: ClientError, cleanup: Cleanup) {
        let Some(mut transfer) = self.transfer.take() else {
            return;
        };
        transfer.cancel.store(true, Ordering::Relaxed);
        self.blocking = None; // only ever this transfer's job; dropping detaches it
        let (id, direction) = match &mut transfer.job {
            Job::Upload(job) => {
                let accepted = matches!(transfer.stage, Stage::Running);
                if accepted {
                    self.send_abort(job.id).await;
                }
                (accepted.then_some(job.id), Direction::Upload)
            }
            Job::Download(job) => {
                if job.accepted && transfer.stage != Stage::Verifying {
                    self.send_abort(job.id).await;
                }
                if let Some(mut file) = job.file.take() {
                    let _ = file.flush().await;
                }
                if let Some(task) = job.sidecar_task.take() {
                    let _ = task.await;
                }
                // The partial lives in the transfers directory; the
                // destination is never touched here.
                if job.accepted {
                    match cleanup {
                        Cleanup::Keep => {
                            let sidecar = job.sidecar(&self.opts.server_id);
                            let path = job.partial.sidecar.clone();
                            let _ = tokio::task::spawn_blocking(move || sidecar.write(&path)).await;
                        }
                        Cleanup::Discard => {
                            let _ = tokio::fs::remove_file(&job.partial.data).await;
                            let _ = tokio::fs::remove_file(&job.partial.sidecar).await;
                        }
                    }
                }
                (job.accepted.then_some(job.id), Direction::Download)
            }
        };
        if let Some(id) = id {
            self.emit(Event::TransferComplete {
                id: Uuid::from_bytes(id).to_string(),
                direction,
                status: TRANSFER_ABORTED,
                message: err.to_string(),
            })
            .await;
        }
        if let Some(reply) = transfer.reply.take() {
            let _ = reply.send(Err(err));
        }
    }

    async fn on_blocking_done(&mut self, done: BlockingDone) {
        match done {
            BlockingDone::UploadPrep(gen, result) if self.is_current(gen) => match result {
                Ok(prepared) => self.send_upload_request(prepared).await,
                Err(e) => self.fail_transfer(e, Cleanup::Keep).await,
            },
            BlockingDone::Verify(gen, result) if self.is_current(gen) => {
                self.finish_download(result).await
            }
            BlockingDone::Publish(gen, result) if self.is_current(gen) => {
                self.download_published(result).await
            }
            _ => {} // a cancelled transfer's leftover work
        }
    }

    async fn on_transfer_accept(&mut self, payload: &[u8]) -> Result<(), ClientError> {
        let accept = TransferAccept::decode(payload)?;
        let Waiter::TransferStart(gen) = self.take_reply(PacketType::FileTransferStart)? else {
            return Err(protocol_violation("unexpected TransferAccept"));
        };
        let awaiting = self
            .transfer
            .as_ref()
            .is_some_and(|t| t.gen == gen && matches!(t.stage, Stage::AwaitingAccept { .. }));
        if !awaiting {
            // Accepted after we gave up on it (cancel / timeout).
            self.send_abort(accept.transfer_id).await;
            return Ok(());
        }
        let is_upload = matches!(
            self.transfer.as_ref().map(|t| &t.job),
            Some(Job::Upload(_))
        );
        if is_upload {
            self.on_upload_accept(accept).await;
        } else {
            self.on_download_accept(accept).await;
        }
        Ok(())
    }

    async fn on_transfer_data(&mut self, payload: &[u8]) -> Result<(), ClientError> {
        let data = TransferData::decode(payload)?;
        let Some(Transfer {
            stage: Stage::Running,
            job: Job::Download(job),
            ..
        }) = self.transfer.as_mut()
        else {
            return Ok(()); // not receiving; ignore
        };
        if data.transfer_id != job.id {
            return Ok(()); // a stale transfer's data
        }
        let index = data.chunk_index;
        let expected = chunk_len(job.size, job.chunk_size, index, job.total);
        if index >= job.total || data.data.len() != expected {
            let err = ClientError::Transfer(format!("server sent a malformed chunk {index}"));
            self.fail_transfer(err, Cleanup::Keep).await;
            return Ok(());
        }
        let actual: [u8; 32] = Sha256::digest(&data.data).into();
        if actual != data.chunk_hash {
            let err = ClientError::Transfer(format!("chunk {index} hash mismatch"));
            self.fail_transfer(err, Cleanup::Keep).await;
            return Ok(());
        }
        // `chunk_len` guarantees offset + len <= size.
        let offset = index as u64 * job.chunk_size as u64;
        let written = match job.file.as_mut() {
            Some(file) => write_at(file, offset, &data.data).await,
            None => Err(io::Error::other("download file is not open")),
        };
        if let Err(e) = written {
            self.fail_transfer(ClientError::Io(e), Cleanup::Keep).await;
            return Ok(());
        }
        job.have.set(index as usize, true);
        job.unsaved_chunks += 1;
        let now = Instant::now();
        let sidecar_due = job.unsaved_chunks >= SIDECAR_EVERY_CHUNKS
            || now.duration_since(job.last_sidecar) >= SIDECAR_EVERY;
        if sidecar_due && job.sidecar_task.as_ref().is_none_or(|t| t.is_finished()) {
            job.unsaved_chunks = 0;
            job.last_sidecar = now;
            job.sidecar_task = Some(spawn_sidecar_write(
                job.sidecar(&self.opts.server_id),
                job.partial.sidecar.clone(),
            ));
        }
        self.maybe_emit_progress(false).await;
        Ok(())
    }

    async fn on_transfer_end(&mut self, payload: &[u8]) -> Result<(), ClientError> {
        let end = TransferEnd::decode(payload)?;
        if let Some(pos) = self.abandoned.iter().position(|id| *id == end.transfer_id) {
            // The late end of a transfer we already gave up on.
            self.abandoned.remove(pos);
            return Ok(());
        }
        let Some(transfer) = self.transfer.as_ref() else {
            warn!("TransferEnd with no active transfer");
            return Ok(());
        };
        match transfer.stage {
            Stage::AwaitingAccept { .. } => {
                // The server can't end what it hasn't accepted. Treat the
                // End as its (malformed) answer to our request, so later
                // replies still line up.
                let gen = transfer.gen;
                if matches!(
                    self.pending.front(),
                    Some(Pending::Reply(Waiter::TransferStart(g))) if *g == gen
                ) {
                    self.pending.pop_front();
                }
                let err = ClientError::Transfer("server ended the transfer before accepting it".into());
                self.fail_transfer(err, Cleanup::Keep).await;
            }
            Stage::Preparing | Stage::Verifying => warn!("unexpected TransferEnd"),
            Stage::Running => {
                let id = match &transfer.job {
                    Job::Upload(job) => job.id,
                    Job::Download(job) => job.id,
                };
                if end.transfer_id != id {
                    warn!("TransferEnd for another transfer");
                    return Ok(());
                }
                if matches!(transfer.job, Job::Upload(_)) {
                    self.finish_upload(end).await;
                } else {
                    self.download_ended(end).await;
                }
            }
        }
        Ok(())
    }

    fn progress_event(&mut self, force: bool) -> Option<Event> {
        let now = Instant::now();
        let transfer = self.transfer.as_mut()?;
        let (id, direction, bits, last) = match &mut transfer.job {
            Job::Upload(job) => (job.id, Direction::Upload, &job.done, &mut job.last_progress),
            Job::Download(job) => (job.id, Direction::Download, &job.have, &mut job.last_progress),
        };
        let total = bits.len() as u32;
        let done = bits.count_ones() as u32;
        let due = force
            || done == total
            || last.is_none_or(|t| now.duration_since(t) >= PROGRESS_INTERVAL);
        if !due {
            return None;
        }
        *last = Some(now);
        let (bitmap, bitmap_bits) = progress_bitmap(bits, PROGRESS_MAX_BITS);
        Some(Event::TransferProgress {
            id: Uuid::from_bytes(id).to_string(),
            direction,
            done,
            total,
            bitmap,
            bitmap_bits,
        })
    }

    async fn maybe_emit_progress(&mut self, force: bool) {
        if let Some(event) = self.progress_event(force) {
            self.emit(event).await;
        }
    }

    // ---- uploads ------------------------------------------------------------

    fn start_upload(&mut self, local: PathBuf, remote_dir: String, reply: Reply<()>) {
        if self.transfer.is_some() {
            let _ = reply.send(Err(ClientError::Transfer("a transfer is already active".into())));
            return;
        }
        let name = match local.file_name().and_then(|n| n.to_str()) {
            Some(n) if n.len() <= u16::MAX as usize => n.to_string(),
            _ => {
                let _ = reply.send(Err(ClientError::Transfer("invalid local file name".into())));
                return;
            }
        };
        let gen = self.next_generation();
        let cancel = Arc::new(AtomicBool::new(false));
        let task = {
            let cancel = cancel.clone();
            tokio::task::spawn_blocking(move || prepare_upload(&local, &cancel))
        };
        self.blocking = Some(Blocking::UploadPrep { gen, task });
        self.transfer = Some(Transfer {
            gen,
            reply: Some(reply),
            cancel,
            stage: Stage::Preparing,
            job: Job::Upload(UploadJob {
                remote_dir,
                name,
                file: None,
                size: 0,
                modified: None,
                sha256: [0u8; 32],
                chunk_size: DEFAULT_CHUNK_SIZE,
                total: 0,
                id: [0u8; 16],
                skip: BitVec::new(),
                done: BitVec::new(),
                next: 0,
                in_flight_bytes: 0,
                last_progress: None,
            }),
        });
    }

    /// The local file is hashed: ask the server to accept it.
    async fn send_upload_request(&mut self, prepared: PreparedUpload) {
        let deadline = Instant::now() + self.opts.request_timeout;
        let Some(Transfer {
            gen,
            stage,
            job: Job::Upload(job),
            ..
        }) = self.transfer.as_mut()
        else {
            return;
        };
        let gen = *gen;
        job.size = prepared.size;
        job.modified = prepared.modified;
        job.sha256 = prepared.sha256;
        job.chunk_size = choose_chunk_size(prepared.size);
        job.file = Some(tokio::fs::File::from_std(prepared.file));
        let request = TransferRequest {
            direction: DIRECTION_UPLOAD,
            path: job.remote_dir.clone(),
            name: job.name.clone(),
            size: job.size,
            chunk_size: job.chunk_size,
            sha256: job.sha256,
            resume_id: [0u8; 16],
            have_bitmap: vec![],
        };
        *stage = Stage::AwaitingAccept { deadline };
        self.send_transfer_request(gen, request).await;
    }

    async fn send_transfer_request(&mut self, gen: u64, request: TransferRequest) {
        match self.send(PacketType::FileTransferStart, request.encode()).await {
            Ok(()) => self.push_pending(Pending::Reply(Waiter::TransferStart(gen))),
            Err(SendError::Rejected(e)) => self.fail_transfer(e, Cleanup::Keep).await,
            Err(SendError::Fatal(e)) => self.dead = Some(format!("write failed: {e}")),
        }
    }

    async fn on_upload_accept(&mut self, accept: TransferAccept) {
        let Some(Transfer {
            stage,
            job: Job::Upload(job),
            ..
        }) = self.transfer.as_mut()
        else {
            return;
        };
        let problem = validate_geometry(
            true,
            job.chunk_size,
            accept.chunk_size,
            accept.total_chunks,
            accept.size,
            accept.have_bitmap.len(),
        )
        .err()
        .or_else(|| (accept.size != job.size).then(|| "server changed the upload size".into()));
        if let Some(problem) = problem {
            job.id = accept.transfer_id;
            *stage = Stage::Running; // so the failure tells the server
            self.fail_transfer(ClientError::Transfer(problem), Cleanup::Keep).await;
            return;
        }
        job.id = accept.transfer_id;
        job.total = accept.total_chunks;
        let mut skip = ChunkBitmap::from_vec(accept.have_bitmap);
        skip.resize(job.total as usize, false);
        job.done = skip.clone();
        job.skip = skip;
        job.next = 0;
        job.in_flight_bytes = 0;
        *stage = Stage::Running;
        // With nothing to send (an empty file, or the server already has
        // every chunk) we simply wait for the server's TransferEnd.
        self.maybe_emit_progress(true).await;
    }

    fn upload_can_send(&self) -> bool {
        match self.transfer.as_ref() {
            Some(Transfer {
                stage: Stage::Running,
                job: Job::Upload(job),
                ..
            }) => {
                job.next < job.total
                    && (job.in_flight_bytes == 0
                        || job.in_flight_bytes + job.chunk_size as u64 <= UPLOAD_WINDOW_BYTES)
            }
            _ => false,
        }
    }

    /// Read, hash and send the next missing chunk, then its barrier. One
    /// chunk per loop turn, so commands and Disconnect are serviced
    /// throughout an upload.
    async fn send_next_chunk(&mut self) {
        let Some(Transfer {
            gen,
            job: Job::Upload(job),
            ..
        }) = self.transfer.as_mut()
        else {
            return;
        };
        let gen = *gen;
        while job.next < job.total && job.skip[job.next as usize] {
            job.next += 1;
        }
        if job.next >= job.total {
            return;
        }
        let index = job.next;
        job.next += 1;
        let len = chunk_len(job.size, job.chunk_size, index, job.total);
        let offset = index as u64 * job.chunk_size as u64;
        let read = match job.file.as_mut() {
            Some(file) => read_chunk(file, offset, len, job.size, job.modified).await,
            None => Err(ClientError::Transfer("upload file is not open".into())),
        };
        let bytes = match read {
            Ok(bytes) => bytes,
            Err(e) => {
                self.fail_transfer(e, Cleanup::Keep).await;
                return;
            }
        };
        job.in_flight_bytes += len as u64;
        let data = TransferData {
            transfer_id: job.id,
            chunk_index: index,
            chunk_hash: Sha256::digest(&bytes).into(),
            data: Bytes::from(bytes),
        };
        let kind = QuietKind::UploadChunk {
            gen,
            len: len as u64,
            index,
        };
        match self
            .send_quiet(PacketType::FileTransferData, data.encode(), Quiet::new(kind))
            .await
        {
            Ok(()) => {}
            Err(SendError::Rejected(e)) => self.fail_transfer(e, Cleanup::Keep).await,
            Err(SendError::Fatal(e)) => self.dead = Some(format!("write failed: {e}")),
        }
    }

    async fn upload_chunk_acked(&mut self, gen: u64, len: u64, index: u32, ok: bool) {
        let Some(Transfer {
            gen: current,
            job: Job::Upload(job),
            ..
        }) = self.transfer.as_mut()
        else {
            return;
        };
        if *current != gen {
            return;
        }
        job.in_flight_bytes = job.in_flight_bytes.saturating_sub(len);
        if ok && (index as usize) < job.done.len() {
            job.done.set(index as usize, true);
            self.maybe_emit_progress(false).await;
        }
    }

    async fn finish_upload(&mut self, end: TransferEnd) {
        let verified = end.status == TRANSFER_VERIFIED;
        if verified {
            if let Some(Transfer {
                job: Job::Upload(job),
                ..
            }) = self.transfer.as_mut()
            {
                job.done.fill(true);
            }
            self.maybe_emit_progress(true).await;
        }
        let Some(mut transfer) = self.transfer.take() else {
            return;
        };
        transfer.cancel.store(true, Ordering::Relaxed);
        let id = match &transfer.job {
            Job::Upload(job) => job.id,
            Job::Download(job) => job.id,
        };
        self.emit(Event::TransferComplete {
            id: Uuid::from_bytes(id).to_string(),
            direction: Direction::Upload,
            status: end.status,
            message: end.message.clone(),
        })
        .await;
        if let Some(reply) = transfer.reply.take() {
            let _ = reply.send(if verified {
                Ok(())
            } else {
                Err(ClientError::Transfer(end.message))
            });
        }
    }

    // ---- downloads ------------------------------------------------------------

    async fn start_download(
        &mut self,
        remote_path: String,
        local: PathBuf,
        expected_size: Option<u64>,
        reply: Reply<()>,
    ) -> Result<(), SendError> {
        if self.transfer.is_some() {
            let _ = reply.send(Err(ClientError::Transfer("a transfer is already active".into())));
            return Ok(());
        }
        let (dir, name) = split_remote(&remote_path);
        if name.is_empty() || local.file_name().is_none() {
            let _ = reply.send(Err(ClientError::InvalidInput("invalid download path".into())));
            return Ok(());
        }
        if expected_size.is_some_and(|s| s > crate::transfer::MAX_TRANSFER_SIZE) {
            let _ = reply.send(Err(ClientError::InvalidInput("file is too large".into())));
            return Ok(());
        }
        let Some(transfers_dir) = self.opts.transfers_dir.as_deref() else {
            let _ = reply.send(Err(ClientError::InvalidInput(
                "downloads need a data directory".into(),
            )));
            return Ok(());
        };

        // Resume only from a sidecar for this server, remote file and
        // destination whose data file is still there.
        let partial = PartialPaths::new(transfers_dir, &self.opts.server_id, &remote_path, &local);
        let resume = {
            let partial = partial.clone();
            tokio::task::spawn_blocking(move || {
                std::fs::metadata(&partial.data)
                    .is_ok_and(|m| m.is_file())
                    .then(|| Sidecar::read(&partial.sidecar))
                    .flatten()
            })
            .await
            .ok()
            .flatten()
        };
        let resume = resume.filter(|sc| {
            sc.server == self.opts.server_id
                && sc.remote == remote_path
                && sc.destination == local
                && expected_size.is_none_or(|s| s == sc.size)
        });
        let requested_chunk = match (&resume, expected_size) {
            (Some(sc), _) => sc.chunk_size,
            (None, Some(size)) => choose_chunk_size(size),
            (None, None) => DEFAULT_CHUNK_SIZE,
        };
        let (resume_id, have_bitmap) = match &resume {
            Some(sc) => (sc.transfer_id, sc.bitmap.clone()),
            None => ([0u8; 16], vec![]),
        };

        let gen = self.next_generation();
        let request = TransferRequest {
            direction: DIRECTION_DOWNLOAD,
            path: dir,
            name,
            size: 0,
            chunk_size: requested_chunk,
            sha256: [0u8; 32],
            resume_id,
            have_bitmap,
        };
        match self.send(PacketType::FileTransferStart, request.encode()).await {
            Ok(()) => self.push_pending(Pending::Reply(Waiter::TransferStart(gen))),
            Err(SendError::Rejected(e)) => {
                let _ = reply.send(Err(e));
                return Ok(());
            }
            Err(SendError::Fatal(e)) => {
                let _ = reply.send(Err(ClientError::Disconnected));
                return Err(SendError::Fatal(e));
            }
        }
        self.transfer = Some(Transfer {
            gen,
            reply: Some(reply),
            cancel: Arc::new(AtomicBool::new(false)),
            stage: Stage::AwaitingAccept {
                deadline: Instant::now() + self.opts.request_timeout,
            },
            job: Job::Download(DownloadJob {
                remote_path,
                local,
                partial: Box::new(partial),
                expected_size,
                requested_chunk,
                resume,
                accepted: false,
                round: 0,
                file: None,
                id: [0u8; 16],
                size: 0,
                chunk_size: requested_chunk,
                total: 0,
                sha256: [0u8; 32],
                have: BitVec::new(),
                last_progress: None,
                unsaved_chunks: 0,
                last_sidecar: Instant::now(),
                sidecar_task: None,
            }),
        });
        Ok(())
    }

    async fn on_download_accept(&mut self, accept: TransferAccept) {
        let server_id = self.opts.server_id.clone();
        let Some(Transfer {
            stage,
            job: Job::Download(job),
            ..
        }) = self.transfer.as_mut()
        else {
            return;
        };
        // Validate everything before touching the filesystem.
        let mut problem = validate_geometry(
            false,
            job.requested_chunk,
            accept.chunk_size,
            accept.total_chunks,
            accept.size,
            accept.have_bitmap.len(),
        )
        .err();
        if problem.is_none() && job.expected_size.is_some_and(|s| s != accept.size) {
            problem = Some("the file's size changed on the server".into());
        }
        let same_file = accept.size == job.size
            && accept.sha256 == job.sha256
            && accept.chunk_size == job.chunk_size;
        if problem.is_none() && job.accepted && !same_file {
            // A follow-up round for a file that changed meanwhile.
            let err = ClientError::Transfer("the file changed on the server".into());
            job.id = accept.transfer_id;
            *stage = Stage::Running;
            self.fail_transfer(err, Cleanup::Discard).await;
            return;
        }
        if let Some(problem) = problem {
            // Refused before anything is created for this attempt; any
            // earlier resume state is left as it was.
            let accepted_before = job.accepted;
            job.id = accept.transfer_id;
            *stage = Stage::Running;
            if !accepted_before {
                self.send_abort(accept.transfer_id).await;
            }
            self.fail_transfer(ClientError::Transfer(problem), Cleanup::Keep).await;
            return;
        }

        job.id = accept.transfer_id;
        if !job.accepted {
            job.size = accept.size;
            job.chunk_size = accept.chunk_size;
            job.total = accept.total_chunks;
            job.sha256 = accept.sha256;
            // Trust local resume state only if it describes this exact file.
            let mut have: ChunkBitmap = match job.resume.take() {
                Some(sc)
                    if sc.size == job.size
                        && sc.sha256 == job.sha256
                        && sc.chunk_size == job.chunk_size
                        && sc.bitmap.len() == bitmap_bytes(job.total) =>
                {
                    ChunkBitmap::from_vec(sc.bitmap)
                }
                _ => BitVec::new(),
            };
            have.resize(job.total as usize, false);
            let fresh = have.not_any();
            // The partial goes in the transfers directory; nothing is
            // created at (or beside) the destination until it verifies.
            let dir = job.partial.data.parent().map(Path::to_path_buf);
            let created = match dir {
                Some(dir) => tokio::task::spawn_blocking(move || create_transfers_dir(&dir))
                    .await
                    .unwrap_or_else(|e| Err(io::Error::other(e))),
                None => Ok(()),
            };
            let opened = match created {
                Ok(()) => {
                    tokio::fs::OpenOptions::new()
                        .create(true)
                        .read(true)
                        .write(true)
                        .truncate(fresh)
                        .open(&job.partial.data)
                        .await
                }
                Err(e) => Err(e),
            };
            match opened {
                Ok(file) => job.file = Some(file),
                Err(e) => {
                    self.fail_transfer(ClientError::Io(e), Cleanup::Keep).await;
                    return;
                }
            }
            job.have = have;
            job.accepted = true;
            // Record the identity straight away so an interruption resumes.
            job.unsaved_chunks = 0;
            job.last_sidecar = Instant::now();
            job.sidecar_task = Some(spawn_sidecar_write(
                job.sidecar(&server_id),
                job.partial.sidecar.clone(),
            ));
        }
        *stage = Stage::Running;
        self.maybe_emit_progress(true).await;
    }

    /// The server finished streaming. Either ask again for chunks it
    /// skipped, or verify the whole file off the actor.
    async fn download_ended(&mut self, end: TransferEnd) {
        let request_timeout = self.opts.request_timeout;
        let Some(Transfer {
            gen,
            stage,
            cancel,
            job: Job::Download(job),
            ..
        }) = self.transfer.as_mut()
        else {
            return;
        };
        let gen = *gen;
        if end.status != TRANSFER_VERIFIED {
            // The server is done with it; nothing to abort.
            *stage = Stage::Verifying;
            let err = ClientError::Transfer(format!("server aborted the download: {}", end.message));
            self.fail_transfer(err, Cleanup::Keep).await;
            return;
        }
        let flushed = match job.file.as_mut() {
            Some(file) => file.flush().await,
            None => Ok(()),
        };
        if let Err(e) = flushed {
            *stage = Stage::Verifying;
            self.fail_transfer(ClientError::Io(e), Cleanup::Keep).await;
            return;
        }
        if !job.have.all() {
            if job.round + 1 < MAX_DOWNLOAD_ROUNDS {
                // The server skipped chunks we don't have (e.g. a stale
                // resume bitmap): ask once more for exactly what's missing.
                job.round += 1;
                job.requested_chunk = job.chunk_size;
                let (dir, name) = split_remote(&job.remote_path);
                let request = TransferRequest {
                    direction: DIRECTION_DOWNLOAD,
                    path: dir,
                    name,
                    size: 0,
                    chunk_size: job.chunk_size,
                    sha256: [0u8; 32],
                    resume_id: job.id,
                    have_bitmap: bitmap_vec(&job.have),
                };
                *stage = Stage::AwaitingAccept {
                    deadline: Instant::now() + request_timeout,
                };
                self.send_transfer_request(gen, request).await;
            } else {
                *stage = Stage::Verifying;
                let err = ClientError::Transfer("the server did not send every chunk".into());
                self.fail_transfer(err, Cleanup::Discard).await;
            }
            return;
        }
        // Every chunk is on disk: hash it (at most `size` bytes) on the
        // blocking pool while the actor keeps serving commands.
        drop(job.file.take());
        *stage = Stage::Verifying;
        let (path, size, cancel) = (job.partial.data.clone(), job.size, cancel.clone());
        let task = tokio::task::spawn_blocking(move || hash_download(&path, size, &cancel));
        self.blocking = Some(Blocking::Verify { gen, task });
        self.maybe_emit_progress(true).await;
    }

    /// The whole-file hash is in: on a match, move the file to its
    /// destination off the actor (a copy across filesystems can take a
    /// while); otherwise fail.
    async fn finish_download(&mut self, result: Result<[u8; 32], ClientError>) {
        let publish = self.opts.publish;
        let Some(Transfer {
            gen,
            cancel,
            job: Job::Download(job),
            ..
        }) = self.transfer.as_mut()
        else {
            return;
        };
        let failure = match result {
            Ok(actual) if actual == job.sha256 => None,
            // The data is wrong: a retry must start from scratch.
            Ok(_) => Some((
                ClientError::Transfer("downloaded file hash mismatch".into()),
                Cleanup::Discard,
            )),
            Err(e) => Some(verify_failure(e)),
        };
        // No sidecar write may land after the sidecar is removed on success.
        if let Some(task) = job.sidecar_task.take() {
            let _ = task.await;
        }
        if let Some((err, cleanup)) = failure {
            self.fail_transfer(err, cleanup).await;
            return;
        }
        let gen = *gen;
        let (data, local, size, sha256, cancel) = (
            job.partial.data.clone(),
            job.local.clone(),
            job.size,
            job.sha256,
            cancel.clone(),
        );
        let task = tokio::task::spawn_blocking(move || {
            publish_download(&data, &local, size, &sha256, publish, &cancel)
        });
        self.blocking = Some(Blocking::Publish { gen, task });
    }

    /// The verified file has reached its destination (or couldn't).
    async fn download_published(&mut self, result: Result<(), ClientError>) {
        let Some(Transfer {
            job: Job::Download(job),
            ..
        }) = self.transfer.as_mut()
        else {
            return;
        };
        if let Err(e) = result {
            // An I/O failure (destination not writable, disk full) keeps the
            // verified partial for a retry; bytes that no longer match their
            // hash are discarded.
            let (err, cleanup) = verify_failure(e);
            self.fail_transfer(err, cleanup).await;
            return;
        }
        let (sidecar, id) = (job.partial.sidecar.clone(), job.id);
        let _ = tokio::fs::remove_file(&sidecar).await;
        let Some(mut transfer) = self.transfer.take() else {
            return;
        };
        self.emit(Event::TransferComplete {
            id: Uuid::from_bytes(id).to_string(),
            direction: Direction::Download,
            status: TRANSFER_VERIFIED,
            message: "verified".into(),
        })
        .await;
        if let Some(reply) = transfer.reply.take() {
            let _ = reply.send(Ok(()));
        }
    }

    // ---- login ----------------------------------------------------------------

    async fn on_auth_challenge(&mut self, payload: &[u8]) -> Result<(), ClientError> {
        let Some(login) = self.login.as_mut() else {
            warn!("unexpected AuthChallenge with no login in flight");
            return Ok(());
        };
        if !matches!(login.phase, LoginPhase::AwaitingChallenge) {
            return Ok(());
        }
        let challenge = AuthChallenge::decode(payload)?;
        let Some(password) = login.password.take() else {
            return Ok(());
        };
        let username = login.username.clone();
        let binding = self.channel_binding;
        // `client_proof` refuses out-of-bounds KDF parameters before running
        // Argon2, so a hostile server can't make us allocate terabytes or
        // spin for hours; the (bounded) Argon2 work itself runs on a blocking
        // thread, not on a runtime worker.
        let derived = tokio::task::spawn_blocking(move || {
            kdx_crypto::client_proof(
                password.as_str(),
                &AuthContext {
                    username: &username,
                    challenge: &challenge.challenge,
                    salt: &challenge.salt,
                    params: KdfParams {
                        m_cost: challenge.m_cost,
                        t_cost: challenge.t_cost,
                        p_cost: challenge.p_cost,
                    },
                    channel_binding: &binding,
                },
            )
        })
        .await;
        let proof = match derived {
            Ok(Ok(proof)) => proof,
            Ok(Err(e)) => {
                return self.fail_login(e.to_string());
            }
            Err(_) => {
                return self.fail_login("login computation failed".into());
            }
        };
        let response = proof.proof;
        if let Some(login) = self.login.as_mut() {
            login.proof = Some(proof);
            login.phase = LoginPhase::AwaitingResult;
        }
        self.send(PacketType::AuthResponse, AuthResponse { response }.encode())
            .await?;
        Ok(())
    }

    /// End the login in flight with `AuthFailed(message)`.
    fn fail_login(&mut self, message: String) -> Result<(), ClientError> {
        if let Some(login) = self.login.take() {
            let _ = login.reply.send(Err(ClientError::AuthFailed(message)));
        }
        Ok(())
    }

    fn on_auth_result(&mut self, payload: &[u8]) -> Result<(), ClientError> {
        let Some(login) = self.login.take() else {
            warn!("unexpected AuthResult with no login in flight");
            return Ok(());
        };
        let result = AuthResult::decode(payload)?;
        if !result.success {
            // Also valid straight after AuthRequest (throttled, server full,
            // invalid username): the server may refuse without a challenge.
            let _ = login.reply.send(Err(ClientError::AuthFailed(result.message)));
            return Ok(());
        }
        // A success counts only after our proof, and only with a server
        // signature that proves the server holds this account's credential.
        // Otherwise it's an impostor (or a relay): fail and drop the link.
        let verified = matches!(login.phase, LoginPhase::AwaitingResult)
            && login
                .proof
                .as_ref()
                .is_some_and(|p| p.verify_server_signature(&result.server_signature));
        if !verified {
            let message = "server failed to prove it knows this account".to_string();
            let _ = login
                .reply
                .send(Err(ClientError::AuthFailed(message.clone())));
            return Err(ClientError::AuthFailed(message));
        }
        self.authenticated = true;
        self.username = Some(login.username);
        let _ = login.reply.send(Ok(Session {
            session_id: result.session_id,
            class: result.class,
        }));
        Ok(())
    }

    // ---- output ---------------------------------------------------------------

    /// Deliver an event to the application. Waits while the event channel is
    /// full (backpressure), but never past a disconnect request.
    async fn emit(&mut self, event: Event) {
        let send = self.events.send(event);
        tokio::select! {
            biased;
            _ = wait_shutdown(&mut self.shutdown) => {}
            _ = send => {}
        }
    }

    /// Send a payload, fragmenting it when it exceeds the frame cap. A
    /// payload over the server's reassembly cap for its type (which the
    /// server treats as a protocol violation and drops the connection for)
    /// fails only this request.
    async fn send(&mut self, packet_type: PacketType, payload: Bytes) -> Result<(), SendError> {
        let cap = kdx_protocol::max_request_payload(packet_type);
        if payload.len() > cap {
            return Err(SendError::Rejected(ClientError::InvalidInput(format!(
                "request too large ({} bytes; the server accepts at most {cap})",
                payload.len()
            ))));
        }
        let mut seq = self.seq;
        let frames = kdx_protocol::fragment(
            packet_type,
            PacketFlags::empty(),
            payload,
            kdx_protocol::DEFAULT_MAX_FRAME_PAYLOAD,
            || {
                let s = seq;
                seq = seq.wrapping_add(1);
                s
            },
        );
        self.seq = seq;
        for frame in frames {
            self.write_frame(frame).await.map_err(SendError::Fatal)?;
        }
        Ok(())
    }

    /// Write one frame, bounded by the write timeout and abandoned at once if
    /// a disconnect is requested (a server that stops reading can't wedge
    /// the actor).
    async fn write_frame(&mut self, frame: KdxFrame) -> io::Result<()> {
        let write = tokio::time::timeout(self.opts.write_timeout, self.framed.send(frame));
        tokio::select! {
            biased;
            _ = wait_shutdown(&mut self.shutdown) => {
                Err(io::Error::new(io::ErrorKind::Interrupted, "disconnect requested"))
            }
            result = write => match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(kdx_protocol::ProtocolError::Io(e))) => Err(e),
                Ok(Err(other)) => Err(io::Error::other(other)),
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "write timed out")),
            },
        }
    }

    /// Best-effort courtesy `Disconnect` on the way out, briefly bounded.
    async fn goodbye(&mut self) {
        let header = PacketHeader {
            version: PROTOCOL_VERSION,
            packet_type: PacketType::Disconnect,
            flags: PacketFlags::empty(),
            sequence: self.seq,
            length: 0,
        };
        self.seq = self.seq.wrapping_add(1);
        let frame = KdxFrame {
            header,
            payload: Bytes::new(),
        };
        let _ = tokio::time::timeout(GOODBYE_TIMEOUT, self.framed.send(frame)).await;
    }
}

impl DownloadJob {
    /// The resume sidecar describing this download's current state.
    fn sidecar(&self, server: &str) -> Sidecar {
        Sidecar {
            server: server.to_string(),
            remote: self.remote_path.clone(),
            destination: self.local.clone(),
            transfer_id: self.id,
            size: self.size,
            chunk_size: self.chunk_size,
            sha256: self.sha256,
            bitmap: bitmap_vec(&self.have),
        }
    }
}

fn protocol_violation(what: impl std::fmt::Display) -> ClientError {
    ClientError::Server(format!("protocol violation: {what}"))
}

/// A bitmap's bytes with the unused tail bits cleared.
fn bitmap_vec(bits: &ChunkBitmap) -> Vec<u8> {
    let mut bits = bits.clone();
    bits.set_uninitialized(false);
    bits.into_vec()
}

fn spawn_sidecar_write(sidecar: Sidecar, path: PathBuf) -> JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        if let Err(e) = sidecar.write(&path) {
            warn!("could not save download resume state: {e}");
        }
    })
}

/// How a failed verification or publish settles the partial: an I/O error
/// keeps it (and its resume state) for a retry; anything else means the
/// bytes can't be trusted and a retry must start from scratch.
fn verify_failure(e: ClientError) -> (ClientError, Cleanup) {
    match e {
        e @ ClientError::Io(_) => (e, Cleanup::Keep),
        e => (e, Cleanup::Discard),
    }
}

/// Write `data` at `offset` and wait for it to reach the OS.
async fn write_at(file: &mut tokio::fs::File, offset: u64, data: &[u8]) -> io::Result<()> {
    file.seek(io::SeekFrom::Start(offset)).await?;
    file.write_all(data).await?;
    file.flush().await
}

/// Read one upload chunk at its offset, refusing if the file has changed
/// (length or mtime) since it was hashed.
async fn read_chunk(
    file: &mut tokio::fs::File,
    offset: u64,
    len: usize,
    size: u64,
    modified: Option<SystemTime>,
) -> Result<Vec<u8>, ClientError> {
    let changed = || ClientError::Transfer("local file changed during upload".into());
    let meta = file.metadata().await?;
    if meta.len() != size || meta.modified().ok() != modified {
        return Err(changed());
    }
    file.seek(io::SeekFrom::Start(offset)).await?;
    let mut buf = vec![0u8; len];
    match file.read_exact(&mut buf).await {
        Ok(_) => Ok(buf),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(changed()),
        Err(e) => Err(ClientError::Io(e)),
    }
}

/// Split a `/dir/sub/name` remote path into (`/dir/sub`, `name`).
fn split_remote(path: &str) -> (String, String) {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some((dir, name)) => {
            let dir = if dir.is_empty() { "/".to_string() } else { dir.to_string() };
            (dir, name.to_string())
        }
        None => ("/".to_string(), trimmed.to_string()),
    }
}

/// Parse a `RoleInfo::id`-style UUID string back into wire bytes.
fn parse_role_id(id: &str) -> Option<[u8; 16]> {
    Uuid::parse_str(id).ok().map(|u| *u.as_bytes())
}
