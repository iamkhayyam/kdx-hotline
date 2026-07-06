//! The connection actor: one task owning the TLS socket. It is the sole
//! reader and writer of the stream, owns the sequence counter, correlates
//! request/response pairs (the wire has no request IDs, so correlation is
//! FIFO-per-response-type), drives the one active transfer, and turns
//! unsolicited server frames into events.

use std::collections::VecDeque;
use std::io;
use std::path::PathBuf;

use bitvec::prelude::*;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use kdx_crypto::KdfParams;
use kdx_protocol::messages::{
    AccountCreate, AccountListRequest, AccountListResponse, AccountRolesRequest,
    AccountRolesResponse, AccountUpdate, AdminDisconnect, AuthChallenge, AuthRequest, AuthResponse,
    AdminBroadcast, AdminShutdown, AuthResult, ChatEvent, ChatInvite, ChatInvited, ChatJoin,
    ChatLeave, ChatSend, ChatTopic, ChatUserList, FileCatalogGenerated, FileCreateFolder,
    FileDelete, FileGenerateCatalog,
    FileListRequest, FileMove, FileSearchRequest, FileSearchResponse, NewsPostCreate,
    NewsPostDelete, NewsThreadListRequest, NewsThreadListResponse, NewsgroupCreate,
    NewsgroupListRequest, NewsgroupListResponse, ServerSettingsRequest, ServerSettingsResponse,
    ServerSettingsUpdate, TrackerListRequest, TrackerListResponse,
    FileListResponse, PresenceChange, PresenceListRequest, PresenceListResponse, PrivateMessage,
    PrivateSend, RoleAssign, RoleCreate, RoleDelete, RoleListRequest, RoleListResponse,
    RoleUnassign, RoleUpdate, TransferAccept, TransferData, TransferEnd, TransferRequest,
    UserInfoRequest, UserInfoResponse, DIRECTION_DOWNLOAD, DIRECTION_UPLOAD, TRANSFER_VERIFIED,
};
use kdx_protocol::{
    KdxCodec, KdxFrame, PacketFlags, PacketHeader, PacketType, Reassembler, PROTOCOL_VERSION,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, Duration};
use tokio_util::codec::Framed;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::error::ClientError;
use crate::event::{
    AccountSummary, Direction, Event, FileSearchEntry, NewsPost, NewsgroupInfo, PresenceUser,
    RoleInfo, ServerSettings, TrackerServer,
};
use crate::handle::{Command, Session};
use crate::transfer::{chunk_len, total_chunks, ChunkBitmap, Sidecar, DEFAULT_CHUNK_SIZE};

const KEEPALIVE: Duration = Duration::from_secs(30);
const MAX_REASSEMBLED: usize = 4 * 1024 * 1024;

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

/// The single active transfer, if any.
enum Transfer {
    Upload(UploadJob),
    Download(DownloadJob),
}

struct UploadJob {
    id: [u8; 16],
    data: Vec<u8>,
    size: u64,
    chunk_size: u32,
    total: u32,
    accepted: bool,
    reply: Option<oneshot::Sender<Result<(), ClientError>>>,
}

struct DownloadJob {
    id: [u8; 16],
    local: PathBuf,
    part_path: PathBuf,
    file: Option<tokio::fs::File>,
    size: u64,
    chunk_size: u32,
    total: u32,
    sha256: [u8; 32],
    have: ChunkBitmap,
    reply: Option<oneshot::Sender<Result<(), ClientError>>>,
}

pub(crate) struct Actor<S> {
    framed: Framed<S, KdxCodec>,
    commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
    reasm: Reassembler,
    seq: u32,
    login: Option<PendingLogin>,
    list_waiters: VecDeque<oneshot::Sender<Result<FileListResponse, ClientError>>>,
    user_list_waiters: VecDeque<oneshot::Sender<Result<Vec<PresenceUser>, ClientError>>>,
    server_list_waiters: VecDeque<oneshot::Sender<Result<Vec<TrackerServer>, ClientError>>>,
    settings_waiters: VecDeque<oneshot::Sender<Result<ServerSettings, ClientError>>>,
    catalog_waiters: VecDeque<oneshot::Sender<Result<u32, ClientError>>>,
    search_waiters: VecDeque<oneshot::Sender<Result<Vec<FileSearchEntry>, ClientError>>>,
    user_info_waiters: VecDeque<oneshot::Sender<Result<PresenceUser, ClientError>>>,
    role_waiters: VecDeque<oneshot::Sender<Result<Vec<RoleInfo>, ClientError>>>,
    account_roles_waiters: VecDeque<oneshot::Sender<Result<Vec<String>, ClientError>>>,
    account_waiters: VecDeque<oneshot::Sender<Result<Vec<AccountSummary>, ClientError>>>,
    newsgroup_waiters: VecDeque<oneshot::Sender<Result<Vec<NewsgroupInfo>, ClientError>>>,
    thread_waiters: VecDeque<oneshot::Sender<Result<Vec<NewsPost>, ClientError>>>,
    transfer: Option<Transfer>,
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
            reasm: Reassembler::default(),
            seq: 0,
            login: None,
            list_waiters: VecDeque::new(),
            user_list_waiters: VecDeque::new(),
            server_list_waiters: VecDeque::new(),
            settings_waiters: VecDeque::new(),
            catalog_waiters: VecDeque::new(),
            search_waiters: VecDeque::new(),
            user_info_waiters: VecDeque::new(),
            role_waiters: VecDeque::new(),
            account_roles_waiters: VecDeque::new(),
            account_waiters: VecDeque::new(),
            newsgroup_waiters: VecDeque::new(),
            thread_waiters: VecDeque::new(),
            transfer: None,
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
                            match self.reasm.push(frame, MAX_REASSEMBLED) {
                                Ok(Some(full)) => {
                                    if let Err(e) = self.handle_frame(full).await {
                                        break format!("protocol error: {e}");
                                    }
                                }
                                Ok(None) => {} // mid-fragment
                                Err(e) => break format!("framing error: {e}"),
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
        for waiter in self.user_list_waiters.drain(..) {
            let _ = waiter.send(Err(ClientError::Disconnected));
        }
        for waiter in self.server_list_waiters.drain(..) {
            let _ = waiter.send(Err(ClientError::Disconnected));
        }
        for waiter in self.settings_waiters.drain(..) {
            let _ = waiter.send(Err(ClientError::Disconnected));
        }
        for waiter in self.catalog_waiters.drain(..) {
            let _ = waiter.send(Err(ClientError::Disconnected));
        }
        for waiter in self.search_waiters.drain(..) {
            let _ = waiter.send(Err(ClientError::Disconnected));
        }
        for waiter in self.user_info_waiters.drain(..) {
            let _ = waiter.send(Err(ClientError::Disconnected));
        }
        for waiter in self.role_waiters.drain(..) {
            let _ = waiter.send(Err(ClientError::Disconnected));
        }
        for waiter in self.account_roles_waiters.drain(..) {
            let _ = waiter.send(Err(ClientError::Disconnected));
        }
        for waiter in self.account_waiters.drain(..) {
            let _ = waiter.send(Err(ClientError::Disconnected));
        }
        for waiter in self.newsgroup_waiters.drain(..) {
            let _ = waiter.send(Err(ClientError::Disconnected));
        }
        for waiter in self.thread_waiters.drain(..) {
            let _ = waiter.send(Err(ClientError::Disconnected));
        }
        if let Some(reply) = self.transfer.take().and_then(transfer_reply) {
            let _ = reply.send(Err(ClientError::Disconnected));
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
                let r = self.send(PacketType::ChatJoin, ChatJoin { room }.encode()).await;
                let _ = reply.send(r.map_err(Into::into));
            }
            Command::Leave { room, reply } => {
                let r = self.send(PacketType::ChatLeave, ChatLeave { room }.encode()).await;
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
            Command::CreateFolder {
                path,
                name,
                kind,
                min_read_class,
                min_write_class,
                reply,
            } => {
                let msg = FileCreateFolder {
                    path,
                    name,
                    kind,
                    min_read_class,
                    min_write_class,
                };
                match self.send(PacketType::FileCreateFolder, msg.encode()).await {
                    Ok(()) => self.list_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
            }
            Command::DeletePath { path, reply } => {
                match self.send(PacketType::FileDelete, FileDelete { path }.encode()).await {
                    Ok(()) => self.list_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
            }
            Command::MovePath {
                path,
                dest_path,
                reply,
            } => {
                let msg = FileMove { path, dest_path };
                match self.send(PacketType::FileMove, msg.encode()).await {
                    Ok(()) => self.list_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
            }
            Command::GenerateCatalog { reply } => {
                match self
                    .send(PacketType::FileGenerateCatalog, FileGenerateCatalog.encode())
                    .await
                {
                    Ok(()) => self.catalog_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
            }
            Command::SearchFiles { query, reply } => {
                match self
                    .send(PacketType::FileSearchRequest, FileSearchRequest { query }.encode())
                    .await
                {
                    Ok(()) => self.search_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
            }
            Command::ListUsers { reply } => {
                match self
                    .send(PacketType::PresenceListRequest, PresenceListRequest.encode())
                    .await
                {
                    Ok(()) => self.user_list_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
            }
            Command::ListServers { filter, reply } => {
                match self
                    .send(PacketType::TrackerListRequest, TrackerListRequest { filter }.encode())
                    .await
                {
                    Ok(()) => self.server_list_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
            }
            Command::GetServerSettings { reply } => {
                match self
                    .send(PacketType::ServerSettingsRequest, ServerSettingsRequest.encode())
                    .await
                {
                    Ok(()) => self.settings_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
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
                match self.send(PacketType::ServerSettingsUpdate, msg.encode()).await {
                    Ok(()) => self.settings_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
            }
            Command::Broadcast { text, reply } => {
                let r = self
                    .send(PacketType::AdminBroadcast, AdminBroadcast { text }.encode())
                    .await;
                let _ = reply.send(r.map_err(Into::into));
            }
            Command::ShutdownServer { message, reply } => {
                let r = self
                    .send(PacketType::AdminShutdown, AdminShutdown { message }.encode())
                    .await;
                let _ = reply.send(r.map_err(Into::into));
            }
            Command::GetUserInfo { username, reply } => {
                match self
                    .send(PacketType::UserInfoRequest, UserInfoRequest { username }.encode())
                    .await
                {
                    Ok(()) => self.user_info_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
            }
            Command::SendPrivate { to, text, reply } => {
                let r = self
                    .send(PacketType::PrivateSend, PrivateSend { to, text }.encode())
                    .await;
                let _ = reply.send(r.map_err(Into::into));
            }
            Command::InviteToChat { to, reply } => {
                let r = self.send(PacketType::ChatInvite, ChatInvite { to }.encode()).await;
                let _ = reply.send(r.map_err(Into::into));
            }
            Command::Upload {
                local,
                remote_dir,
                reply,
            } => self.start_upload(local, remote_dir, reply).await?,
            Command::Download {
                remote_path,
                local,
                reply,
            } => self.start_download(remote_path, local, reply).await?,
            Command::ListRoles { reply } => {
                match self
                    .send(PacketType::RoleListRequest, RoleListRequest.encode())
                    .await
                {
                    Ok(()) => self.role_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
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
                match self.send(PacketType::RoleCreate, msg.encode()).await {
                    Ok(()) => self.role_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
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
                match self.send(PacketType::RoleUpdate, msg.encode()).await {
                    Ok(()) => self.role_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
            }
            Command::DeleteRole { id, reply } => {
                let Some(id) = parse_role_id(&id) else {
                    let _ = reply.send(Err(ClientError::InvalidInput("bad role id".into())));
                    return Ok(());
                };
                match self
                    .send(PacketType::RoleDelete, RoleDelete { id }.encode())
                    .await
                {
                    Ok(()) => self.role_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
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
                match self.send(PacketType::RoleAssign, msg.encode()).await {
                    Ok(()) => self.role_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
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
                match self.send(PacketType::RoleUnassign, msg.encode()).await {
                    Ok(()) => self.role_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
            }
            Command::AccountRoles { username, reply } => {
                let msg = AccountRolesRequest { username };
                match self.send(PacketType::AccountRolesRequest, msg.encode()).await {
                    Ok(()) => self.account_roles_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
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
                let r = self.send(PacketType::AdminDisconnect, msg.encode()).await;
                let _ = reply.send(r.map_err(Into::into));
            }
            Command::ListAccounts { reply } => {
                match self
                    .send(PacketType::AccountListRequest, AccountListRequest.encode())
                    .await
                {
                    Ok(()) => self.account_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
            }
            Command::CreateAccount {
                username,
                password,
                base_class,
                granted,
                revoked,
                reply,
            } => {
                let msg = AccountCreate {
                    username,
                    password,
                    base_class,
                    granted,
                    revoked,
                };
                match self.send(PacketType::AccountCreate, msg.encode()).await {
                    Ok(()) => self.account_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
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
                match self.send(PacketType::AccountUpdate, msg.encode()).await {
                    Ok(()) => self.account_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
            }
            Command::ListNewsgroups { reply } => {
                match self
                    .send(PacketType::NewsgroupListRequest, NewsgroupListRequest.encode())
                    .await
                {
                    Ok(()) => self.newsgroup_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
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
                match self.send(PacketType::NewsgroupCreate, msg.encode()).await {
                    Ok(()) => self.newsgroup_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
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
                match self.send(PacketType::NewsThreadListRequest, msg.encode()).await {
                    Ok(()) => self.thread_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
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
                match self.send(PacketType::NewsPostCreate, msg.encode()).await {
                    Ok(()) => self.thread_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
            }
            Command::DeletePost { post_id, reply } => {
                let Some(post_id) = parse_role_id(&post_id) else {
                    let _ = reply.send(Err(ClientError::InvalidInput("bad post id".into())));
                    return Ok(());
                };
                let msg = NewsPostDelete { post_id };
                match self.send(PacketType::NewsPostDelete, msg.encode()).await {
                    Ok(()) => self.thread_waiters.push_back(reply),
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
            }
            Command::Disconnect => unreachable!("handled in run loop"),
        }
        Ok(())
    }

    async fn start_upload(
        &mut self,
        local: PathBuf,
        remote_dir: String,
        reply: oneshot::Sender<Result<(), ClientError>>,
    ) -> io::Result<()> {
        if self.transfer.is_some() {
            let _ = reply.send(Err(ClientError::Transfer("a transfer is already active".into())));
            return Ok(());
        }
        let name = match local.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => {
                let _ = reply.send(Err(ClientError::Transfer("invalid local file name".into())));
                return Ok(());
            }
        };
        let data = match tokio::fs::read(&local).await {
            Ok(d) => d,
            Err(e) => {
                let _ = reply.send(Err(ClientError::Io(e)));
                return Ok(());
            }
        };
        let size = data.len() as u64;
        let chunk_size = DEFAULT_CHUNK_SIZE;
        let total = total_chunks(size, chunk_size);
        let sha256: [u8; 32] = Sha256::digest(&data).into();

        let request = TransferRequest {
            direction: DIRECTION_UPLOAD,
            path: remote_dir,
            name,
            size,
            chunk_size,
            sha256,
            resume_id: [0u8; 16],
            have_bitmap: vec![],
        };
        self.send(PacketType::FileTransferStart, request.encode()).await?;
        self.transfer = Some(Transfer::Upload(UploadJob {
            id: [0u8; 16],
            data,
            size,
            chunk_size,
            total,
            accepted: false,
            reply: Some(reply),
        }));
        Ok(())
    }

    async fn start_download(
        &mut self,
        remote_path: String,
        local: PathBuf,
        reply: oneshot::Sender<Result<(), ClientError>>,
    ) -> io::Result<()> {
        if self.transfer.is_some() {
            let _ = reply.send(Err(ClientError::Transfer("a transfer is already active".into())));
            return Ok(());
        }
        let (dir, name) = split_remote(&remote_path);
        let chunk_size = DEFAULT_CHUNK_SIZE;

        // Resume from a sidecar if one matches this local target.
        let sidecar = Sidecar::read(&local);
        let (resume_id, have_bitmap) = match &sidecar {
            Some(sc) if sc.chunk_size == chunk_size => (sc.transfer_id, sc.bitmap.clone()),
            _ => ([0u8; 16], vec![]),
        };

        let request = TransferRequest {
            direction: DIRECTION_DOWNLOAD,
            path: dir,
            name,
            size: 0,
            chunk_size,
            sha256: [0u8; 32],
            resume_id,
            have_bitmap,
        };
        self.send(PacketType::FileTransferStart, request.encode()).await?;

        let part_path = with_part_suffix(&local);
        self.transfer = Some(Transfer::Download(DownloadJob {
            id: [0u8; 16],
            local,
            part_path,
            file: None,
            size: 0,
            chunk_size,
            total: 0,
            sha256: [0u8; 32],
            have: BitVec::new(),
            reply: Some(reply),
        }));
        Ok(())
    }

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
            PacketType::FileCatalogGenerated => {
                let response = FileCatalogGenerated::decode(&frame.payload)?;
                if let Some(waiter) = self.catalog_waiters.pop_front() {
                    let _ = waiter.send(Ok(response.count));
                }
            }
            PacketType::FileSearchResponse => {
                let response = FileSearchResponse::decode(&frame.payload)?;
                if let Some(waiter) = self.search_waiters.pop_front() {
                    let _ = waiter.send(Ok(response.entries.into_iter().map(Into::into).collect()));
                }
            }
            PacketType::PresenceListResponse => {
                let response = PresenceListResponse::decode(&frame.payload)?;
                if let Some(waiter) = self.user_list_waiters.pop_front() {
                    let _ = waiter.send(Ok(response.users.into_iter().map(Into::into).collect()));
                }
            }
            PacketType::UserInfoResponse => {
                let response = UserInfoResponse::decode(&frame.payload)?;
                if let Some(waiter) = self.user_info_waiters.pop_front() {
                    let _ = waiter.send(Ok(response.entry.into()));
                }
            }
            PacketType::TrackerListResponse => {
                let response = TrackerListResponse::decode(&frame.payload)?;
                if let Some(waiter) = self.server_list_waiters.pop_front() {
                    let _ = waiter.send(Ok(response.servers.into_iter().map(Into::into).collect()));
                }
            }
            PacketType::ServerSettingsResponse => {
                let response = ServerSettingsResponse::decode(&frame.payload)?;
                if let Some(waiter) = self.settings_waiters.pop_front() {
                    let _ = waiter.send(Ok(response.into()));
                }
            }
            PacketType::RoleListResponse => {
                let response = RoleListResponse::decode(&frame.payload)?;
                if let Some(waiter) = self.role_waiters.pop_front() {
                    let _ = waiter.send(Ok(response.roles.into_iter().map(Into::into).collect()));
                }
            }
            PacketType::AccountRolesResponse => {
                let response = AccountRolesResponse::decode(&frame.payload)?;
                if let Some(waiter) = self.account_roles_waiters.pop_front() {
                    let _ = waiter.send(Ok(response
                        .role_ids
                        .into_iter()
                        .map(|id| Uuid::from_bytes(id).to_string())
                        .collect()));
                }
            }
            PacketType::AccountListResponse => {
                let response = AccountListResponse::decode(&frame.payload)?;
                if let Some(waiter) = self.account_waiters.pop_front() {
                    let _ = waiter.send(Ok(response
                        .accounts
                        .into_iter()
                        .map(Into::into)
                        .collect()));
                }
            }
            PacketType::NewsgroupListResponse => {
                let response = NewsgroupListResponse::decode(&frame.payload)?;
                if let Some(waiter) = self.newsgroup_waiters.pop_front() {
                    let _ = waiter.send(Ok(response.groups.into_iter().map(Into::into).collect()));
                }
            }
            PacketType::NewsThreadListResponse => {
                let response = NewsThreadListResponse::decode(&frame.payload)?;
                if let Some(waiter) = self.thread_waiters.pop_front() {
                    let _ = waiter.send(Ok(response.posts.into_iter().map(Into::into).collect()));
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
            PacketType::Error => self.on_error(&frame.payload).await,
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
            PacketType::Pong => {}
            other => debug!(packet_type = ?other, "unhandled inbound packet"),
        }
        Ok(())
    }

    /// The server accepted our transfer. For an upload, stream the missing
    /// chunks; for a download, allocate the file and wait for data.
    async fn on_transfer_accept(&mut self, payload: &[u8]) -> Result<(), ClientError> {
        let accept = TransferAccept::decode(payload)?;
        match self.transfer.take() {
            Some(Transfer::Upload(mut job)) => {
                job.id = accept.transfer_id;
                job.accepted = true;
                let have = BitVec::<u8, Lsb0>::from_vec(accept.have_bitmap);
                // Send every chunk the server doesn't already have.
                for index in 0..job.total {
                    if have.get(index as usize).map(|b| *b).unwrap_or(false) {
                        continue;
                    }
                    let len = chunk_len(job.size, job.chunk_size, index, job.total);
                    let offset = index as usize * job.chunk_size as usize;
                    let slice = &job.data[offset..offset + len];
                    let data = TransferData {
                        transfer_id: job.id,
                        chunk_index: index,
                        chunk_hash: Sha256::digest(slice).into(),
                        data: Bytes::copy_from_slice(slice),
                    };
                    self.send_fragmented(PacketType::FileTransferData, data.encode())
                        .await?;
                    self.emit_progress(job.id, Direction::Upload, index + 1, job.total, &have)
                        .await;
                }
                self.transfer = Some(Transfer::Upload(job));
            }
            Some(Transfer::Download(mut job)) => {
                job.id = accept.transfer_id;
                job.size = accept.size;
                job.chunk_size = accept.chunk_size;
                job.total = accept.total_chunks;
                job.sha256 = accept.sha256;
                let mut have = BitVec::<u8, Lsb0>::from_vec(accept.have_bitmap);
                have.resize(job.total as usize, false);
                job.have = have;

                // Open (or reopen) the partial file, sized to the full length.
                let file = tokio::fs::OpenOptions::new()
                    .create(true)
                    .read(true)
                    .write(true)
                    .truncate(false)
                    .open(&job.part_path)
                    .await?;
                file.set_len(job.size).await?;
                job.file = Some(file);
                self.transfer = Some(Transfer::Download(job));
            }
            other => {
                // Stray accept with no matching transfer; restore state.
                self.transfer = other;
                warn!("unexpected TransferAccept");
            }
        }
        Ok(())
    }

    async fn on_transfer_data(&mut self, payload: &[u8]) -> Result<(), ClientError> {
        let data = TransferData::decode(payload)?;
        let Some(Transfer::Download(job)) = self.transfer.as_mut() else {
            return Ok(()); // not downloading; ignore
        };
        if data.transfer_id != job.id || data.chunk_index >= job.total {
            return Ok(());
        }
        let actual: [u8; 32] = Sha256::digest(&data.data).into();
        if actual != data.chunk_hash {
            return Err(ClientError::Transfer(format!(
                "chunk {} hash mismatch",
                data.chunk_index
            )));
        }
        let offset = data.chunk_index as u64 * job.chunk_size as u64;
        let file = job.file.as_mut().expect("file opened on accept");
        file.seek(io::SeekFrom::Start(offset)).await?;
        file.write_all(&data.data).await?;
        job.have.set(data.chunk_index as usize, true);

        // Persist resume state after every accepted chunk.
        let sidecar = Sidecar {
            transfer_id: job.id,
            size: job.size,
            chunk_size: job.chunk_size,
            sha256: job.sha256,
            bitmap: job.have.clone().into_vec(),
        };
        let _ = sidecar.write(&job.local);

        let done = job.have.count_ones() as u32;
        let (id, total, bitmap) = (job.id, job.total, job.have.clone());
        self.emit_progress(id, Direction::Download, done, total, &bitmap).await;
        Ok(())
    }

    async fn on_transfer_end(&mut self, payload: &[u8]) -> Result<(), ClientError> {
        let end = TransferEnd::decode(payload)?;
        match self.transfer.take() {
            Some(Transfer::Upload(mut job)) => {
                let verified = end.status == TRANSFER_VERIFIED;
                self.emit(Event::TransferComplete {
                    id: Uuid::from_bytes(job.id).to_string(),
                    direction: Direction::Upload,
                    status: end.status,
                    message: end.message.clone(),
                })
                .await;
                if let Some(reply) = job.reply.take() {
                    let _ = reply.send(if verified {
                        Ok(())
                    } else {
                        Err(ClientError::Transfer(end.message))
                    });
                }
            }
            Some(Transfer::Download(mut job)) => {
                let result = self.finish_download(&mut job).await;
                self.emit(Event::TransferComplete {
                    id: Uuid::from_bytes(job.id).to_string(),
                    direction: Direction::Download,
                    status: if result.is_ok() { TRANSFER_VERIFIED } else { 1 },
                    message: match &result {
                        Ok(()) => "verified".into(),
                        Err(e) => e.to_string(),
                    },
                })
                .await;
                if let Some(reply) = job.reply.take() {
                    let _ = reply.send(result);
                }
            }
            None => warn!("TransferEnd with no active transfer"),
        }
        Ok(())
    }

    /// Verify the downloaded file's whole-file hash, then promote `.part` to
    /// the final path and drop the resume sidecar.
    async fn finish_download(&self, job: &mut DownloadJob) -> Result<(), ClientError> {
        let mut file = job.file.take().expect("file opened on accept");
        file.flush().await?;
        file.seek(io::SeekFrom::Start(0)).await?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 128 * 1024];
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != job.sha256 {
            return Err(ClientError::Transfer("downloaded file hash mismatch".into()));
        }
        drop(file);
        tokio::fs::rename(&job.part_path, &job.local).await?;
        Sidecar::remove(&job.local);
        Ok(())
    }

    async fn on_error(&mut self, payload: &[u8]) {
        let text = String::from_utf8_lossy(payload).into_owned();
        // If a transfer is mid-negotiation, an Error frame aborts it.
        if let Some(reply) = self.transfer.take().and_then(transfer_reply) {
            let _ = reply.send(Err(ClientError::Transfer(text.clone())));
        }
        // A file listing/mutation can fail (missing privilege, name exists,
        // not found) — fail the pending waiter instead of hanging it.
        if let Some(waiter) = self.list_waiters.pop_front() {
            let _ = waiter.send(Err(ClientError::Server(text.clone())));
        }
        // A catalog generation or search can fail the same way (missing
        // privilege, or search before any catalog exists).
        if let Some(waiter) = self.catalog_waiters.pop_front() {
            let _ = waiter.send(Err(ClientError::Server(text.clone())));
        }
        if let Some(waiter) = self.search_waiters.pop_front() {
            let _ = waiter.send(Err(ClientError::Server(text.clone())));
        }
        // Likewise a pending User Info lookup (e.g. the user isn't online).
        if let Some(waiter) = self.user_info_waiters.pop_front() {
            let _ = waiter.send(Err(ClientError::Server(text.clone())));
        }
        // Role mutations routinely fail on privilege/not-found errors — don't
        // leave the caller hanging until disconnect.
        if let Some(waiter) = self.role_waiters.pop_front() {
            let _ = waiter.send(Err(ClientError::Server(text.clone())));
        }
        if let Some(waiter) = self.account_roles_waiters.pop_front() {
            let _ = waiter.send(Err(ClientError::Server(text.clone())));
        }
        // Account mutations fail on privilege / duplicate-name / not-found.
        if let Some(waiter) = self.account_waiters.pop_front() {
            let _ = waiter.send(Err(ClientError::Server(text.clone())));
        }
        // News ops fail on privilege / class thresholds / not-found.
        if let Some(waiter) = self.newsgroup_waiters.pop_front() {
            let _ = waiter.send(Err(ClientError::Server(text.clone())));
        }
        if let Some(waiter) = self.thread_waiters.pop_front() {
            let _ = waiter.send(Err(ClientError::Server(text.clone())));
        }
        // Server settings requests/updates fail on missing SERVER_ADMIN.
        if let Some(waiter) = self.settings_waiters.pop_front() {
            let _ = waiter.send(Err(ClientError::Server(text.clone())));
        }
        self.emit(Event::ServerError { text }).await;
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
            let _ = login.reply.send(Err(ClientError::AuthFailed(result.message)));
        }
        Ok(())
    }

    async fn emit_progress(
        &self,
        id: [u8; 16],
        direction: Direction,
        done: u32,
        total: u32,
        bitmap: &ChunkBitmap,
    ) {
        self.emit(Event::TransferProgress {
            id: Uuid::from_bytes(id).to_string(),
            direction,
            done,
            total,
            bitmap: bitmap.clone().into_vec(),
        })
        .await;
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
        self.write_frame(KdxFrame { header, payload }).await
    }

    /// Send a payload, fragmenting when it exceeds the frame cap.
    async fn send_fragmented(&mut self, packet_type: PacketType, payload: Bytes) -> io::Result<()> {
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
            self.write_frame(frame).await?;
        }
        Ok(())
    }

    async fn write_frame(&mut self, frame: KdxFrame) -> io::Result<()> {
        self.framed.send(frame).await.map_err(|e| match e {
            kdx_protocol::ProtocolError::Io(e) => e,
            other => io::Error::other(other),
        })
    }
}

/// Extract a transfer's reply channel for failure on teardown.
fn transfer_reply(t: Transfer) -> Option<oneshot::Sender<Result<(), ClientError>>> {
    match t {
        Transfer::Upload(mut j) => j.reply.take(),
        Transfer::Download(mut j) => j.reply.take(),
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

fn with_part_suffix(local: &std::path::Path) -> PathBuf {
    let mut s = local.as_os_str().to_owned();
    s.push(".part");
    PathBuf::from(s)
}

/// Parse a `RoleInfo::id`-style UUID string back into wire bytes.
fn parse_role_id(id: &str) -> Option<[u8; 16]> {
    Uuid::parse_str(id).ok().map(|u| *u.as_bytes())
}
