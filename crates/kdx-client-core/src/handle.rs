use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};

use kdx_crypto::{AuthContext, KdfParams, PasswordChangeContext, StoredCredential};
use kdx_protocol::messages::{
    Credential, FileInfoResponse, FileListResponse, PasswordChangeChallenge, PasswordChangeResult,
};
use zeroize::Zeroizing;

use crate::error::ClientError;
use crate::event::{
    AccountSummary, FileSearchEntry, HistoryEntry, IpRule, NewsPost, NewsgroupInfo, PresenceUser,
    RoleInfo, ServerSettings, TrackerServer,
};

/// A logged-in session's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    pub session_id: [u8; 16],
    pub class: u8,
}

/// A login password on its way to the connection actor: wiped from memory
/// when dropped, and never shown by `Debug`.
pub(crate) struct Password(zeroize::Zeroizing<String>);

impl Password {
    pub(crate) fn new(password: &str) -> Self {
        Self(zeroize::Zeroizing::new(password.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

/// A password-change challenge, plus what the proof must be bound to that
/// only the actor knows: the logged-in username and the TLS exporter value.
#[derive(Debug)]
pub(crate) struct ChangeChallenge {
    pub challenge: PasswordChangeChallenge,
    pub username: String,
    pub channel_binding: [u8; kdx_crypto::CHANNEL_BINDING_LEN],
}

/// Commands sent from a `ClientHandle` into the connection actor. Each
/// carries a `oneshot` for its result where the operation has one.
#[derive(Debug)]
pub(crate) enum Command {
    Login {
        username: String,
        password: Password,
        reply: oneshot::Sender<Result<Session, ClientError>>,
    },
    Join {
        room: String,
        reply: oneshot::Sender<Result<(), ClientError>>,
    },
    Leave {
        room: String,
        reply: oneshot::Sender<Result<(), ClientError>>,
    },
    SendChat {
        room: String,
        flags: u8,
        text: String,
        reply: oneshot::Sender<Result<(), ClientError>>,
    },
    SetTopic {
        room: String,
        topic: String,
        reply: oneshot::Sender<Result<(), ClientError>>,
    },
    ListFiles {
        path: String,
        reply: oneshot::Sender<Result<FileListResponse, ClientError>>,
    },
    CreateFolder {
        path: String,
        name: String,
        kind: u8,
        min_read_class: u8,
        min_write_class: u8,
        owner: Option<String>,
        reply: oneshot::Sender<Result<FileListResponse, ClientError>>,
    },
    DeletePath {
        path: String,
        reply: oneshot::Sender<Result<FileListResponse, ClientError>>,
    },
    MovePath {
        path: String,
        dest_path: String,
        reply: oneshot::Sender<Result<FileListResponse, ClientError>>,
    },
    AliasPath {
        source_path: String,
        dest_path: String,
        reply: oneshot::Sender<Result<FileListResponse, ClientError>>,
    },
    GetFileInfo {
        path: String,
        reply: oneshot::Sender<Result<FileInfoResponse, ClientError>>,
    },
    /// No reply: the server just applies the identity change (fire-and-forget).
    SetIdentity {
        name: String,
        description: String,
    },
    GenerateCatalog {
        reply: oneshot::Sender<Result<u32, ClientError>>,
    },
    SearchFiles {
        query: String,
        reply: oneshot::Sender<Result<Vec<FileSearchEntry>, ClientError>>,
    },
    ListUsers {
        reply: oneshot::Sender<Result<Vec<PresenceUser>, ClientError>>,
    },
    ListServers {
        filter: String,
        reply: oneshot::Sender<Result<Vec<TrackerServer>, ClientError>>,
    },
    GetServerSettings {
        reply: oneshot::Sender<Result<ServerSettings, ClientError>>,
    },
    UpdateServerSettings {
        name: String,
        description: String,
        greeting: String,
        max_users: u32,
        reply: oneshot::Sender<Result<ServerSettings, ClientError>>,
    },
    Broadcast {
        text: String,
        reply: oneshot::Sender<Result<(), ClientError>>,
    },
    ShutdownServer {
        message: String,
        reply: oneshot::Sender<Result<(), ClientError>>,
    },
    ListHistory {
        limit: u32,
        reply: oneshot::Sender<Result<Vec<HistoryEntry>, ClientError>>,
    },
    ListIpRules {
        reply: oneshot::Sender<Result<Vec<IpRule>, ClientError>>,
    },
    CreateIpRule {
        position: i32,
        action: String,
        cidr: String,
        note: String,
        reply: oneshot::Sender<Result<Vec<IpRule>, ClientError>>,
    },
    DeleteIpRule {
        id: String,
        reply: oneshot::Sender<Result<Vec<IpRule>, ClientError>>,
    },
    ListConnections {
        reply: oneshot::Sender<Result<Vec<PresenceUser>, ClientError>>,
    },
    SetRoomFlags {
        room: String,
        min_class_join: u8,
        interview_mode: bool,
        reply: oneshot::Sender<Result<(), ClientError>>,
    },
    GetUserInfo {
        username: String,
        reply: oneshot::Sender<Result<PresenceUser, ClientError>>,
    },
    SendPrivate {
        to: String,
        text: String,
        reply: oneshot::Sender<Result<(), ClientError>>,
    },
    InviteToChat {
        to: String,
        reply: oneshot::Sender<Result<String, ClientError>>,
    },
    Upload {
        local: PathBuf,
        remote_dir: String,
        reply: oneshot::Sender<Result<(), ClientError>>,
    },
    Download {
        remote_path: String,
        local: PathBuf,
        expected_size: Option<u64>,
        reply: oneshot::Sender<Result<(), ClientError>>,
    },
    /// Abort the active transfer, if any; replies whether one was active.
    CancelTransfer {
        reply: oneshot::Sender<Result<bool, ClientError>>,
    },
    ListRoles {
        reply: oneshot::Sender<Result<Vec<RoleInfo>, ClientError>>,
    },
    CreateRole {
        name: String,
        privileges: u32,
        rank: i32,
        color: String,
        reply: oneshot::Sender<Result<Vec<RoleInfo>, ClientError>>,
    },
    UpdateRole {
        id: String,
        name: String,
        privileges: u32,
        rank: i32,
        color: String,
        reply: oneshot::Sender<Result<Vec<RoleInfo>, ClientError>>,
    },
    DeleteRole {
        id: String,
        reply: oneshot::Sender<Result<Vec<RoleInfo>, ClientError>>,
    },
    AssignRole {
        username: String,
        role_id: String,
        reply: oneshot::Sender<Result<Vec<RoleInfo>, ClientError>>,
    },
    UnassignRole {
        username: String,
        role_id: String,
        reply: oneshot::Sender<Result<Vec<RoleInfo>, ClientError>>,
    },
    AccountRoles {
        username: String,
        reply: oneshot::Sender<Result<Vec<String>, ClientError>>,
    },
    DisconnectUser {
        username: String,
        reason: String,
        ban_secs: u32,
        reply: oneshot::Sender<Result<(), ClientError>>,
    },
    ListAccounts {
        reply: oneshot::Sender<Result<Vec<AccountSummary>, ClientError>>,
    },
    CreateAccount {
        username: String,
        credential: Credential,
        base_class: u8,
        granted: u32,
        revoked: u32,
        reply: oneshot::Sender<Result<Vec<AccountSummary>, ClientError>>,
    },
    UpdateAccount {
        username: String,
        base_class: u8,
        granted: u32,
        revoked: u32,
        reply: oneshot::Sender<Result<Vec<AccountSummary>, ClientError>>,
    },
    SetAccountPassword {
        username: String,
        credential: Credential,
        reply: oneshot::Sender<Result<Vec<AccountSummary>, ClientError>>,
    },
    /// `PasswordChangeBegin`; answered with the challenge (or `Error`).
    BeginPasswordChange {
        reply: oneshot::Sender<Result<ChangeChallenge, ClientError>>,
    },
    /// `PasswordChangeProof`; answered with the result (or `Error`).
    FinishPasswordChange {
        proof: [u8; 32],
        credential: Credential,
        reply: oneshot::Sender<Result<PasswordChangeResult, ClientError>>,
    },
    ListNewsgroups {
        reply: oneshot::Sender<Result<Vec<NewsgroupInfo>, ClientError>>,
    },
    CreateNewsgroup {
        name: String,
        description: String,
        min_read_class: u8,
        min_post_class: u8,
        reply: oneshot::Sender<Result<Vec<NewsgroupInfo>, ClientError>>,
    },
    ListThread {
        newsgroup_id: String,
        reply: oneshot::Sender<Result<Vec<NewsPost>, ClientError>>,
    },
    CreatePost {
        newsgroup_id: String,
        parent_id: String,
        subject: String,
        body: String,
        reply: oneshot::Sender<Result<Vec<NewsPost>, ClientError>>,
    },
    DeletePost {
        post_id: String,
        reply: oneshot::Sender<Result<Vec<NewsPost>, ClientError>>,
    },
}

/// Handle to a connected KDX client. Cloneable; every method round-trips a
/// command into the single connection actor.
///
/// Every request is bounded by `ClientConfig::request_timeout` (default
/// 30 s) and fails with `ClientError::Timeout` if the server doesn't answer
/// in time; uploads and downloads are exempt (they can legitimately run for
/// a long time) and instead fail if the connection goes quiet. Strings that
/// can't be encoded on the wire (over 65,535 bytes) fail that call with
/// `ClientError::InvalidInput` instead of corrupting the session.
#[derive(Clone, Debug)]
pub struct ClientHandle {
    pub(crate) tx: mpsc::Sender<Command>,
    /// Out-of-band disconnect signal: works even when the command queue is
    /// full or the actor is blocked writing to a stalled server.
    pub(crate) shutdown: Arc<watch::Sender<bool>>,
    pub(crate) request_timeout: Duration,
    /// Held for a whole password change: the server keeps one challenge per
    /// connection, so two interleaved changes would answer each other's
    /// challenges (and be counted as wrong passwords).
    pub(crate) password_change: Arc<tokio::sync::Mutex<()>>,
}

/// Longest string the wire's u16 length prefix can carry.
const MAX_WIRE_STR: usize = u16::MAX as usize;

/// Copy a caller's string for the wire, refusing ones that would overflow
/// the u16 length prefix (the encoder would silently truncate the prefix
/// and the server would drop the connection on the malformed payload).
fn wire(s: &str) -> Result<String, ClientError> {
    if s.len() > MAX_WIRE_STR {
        return Err(ClientError::InvalidInput(format!(
            "text is too long ({} bytes; the limit is {MAX_WIRE_STR})",
            s.len()
        )));
    }
    Ok(s.to_owned())
}

/// Derive a fresh SCRAM credential for `password` on a blocking thread
/// (Argon2 is CPU- and memory-heavy), wiping the copy it works on.
async fn derive_stored(password: &str) -> Result<StoredCredential, ClientError> {
    let password = Zeroizing::new(password.to_owned());
    tokio::task::spawn_blocking(move || StoredCredential::derive(&password))
        .await
        .map_err(|_| blocking_failed())?
        .map_err(ClientError::from)
}

/// [`derive_stored`], in wire form. Refuses an empty password.
async fn derive_credential(password: &str) -> Result<Credential, ClientError> {
    if password.is_empty() {
        return Err(ClientError::InvalidInput("a password is required".into()));
    }
    Ok(to_wire(&derive_stored(password).await?))
}

fn to_wire(credential: &StoredCredential) -> Credential {
    Credential {
        m_cost: credential.params.m_cost,
        t_cost: credential.params.t_cost,
        p_cost: credential.params.p_cost,
        salt: credential.salt.clone(),
        stored_key: credential.stored_key,
        server_key: credential.server_key,
    }
}

fn blocking_failed() -> ClientError {
    ClientError::Io(std::io::Error::other("credential derivation failed"))
}

impl ClientHandle {
    async fn send<T>(
        &self,
        make: impl FnOnce(oneshot::Sender<Result<T, ClientError>>) -> Command,
    ) -> Result<T, ClientError> {
        self.send_with_timeout(make, Some(self.request_timeout)).await
    }

    async fn send_with_timeout<T>(
        &self,
        make: impl FnOnce(oneshot::Sender<Result<T, ClientError>>) -> Command,
        limit: Option<Duration>,
    ) -> Result<T, ClientError> {
        let (reply, rx) = oneshot::channel();
        let round_trip = async {
            self.tx
                .send(make(reply))
                .await
                .map_err(|_| ClientError::Disconnected)?;
            rx.await.map_err(|_| ClientError::Disconnected)?
        };
        match limit {
            // Dropping `rx` on timeout is safe: the actor keeps the request
            // queued and discards the late reply when it arrives.
            Some(limit) => tokio::time::timeout(limit, round_trip)
                .await
                .map_err(|_| ClientError::Timeout("no reply from the server".into()))?,
            None => round_trip.await,
        }
    }

    /// Log in. A connection logs in once: after a successful login this
    /// fails at once with `ClientError::InvalidInput` (reconnect to change
    /// accounts). A failed login may be retried.
    pub async fn login(&self, username: &str, password: &str) -> Result<Session, ClientError> {
        self.send(|reply| Command::Login {
            username: username.to_owned(),
            password: Password::new(password),
            reply,
        })
        .await
    }

    /// Join a chat room. Resolves once the server has answered: `Ok` means
    /// you are in the room; `Err(ClientError::Server)` means it refused
    /// (not invited to a private room, joining too fast, too many rooms,
    /// class gate), in which case you are still in whatever rooms you were
    /// in before. The refusal is also emitted as `Event::ServerError`.
    pub async fn join(&self, room: &str) -> Result<(), ClientError> {
        let room = wire(room)?;
        self.send(|reply| Command::Join { room, reply }).await
    }

    pub async fn leave(&self, room: &str) -> Result<(), ClientError> {
        let room = wire(room)?;
        self.send(|reply| Command::Leave { room, reply }).await
    }

    /// Send a chat message. `flags` may include `kdx_protocol::messages::CHAT_ACTION`.
    pub async fn send_chat(&self, room: &str, flags: u8, text: &str) -> Result<(), ClientError> {
        let (room, text) = (wire(room)?, wire(text)?);
        self.send(|reply| Command::SendChat {
            room,
            flags,
            text,
            reply,
        })
        .await
    }

    pub async fn set_topic(&self, room: &str, topic: &str) -> Result<(), ClientError> {
        let (room, topic) = (wire(room)?, wire(topic)?);
        self.send(|reply| Command::SetTopic { room, topic, reply })
            .await
    }

    pub async fn list_files(&self, path: &str) -> Result<FileListResponse, ClientError> {
        let path = wire(path)?;
        self.send(|reply| Command::ListFiles { path, reply }).await
    }

    /// Fetch node metadata for the Files "Get Info" verb. Requires read
    /// access to the node; aliases resolve to their target.
    pub async fn get_file_info(&self, path: &str) -> Result<FileInfoResponse, ClientError> {
        let path = wire(path)?;
        self.send(|reply| Command::GetFileInfo { path, reply }).await
    }

    /// Set your own display name / description (`/name`, `/desc`). The
    /// server rebroadcasts presence so everyone sees the change live.
    /// Fire-and-forget: the server applies it without a reply.
    pub async fn set_identity(&self, name: &str, description: &str) -> Result<(), ClientError> {
        let (name, description) = (wire(name)?, wire(description)?);
        let send = self.tx.send(Command::SetIdentity { name, description });
        tokio::time::timeout(self.request_timeout, send)
            .await
            .map_err(|_| ClientError::Timeout("client is busy".into()))?
            .map_err(|_| ClientError::Disconnected)
    }

    /// Create a folder-like node (`kind`: 0 directory, 2 drop box, 3 upload
    /// folder) under `path` with class thresholds. Requires FILE_MANAGE_TREE.
    /// Resolves with the updated listing of `path`.
    pub async fn create_folder(
        &self,
        path: &str,
        name: &str,
        kind: u8,
        min_read_class: u8,
        min_write_class: u8,
        owner: Option<&str>,
    ) -> Result<FileListResponse, ClientError> {
        let (path, name) = (wire(path)?, wire(name)?);
        let owner = owner.map(wire).transpose()?;
        self.send(|reply| Command::CreateFolder {
            path,
            name,
            kind,
            min_read_class,
            min_write_class,
            owner,
            reply,
        })
        .await
    }

    /// Delete a node (recursively, for folders). Requires FILE_MANAGE_TREE.
    /// Resolves with the updated listing of the deleted node's parent.
    pub async fn delete_path(&self, path: &str) -> Result<FileListResponse, ClientError> {
        let path = wire(path)?;
        self.send(|reply| Command::DeletePath { path, reply }).await
    }

    /// Move a node into a different folder (Select-for-Move → Move-into),
    /// keeping its name. Requires FILE_MANAGE_TREE and write access to both
    /// the node and the destination. Resolves with the updated listing of
    /// `dest_path`.
    pub async fn move_path(
        &self,
        path: &str,
        dest_path: &str,
    ) -> Result<FileListResponse, ClientError> {
        let (path, dest_path) = (wire(path)?, wire(dest_path)?);
        self.send(|reply| Command::MovePath {
            path,
            dest_path,
            reply,
        })
        .await
    }

    /// Create an alias at `dest_path` pointing to `source_path`
    /// (Select-for-Alias → Alias-into). The alias inherits the source's leaf
    /// name and behaves like the target for read/download. Requires
    /// FILE_MANAGE_TREE and write access to the destination. Resolves with
    /// the updated listing of `dest_path`.
    pub async fn alias_path(
        &self,
        source_path: &str,
        dest_path: &str,
    ) -> Result<FileListResponse, ClientError> {
        let (source_path, dest_path) = (wire(source_path)?, wire(dest_path)?);
        self.send(|reply| Command::AliasPath {
            source_path,
            dest_path,
            reply,
        })
        .await
    }

    /// (Re)build the server's search catalog. Requires FILE_MANAGE_TREE.
    /// Resolves with the number of entries indexed. The catalog does not
    /// auto-refresh — call again after tree changes to keep search current.
    pub async fn generate_catalog(&self) -> Result<u32, ClientError> {
        self.send(|reply| Command::GenerateCatalog { reply }).await
    }

    /// Search the last-generated catalog. Empty `query` matches everything
    /// visible to the caller's class. Errors if no catalog has been
    /// generated yet.
    pub async fn search_files(&self, query: &str) -> Result<Vec<FileSearchEntry>, ClientError> {
        let query = wire(query)?;
        self.send(|reply| Command::SearchFiles { query, reply }).await
    }

    /// Fetch the server-wide roster of currently online users (the global
    /// User List, distinct from a chat room's member list).
    pub async fn list_users(&self) -> Result<Vec<PresenceUser>, ClientError> {
        self.send(|reply| Command::ListUsers { reply }).await
    }

    /// Fetch the tracker directory of live servers (the Tracker window),
    /// optionally filtered by a case-insensitive name substring (empty = all).
    pub async fn list_servers(&self, filter: &str) -> Result<Vec<TrackerServer>, ClientError> {
        let filter = wire(filter)?;
        self.send(|reply| Command::ListServers { filter, reply }).await
    }

    /// Fetch the live server settings (the Server Settings window). Requires
    /// `SERVER_ADMIN`.
    pub async fn get_server_settings(&self) -> Result<ServerSettings, ClientError> {
        self.send(|reply| Command::GetServerSettings { reply }).await
    }

    /// Replace the live-editable server settings (name/description/greeting/
    /// max_users) wholesale. Requires `SERVER_ADMIN`. Resolves with the
    /// updated settings.
    pub async fn update_server_settings(
        &self,
        name: &str,
        description: &str,
        greeting: &str,
        max_users: u32,
    ) -> Result<ServerSettings, ClientError> {
        let (name, description, greeting) = (wire(name)?, wire(description)?, wire(greeting)?);
        self.send(|reply| Command::UpdateServerSettings {
            name,
            description,
            greeting,
            max_users,
            reply,
        })
        .await
    }

    /// Send `text` to every currently-connected session, regardless of chat
    /// room membership. Requires `SERVER_ADMIN`. Resolves once the request is
    /// written; the server's ack (or refusal) arrives as `Event::ServerInfo`
    /// (or `Event::ServerError`).
    pub async fn broadcast(&self, text: &str) -> Result<(), ClientError> {
        let text = wire(text)?;
        self.send(|reply| Command::Broadcast { text, reply }).await
    }

    /// Gracefully shut down the server: broadcast `message`, disconnect every
    /// session (including this one), and stop accepting new connections.
    /// Requires `SERVER_ADMIN`. "Exit" only — never touches the host OS.
    pub async fn shutdown_server(&self, message: &str) -> Result<(), ClientError> {
        let message = wire(message)?;
        self.send(|reply| Command::ShutdownServer { message, reply })
            .await
    }

    /// Fetch the most recent audit-log entries (the Server History window),
    /// newest first. Requires `SERVER_ADMIN`; otherwise resolves to
    /// `ClientError::Server`.
    pub async fn list_history(&self, limit: u32) -> Result<Vec<HistoryEntry>, ClientError> {
        self.send(|reply| Command::ListHistory { limit, reply })
            .await
    }

    /// List Allow-Deny IP rules in priority order (lowest `position` first).
    /// Requires `SERVER_ADMIN`.
    pub async fn list_ip_rules(&self) -> Result<Vec<IpRule>, ClientError> {
        self.send(|reply| Command::ListIpRules { reply }).await
    }

    /// Create a new IP rule. `action` must be "allow" or "deny"; `cidr` must
    /// parse as an `ipnet::IpNet` (e.g. "1.2.3.4/32", "10.0.0.0/8",
    /// "2001:db8::/32"). Resolves with the server's full, updated rule list.
    /// Requires `SERVER_ADMIN`.
    pub async fn create_ip_rule(
        &self,
        position: i32,
        action: &str,
        cidr: &str,
        note: &str,
    ) -> Result<Vec<IpRule>, ClientError> {
        let (action, cidr, note) = (wire(action)?, wire(cidr)?, wire(note)?);
        self.send(|reply| Command::CreateIpRule {
            position,
            action,
            cidr,
            note,
            reply,
        })
        .await
    }

    /// Delete an IP rule by id. Resolves with the server's full, updated rule
    /// list. Requires `SERVER_ADMIN`.
    pub async fn delete_ip_rule(&self, id: &str) -> Result<Vec<IpRule>, ClientError> {
        let id = wire(id)?;
        self.send(|reply| Command::DeleteIpRule { id, reply }).await
    }

    /// Fetch the live connection roster (Connection Monitor). Returns the same
    /// shape as `list_users`, but the server gates it on `USER_KICK` — plain
    /// users get `ClientError::Server`. Refresh at whatever cadence you like;
    /// there's no push channel for connection changes distinct from
    /// presence.
    pub async fn list_connections(&self) -> Result<Vec<PresenceUser>, ClientError> {
        self.send(|reply| Command::ListConnections { reply }).await
    }

    /// Change a chat room's admin-configurable flags. Requires membership
    /// in `room` and `CHAT_SET_TOPIC`. `min_class_join` is clamped 0..=3;
    /// setting `interview_mode = true` mutes every member who lacks
    /// `CHAT_SET_TOPIC` until it's toggled off. Resolves once the request
    /// is written; the room's own system-message event announces the
    /// change to every joined member.
    pub async fn set_room_flags(
        &self,
        room: &str,
        min_class_join: u8,
        interview_mode: bool,
    ) -> Result<(), ClientError> {
        let room = wire(room)?;
        self.send(|reply| Command::SetRoomFlags {
            room,
            min_class_join,
            interview_mode,
            reply,
        })
        .await
    }

    /// Fetch one user's detail (login/idle time, address) for the User Info
    /// window. Errors if the user isn't currently online.
    pub async fn get_user_info(&self, username: &str) -> Result<PresenceUser, ClientError> {
        let username = wire(username)?;
        self.send(|reply| Command::GetUserInfo { username, reply })
            .await
    }

    /// Send a private (direct) message to `to`. Resolves once the send frame
    /// is written; delivery and the sender-echo arrive as
    /// `Event::PrivateMessage`. Errors surface via `Event::ServerError` (e.g.
    /// the recipient is offline).
    pub async fn send_private(&self, to: &str, text: &str) -> Result<(), ClientError> {
        let (to, text) = (wire(to)?, wire(text)?);
        self.send(|reply| Command::SendPrivate { to, text, reply })
            .await
    }

    /// Invite `to` into a fresh private chat and return the new room's id
    /// (`priv-<uuid>`). The server joins you to that room straight away, so
    /// switch the UI to it (send with `send_chat(&room, ..)`); the invitee —
    /// if online — gets `Event::ChatInvited` for the same room.
    ///
    /// Resolves only once the server has answered: `Err(ClientError::Server)`
    /// if it refused (invitee offline, inviting yourself, missing
    /// `CHAT_PRIVATE`) — the refusal is also emitted as `Event::ServerError`
    /// as before. The room id is learned from the room's first member list
    /// (`Event::UserList` for a `priv-*` room this client didn't join
    /// itself), since the wire ack doesn't carry it.
    pub async fn invite_to_chat(&self, to: &str) -> Result<String, ClientError> {
        let to = wire(to)?;
        self.send(|reply| Command::InviteToChat { to, reply }).await
    }

    /// Upload a local file into `remote_dir`; the remote name is the local
    /// file's basename. The file must be a regular file of at most 16 GiB;
    /// it is hashed and then streamed from disk (never read whole into
    /// memory), and the upload fails if the file changes meanwhile.
    /// Resolves when the transfer verifies (or fails);
    /// `Event::TransferProgress` is emitted throughout. Other commands keep
    /// working while it runs; `cancel_transfer` or `disconnect` abort it.
    pub async fn upload(&self, local: PathBuf, remote_dir: &str) -> Result<(), ClientError> {
        let remote_dir = wire(remote_dir)?;
        self.send_with_timeout(
            |reply| Command::Upload {
                local,
                remote_dir,
                reply,
            },
            None,
        )
        .await
    }

    /// Download `remote_path` (a `/dir/file` path) to `local`, resuming from a
    /// `.kdxpart` sidecar if one matches this server and remote file. The
    /// bytes accumulate in `<local>.kdxdata` and are renamed to `local` only
    /// after the whole-file hash verifies. Resolves on completion.
    ///
    /// `local` is used verbatim: derive its file name from server-supplied
    /// names only via [`crate::safe_local_file_name`].
    pub async fn download(&self, remote_path: &str, local: PathBuf) -> Result<(), ClientError> {
        self.download_inner(remote_path, local, None).await
    }

    /// Like [`download`](Self::download), but refuse the transfer unless the
    /// server's announced size equals `expected_size` (e.g. the size shown
    /// in the listing the user picked the file from).
    pub async fn download_expecting(
        &self,
        remote_path: &str,
        local: PathBuf,
        expected_size: u64,
    ) -> Result<(), ClientError> {
        self.download_inner(remote_path, local, Some(expected_size))
            .await
    }

    async fn download_inner(
        &self,
        remote_path: &str,
        local: PathBuf,
        expected_size: Option<u64>,
    ) -> Result<(), ClientError> {
        let remote_path = wire(remote_path)?;
        self.send_with_timeout(
            |reply| Command::Download {
                remote_path,
                local,
                expected_size,
                reply,
            },
            None,
        )
        .await
    }

    /// Abort the active upload or download, if any. Its `upload`/`download`
    /// call resolves with `ClientError::Transfer("cancelled")`; a cancelled
    /// download keeps its resume state. Returns whether a transfer was
    /// active.
    pub async fn cancel_transfer(&self) -> Result<bool, ClientError> {
        self.send(|reply| Command::CancelTransfer { reply }).await
    }

    /// Fetch every custom role defined on the server (the Roles window's
    /// initial load and refresh).
    pub async fn list_roles(&self) -> Result<Vec<RoleInfo>, ClientError> {
        self.send(|reply| Command::ListRoles { reply }).await
    }

    /// Define a new role. Requires the SysOp's account to hold `USER_ADMIN`;
    /// otherwise resolves to `ClientError::Server`. Resolves with the
    /// server's full, updated role list.
    pub async fn create_role(
        &self,
        name: &str,
        privileges: u32,
        rank: i32,
        color: &str,
    ) -> Result<Vec<RoleInfo>, ClientError> {
        let (name, color) = (wire(name)?, wire(color)?);
        self.send(|reply| Command::CreateRole {
            name,
            privileges,
            rank,
            color,
            reply,
        })
        .await
    }

    /// Rename/re-scope an existing role by id (a UUID string from
    /// `RoleInfo::id`). Requires `USER_ADMIN`.
    pub async fn update_role(
        &self,
        id: &str,
        name: &str,
        privileges: u32,
        rank: i32,
        color: &str,
    ) -> Result<Vec<RoleInfo>, ClientError> {
        let (id, name, color) = (wire(id)?, wire(name)?, wire(color)?);
        self.send(|reply| Command::UpdateRole {
            id,
            name,
            privileges,
            rank,
            color,
            reply,
        })
        .await
    }

    /// Delete a role outright. Requires `USER_ADMIN`.
    pub async fn delete_role(&self, id: &str) -> Result<Vec<RoleInfo>, ClientError> {
        let id = wire(id)?;
        self.send(|reply| Command::DeleteRole { id, reply }).await
    }

    /// Attach a role to an account by username. Requires `USER_ADMIN`.
    /// Idempotent server-side.
    pub async fn assign_role(&self, username: &str, role_id: &str) -> Result<Vec<RoleInfo>, ClientError> {
        let (username, role_id) = (wire(username)?, wire(role_id)?);
        self.send(|reply| Command::AssignRole {
            username,
            role_id,
            reply,
        })
        .await
    }

    /// Detach a role from an account by username. Requires `USER_ADMIN`.
    pub async fn unassign_role(&self, username: &str, role_id: &str) -> Result<Vec<RoleInfo>, ClientError> {
        let (username, role_id) = (wire(username)?, wire(role_id)?);
        self.send(|reply| Command::UnassignRole {
            username,
            role_id,
            reply,
        })
        .await
    }

    /// Which roles does `username` currently hold? Requires `USER_ADMIN`.
    /// Returns role ids (UUID strings, matching `RoleInfo::id`).
    pub async fn account_roles(&self, username: &str) -> Result<Vec<String>, ClientError> {
        let username = wire(username)?;
        self.send(|reply| Command::AccountRoles { username, reply })
            .await
    }

    /// Forcibly disconnect another user by username. Requires `USER_KICK`; a
    /// non-zero `ban_secs` additionally requires `USER_BAN` and records an
    /// expiring ban that refuses that account's logins until it lapses.
    /// Resolves once the request frame is written; the server's acknowledgement
    /// (or refusal) arrives as `Event::ServerInfo` / `Event::ServerError`.
    pub async fn disconnect_user(
        &self,
        username: &str,
        reason: &str,
        ban_secs: u32,
    ) -> Result<(), ClientError> {
        let (username, reason) = (wire(username)?, wire(reason)?);
        self.send(|reply| Command::DisconnectUser {
            username,
            reason,
            ban_secs,
            reply,
        })
        .await
    }

    /// List every account (the Accounts window). Requires `USER_ADMIN`;
    /// otherwise resolves to `ClientError::Server`.
    pub async fn list_accounts(&self) -> Result<Vec<AccountSummary>, ClientError> {
        self.send(|reply| Command::ListAccounts { reply }).await
    }

    /// Provision a new account with initial password `password`. Its
    /// credential (fresh salt, Argon2id, StoredKey/ServerKey) is derived
    /// here, on a blocking thread; the password itself never leaves this
    /// process. Requires `USER_ADMIN`. Resolves with the server's full,
    /// updated account list. Password policy (length etc.) is the caller's:
    /// the server can't see the password to enforce any.
    pub async fn create_account(
        &self,
        username: &str,
        password: &str,
        base_class: u8,
        granted: u32,
        revoked: u32,
    ) -> Result<Vec<AccountSummary>, ClientError> {
        let username = wire(username)?;
        let credential = derive_credential(password).await?;
        self.send(|reply| Command::CreateAccount {
            username,
            credential,
            base_class,
            granted,
            revoked,
            reply,
        })
        .await
    }

    /// Reset another account's password to `new_password` (an
    /// administrator's reset: no proof of the old one). The credential is
    /// derived here; the password never leaves this process. Requires
    /// `USER_ADMIN` and the right to manage that account (the same rules as
    /// [`ClientHandle::update_account`]); your own password goes through
    /// [`ClientHandle::change_password`] instead. The server disconnects the
    /// account's live sessions. Resolves with the updated account list.
    pub async fn set_account_password(
        &self,
        username: &str,
        new_password: &str,
    ) -> Result<Vec<AccountSummary>, ClientError> {
        let username = wire(username)?;
        let credential = derive_credential(new_password).await?;
        self.send(|reply| Command::SetAccountPassword {
            username,
            credential,
            reply,
        })
        .await
    }

    /// Change the logged-in account's own password. Proves knowledge of
    /// `current` with a fresh challenge-response bound to this TLS session
    /// and hands the server a credential derived here from `new` — neither
    /// password crosses the wire. The server's answer is accepted only with
    /// a server signature proving it held the old credential (otherwise the
    /// connection is dropped, as for a login). On success the server signs
    /// out the account's other sessions; this one stays logged in, and the
    /// server's message is returned.
    ///
    /// Fails with `ClientError::AuthFailed` for a wrong current password
    /// (the server counts these like failed logins, and drops the
    /// connection after a few), and `ClientError::Server` when the server
    /// refuses (guest account, throttled, not supported). Runs Argon2 twice,
    /// on blocking threads.
    pub async fn change_password(&self, current: &str, new: &str) -> Result<String, ClientError> {
        if new.is_empty() {
            return Err(ClientError::InvalidInput("the new password is empty".into()));
        }
        let current = Zeroizing::new(current.to_owned());
        let _one_at_a_time = self.password_change.lock().await;
        // Derive the new credential while the server picks a challenge.
        let (derived, begun) = tokio::join!(
            derive_stored(new),
            self.send(|reply| Command::BeginPasswordChange { reply })
        );
        let new_credential = derived?;
        let ChangeChallenge {
            challenge,
            username,
            channel_binding,
        } = begun?;
        let for_proof = new_credential.clone();
        let proof = tokio::task::spawn_blocking(move || {
            kdx_crypto::password_change_proof(
                &current,
                &PasswordChangeContext {
                    current: AuthContext {
                        username: &username,
                        challenge: &challenge.challenge,
                        salt: &challenge.salt,
                        params: KdfParams {
                            m_cost: challenge.m_cost,
                            t_cost: challenge.t_cost,
                            p_cost: challenge.p_cost,
                        },
                        channel_binding: &channel_binding,
                    },
                    new_credential: &for_proof,
                },
            )
        })
        .await
        .map_err(|_| blocking_failed())??;
        let credential = to_wire(&new_credential);
        let result = self
            .send(|reply| Command::FinishPasswordChange {
                proof: proof.proof,
                credential,
                reply,
            })
            .await?;
        if !result.success {
            return Err(ClientError::AuthFailed(result.message));
        }
        if !proof.verify_server_signature(&result.server_signature) {
            self.disconnect().await;
            return Err(ClientError::AuthFailed(
                "server failed to prove it knows this account".into(),
            ));
        }
        Ok(result.message)
    }

    /// Change an account's class and privilege overrides (not its password).
    /// Requires `USER_ADMIN`.
    pub async fn update_account(
        &self,
        username: &str,
        base_class: u8,
        granted: u32,
        revoked: u32,
    ) -> Result<Vec<AccountSummary>, ClientError> {
        let username = wire(username)?;
        self.send(|reply| Command::UpdateAccount {
            username,
            base_class,
            granted,
            revoked,
            reply,
        })
        .await
    }

    /// List the newsgroups the caller may read (the News window's tree).
    pub async fn list_newsgroups(&self) -> Result<Vec<NewsgroupInfo>, ClientError> {
        self.send(|reply| Command::ListNewsgroups { reply }).await
    }

    /// Create a newsgroup with class thresholds. Requires `USER_ADMIN`.
    /// Resolves with the updated newsgroup list.
    pub async fn create_newsgroup(
        &self,
        name: &str,
        description: &str,
        min_read_class: u8,
        min_post_class: u8,
    ) -> Result<Vec<NewsgroupInfo>, ClientError> {
        let (name, description) = (wire(name)?, wire(description)?);
        self.send(|reply| Command::CreateNewsgroup {
            name,
            description,
            min_read_class,
            min_post_class,
            reply,
        })
        .await
    }

    /// Every post in a newsgroup, oldest first; the caller builds the thread
    /// tree from each post's `parent_id`.
    pub async fn list_thread(&self, newsgroup_id: &str) -> Result<Vec<NewsPost>, ClientError> {
        let newsgroup_id = wire(newsgroup_id)?;
        self.send(|reply| Command::ListThread {
            newsgroup_id,
            reply,
        })
        .await
    }

    /// Post to a newsgroup. `parent_id` empty starts a new thread; otherwise it
    /// replies to that post. Resolves with the newsgroup's updated post list.
    pub async fn create_post(
        &self,
        newsgroup_id: &str,
        parent_id: &str,
        subject: &str,
        body: &str,
    ) -> Result<Vec<NewsPost>, ClientError> {
        let (newsgroup_id, parent_id) = (wire(newsgroup_id)?, wire(parent_id)?);
        let (subject, body) = (wire(subject)?, wire(body)?);
        self.send(|reply| Command::CreatePost {
            newsgroup_id,
            parent_id,
            subject,
            body,
            reply,
        })
        .await
    }

    /// Delete a post you authored (admins may delete any). Resolves with the
    /// newsgroup's updated post list.
    pub async fn delete_post(&self, post_id: &str) -> Result<Vec<NewsPost>, ClientError> {
        let post_id = wire(post_id)?;
        self.send(|reply| Command::DeletePost { post_id, reply }).await
    }

    /// Ask the actor to close the connection. Takes effect promptly even if
    /// the actor is mid-transfer, its command queue is full, or the server
    /// has stopped reading; never blocks. `Event::Disconnected` follows.
    pub async fn disconnect(&self) {
        self.shutdown.send_replace(true);
    }
}
