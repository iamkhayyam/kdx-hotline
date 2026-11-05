//! Tauri commands: thin async forwards from the webview into the client-core
//! `ClientHandle`. Core events are pushed to the webview by a forwarder task
//! (see `events.rs`) spawned in [`connect`].
//!
//! Local paths never come from the webview: `upload`/`download` open the
//! native dialog here, so script in a window can't name a file to exfiltrate
//! or overwrite. Likewise `trust` can only pin the certificate the last
//! `connect` refused.

use std::path::PathBuf;
use std::time::Duration;

use kdx_client_core::{
    connect as core_connect, trust_server, AccountSummary, BanList, ClientConfig, ClientError,
    ClientHandle, FileInfoResponse, FileSearchEntry, HistoryEntry, IpRule, NewsPost,
    NewsgroupInfo, PresenceUser, RoleInfo, ServerSettings, TrackerServer,
};
use serde::Serialize;
use tauri::{AppHandle, Manager, Runtime, State, Window};
use tauri_plugin_dialog::{DialogExt, FileDialogBuilder, FilePath};

use crate::events::{self, emit_disconnected};
use crate::sanitize::safe_local_file_name;
use crate::secrets::{self, SecretRecord};
use crate::state::{AppState, Conn, PendingTrust, SessionUser};

/// How long a replaced/abandoned connection gets to accept its Disconnect
/// command. A wedged actor (full command queue, blocked write) must never
/// wedge the app.
const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Characters of the new fingerprint the user must type to replace a pinned
/// key.
pub const KEY_CHANGE_CONFIRM_CHARS: usize = 8;

/// Error shape sent to the webview. The `kind` discriminant lets the UI
/// special-case an untrusted certificate (to show the TOFU prompt).
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CmdError {
    UntrustedCertificate {
        host: String,
        port: u16,
        fingerprint: String,
        previous: Option<String>,
    },
    Message {
        message: String,
    },
}

impl CmdError {
    fn msg(e: impl std::fmt::Display) -> Self {
        CmdError::Message {
            message: e.to_string(),
        }
    }
}

type CmdResult<T> = Result<T, CmdError>;

/// Serializable file entry for the Files window.
#[derive(Serialize)]
pub struct FileEntryDto {
    pub name: String,
    pub kind: u8,
    pub size: u64,
}

#[derive(Serialize)]
pub struct FileListDto {
    pub path: String,
    pub entries: Vec<FileEntryDto>,
}

/// The client's state directory: `known_hosts.toml` and (under
/// `transfers/`) partial downloads. Tauri's app_data_dir, which under the
/// macOS App Sandbox resolves inside the app's container — the only place
/// besides a dialog-chosen file that the app writes to.
fn data_dir<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, CmdError> {
    app.path().app_data_dir().map_err(CmdError::msg)
}

/// Retire a connection that is no longer current: stop forwarding its
/// events (so nothing of it reaches the webview any more), tell the webview
/// it ended, then ask the actor to hang up, waiting at most
/// [`DISCONNECT_TIMEOUT`].
async fn retire<R: Runtime>(app: &AppHandle<R>, state: &AppState, conn: Conn, reason: &str) {
    conn.forwarder.abort();
    emit_disconnected(app, conn.generation, &state.seq, reason);
    if tokio::time::timeout(DISCONNECT_TIMEOUT, conn.handle.disconnect())
        .await
        .is_err()
    {
        tracing::warn!("connection did not accept Disconnect within {DISCONNECT_TIMEOUT:?}");
    }
}

/// Connect to a server, replacing (and hanging up) any current connection.
/// Returns the new connection generation, which tags every event it emits.
#[tauri::command]
pub async fn connect<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    host: String,
    port: u16,
) -> CmdResult<u64> {
    lock_pending(&state).take();

    // Hang up the old session first so none of its events — least of all
    // its eventual Disconnected — can bleed into the new one. `take()` is its
    // own statement: the lock is never held across an await.
    let old = state.conn.lock().await.take();
    if let Some(old) = old {
        retire(&app, &state, old, "switched servers").await;
    }

    let cfg = ClientConfig::new(host.clone(), port, data_dir(&app)?);
    let (handle, events) = match core_connect(cfg).await {
        Ok(pair) => pair,
        Err(ClientError::UntrustedCertificate {
            host: _,
            fingerprint,
            previous,
        }) => {
            // Remember exactly what was presented: `trust` may pin only this.
            *lock_pending(&state) = Some(PendingTrust {
                host: host.clone(),
                port,
                fingerprint: fingerprint.clone(),
                previous: previous.clone(),
            });
            return Err(CmdError::UntrustedCertificate {
                host,
                port,
                fingerprint,
                previous,
            });
        }
        Err(e) => return Err(CmdError::msg(e)),
    };

    let gen = state.next_generation();
    // Spawn the forwarder while holding the lock, so its end-of-connection
    // cleanup can't run before the connection is recorded.
    let replaced = {
        let mut slot = state.conn.lock().await;
        let forwarder = tauri::async_runtime::spawn(events::forward(app.clone(), gen, events));
        slot.replace(Conn {
            handle,
            generation: gen,
            forwarder,
            host,
            port,
            user: None,
        })
    };
    if let Some(r) = replaced {
        // A concurrent connect raced us; the latest one wins.
        retire(&app, &state, r, "switched servers").await;
    }
    Ok(gen)
}

fn lock_pending<'a>(
    state: &'a State<'_, AppState>,
) -> std::sync::MutexGuard<'a, Option<PendingTrust>> {
    state
        .pending_trust
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Decide whether `trust(host, port, confirm)` may pin, returning the
/// fingerprint to pin. Only the certificate the last connect refused for
/// this exact host:port qualifies, and replacing an already-pinned key
/// additionally needs the first [`KEY_CHANGE_CONFIRM_CHARS`] characters of
/// the new fingerprint typed back.
pub fn check_trust(
    pending: Option<&PendingTrust>,
    host: &str,
    port: u16,
    confirm: Option<&str>,
) -> Result<String, &'static str> {
    let Some(p) = pending.filter(|p| p.host == host && p.port == port) else {
        return Err("no untrusted certificate is pending for this server — connect again");
    };
    if p.previous.is_some() {
        let expected = key_change_code(&p.fingerprint);
        if confirm.map(str::trim) != Some(expected.as_str()) {
            return Err("type the first characters of the NEW fingerprint to replace the pinned key");
        }
    }
    Ok(p.fingerprint.clone())
}

/// The characters a user must type to accept a changed key: the start of the
/// fingerprint's digest (after any `sha256:` prefix).
pub fn key_change_code(fingerprint: &str) -> String {
    let digest = fingerprint.split_once(':').map_or(fingerprint, |(_, d)| d);
    digest.chars().take(KEY_CHANGE_CONFIRM_CHARS).collect()
}

/// Pin the certificate the last `connect` to `host:port` refused. One-shot.
#[tauri::command]
pub async fn trust<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    host: String,
    port: u16,
    confirm: Option<String>,
) -> CmdResult<()> {
    let fingerprint = {
        let pending = lock_pending(&state);
        check_trust(pending.as_ref(), &host, port, confirm.as_deref()).map_err(CmdError::msg)?
    };
    trust_server(&data_dir(&app)?, &host, port, &fingerprint).map_err(CmdError::msg)?;
    let mut pending = lock_pending(&state);
    if pending.as_ref().is_some_and(|p| p.fingerprint == fingerprint) {
        pending.take();
    }
    Ok(())
}

fn current_handle(conn: &Option<Conn>) -> CmdResult<ClientHandle> {
    conn.as_ref()
        .map(|c| c.handle.clone())
        .ok_or_else(|| CmdError::msg("not connected"))
}

async fn with_client<T, F, Fut>(state: &State<'_, AppState>, f: F) -> CmdResult<T>
where
    F: FnOnce(ClientHandle) -> Fut,
    Fut: std::future::Future<Output = Result<T, ClientError>>,
{
    let handle = current_handle(&*state.conn.lock().await)?;
    f(handle).await.map_err(CmdError::msg)
}

/// What a window opened after login needs to know about the session.
#[derive(Serialize)]
pub struct SessionDto {
    pub gen: u64,
    pub host: String,
    pub port: u16,
    pub user: Option<SessionUser>,
}

/// The current connection (if any), for hydrating a freshly opened window.
#[tauri::command]
pub async fn get_session(state: State<'_, AppState>) -> CmdResult<Option<SessionDto>> {
    Ok(state.conn.lock().await.as_ref().map(|c| SessionDto {
        gen: c.generation,
        host: c.host.clone(),
        port: c.port,
        user: c.user.clone(),
    }))
}

/// Log in; resolves to who is now logged in (username, class and effective
/// privileges — what `get_session` reports from then on). With an empty
/// `password` and a `bookmark_id`, the bookmark's password is read from the
/// OS credential store here — it never travels through the webview — and
/// only if it was saved for this server and login.
#[tauri::command]
pub async fn login(
    state: State<'_, AppState>,
    username: String,
    password: String,
    bookmark_id: Option<String>,
) -> CmdResult<SessionUser> {
    let (handle, gen, host, port) = {
        let conn = state.conn.lock().await;
        let c = conn.as_ref().ok_or_else(|| CmdError::msg("not connected"))?;
        (c.handle.clone(), c.generation, c.host.clone(), c.port)
    };
    let password = match bookmark_id {
        Some(id) if password.is_empty() => {
            let record = tauri::async_runtime::spawn_blocking(move || secrets::load(&id))
                .await
                .map_err(CmdError::msg)?
                .map_err(|e| CmdError::msg(format!("couldn't read the saved password: {e}")))?
                .ok_or_else(|| CmdError::msg("no saved password for this bookmark — type it"))?;
            record
                .password_for(&host, port, &username)
                .map_err(CmdError::msg)?
        }
        _ => password,
    };
    let session = handle.login(&username, &password).await.map_err(CmdError::msg)?;
    let user = SessionUser::new(username, &session);
    if let Some(c) = state.conn.lock().await.as_mut() {
        if c.generation == gen {
            c.user = Some(user.clone());
        }
    }
    Ok(user)
}

/// Save a bookmark's password in the OS credential store. Returns `false`
/// (not saved) when no credential store is available.
#[tauri::command]
pub async fn save_secret(
    bookmark_id: String,
    host: String,
    port: u16,
    login: String,
    password: String,
) -> CmdResult<bool> {
    if !secrets::valid_bookmark_id(&bookmark_id) {
        return Err(CmdError::msg("invalid bookmark id"));
    }
    let record = SecretRecord {
        host,
        port,
        login,
        password,
    };
    let result = tauri::async_runtime::spawn_blocking(move || secrets::save(&bookmark_id, &record))
        .await
        .map_err(CmdError::msg)?;
    if let Err(e) = &result {
        tracing::warn!("credential store unavailable, password not saved: {e}");
    }
    Ok(result.is_ok())
}

/// Forget a bookmark's saved password.
#[tauri::command]
pub async fn delete_secret(bookmark_id: String) -> CmdResult<()> {
    tauri::async_runtime::spawn_blocking(move || secrets::delete(&bookmark_id))
        .await
        .map_err(CmdError::msg)?
        .map_err(CmdError::msg)
}

#[tauri::command]
pub async fn join_room(state: State<'_, AppState>, room: String) -> CmdResult<()> {
    with_client(&state, |c| async move { c.join(&room).await }).await
}

#[tauri::command]
pub async fn leave_room(state: State<'_, AppState>, room: String) -> CmdResult<()> {
    with_client(&state, |c| async move { c.leave(&room).await }).await
}

#[tauri::command]
pub async fn send_chat(
    state: State<'_, AppState>,
    room: String,
    flags: u8,
    text: String,
) -> CmdResult<()> {
    with_client(&state, |c| async move { c.send_chat(&room, flags, &text).await }).await
}

#[tauri::command]
pub async fn set_topic(state: State<'_, AppState>, room: String, topic: String) -> CmdResult<()> {
    with_client(&state, |c| async move { c.set_topic(&room, &topic).await }).await
}

#[tauri::command]
pub async fn list_files(state: State<'_, AppState>, path: String) -> CmdResult<FileListDto> {
    with_client(&state, |c| async move { c.list_files(&path).await })
        .await
        .map(file_list_dto)
}

#[tauri::command]
pub async fn create_folder(
    state: State<'_, AppState>,
    path: String,
    name: String,
    kind: u8,
    min_read_class: u8,
    min_write_class: u8,
    owner: Option<String>,
) -> CmdResult<FileListDto> {
    with_client(&state, |c| async move {
        c.create_folder(&path, &name, kind, min_read_class, min_write_class, owner.as_deref())
            .await
    })
    .await
    .map(file_list_dto)
}

#[tauri::command]
pub async fn delete_path(state: State<'_, AppState>, path: String) -> CmdResult<FileListDto> {
    with_client(&state, |c| async move { c.delete_path(&path).await })
        .await
        .map(file_list_dto)
}

#[tauri::command]
pub async fn move_path(
    state: State<'_, AppState>,
    path: String,
    dest_path: String,
) -> CmdResult<FileListDto> {
    with_client(&state, |c| async move { c.move_path(&path, &dest_path).await })
        .await
        .map(file_list_dto)
}

#[tauri::command]
pub async fn alias_path(
    state: State<'_, AppState>,
    source_path: String,
    dest_path: String,
) -> CmdResult<FileListDto> {
    with_client(&state, |c| async move { c.alias_path(&source_path, &dest_path).await })
        .await
        .map(file_list_dto)
}

#[tauri::command]
pub async fn generate_catalog(state: State<'_, AppState>) -> CmdResult<u32> {
    with_client(&state, |c| async move { c.generate_catalog().await }).await
}

#[tauri::command]
pub async fn search_files(
    state: State<'_, AppState>,
    query: String,
) -> CmdResult<Vec<FileSearchEntry>> {
    with_client(&state, |c| async move { c.search_files(&query).await }).await
}

fn file_list_dto(r: kdx_client_core::FileListResponse) -> FileListDto {
    FileListDto {
        path: r.path,
        entries: r
            .entries
            .into_iter()
            .map(|e| FileEntryDto {
                name: e.name,
                kind: e.kind,
                size: e.size,
            })
            .collect(),
    }
}

#[tauri::command]
pub async fn list_users(state: State<'_, AppState>) -> CmdResult<Vec<PresenceUser>> {
    with_client(&state, |c| async move { c.list_users().await }).await
}

#[tauri::command]
pub async fn list_servers(
    state: State<'_, AppState>,
    filter: String,
) -> CmdResult<Vec<TrackerServer>> {
    with_client(&state, |c| async move { c.list_servers(&filter).await }).await
}

#[tauri::command]
pub async fn get_server_settings(state: State<'_, AppState>) -> CmdResult<ServerSettings> {
    with_client(&state, |c| async move { c.get_server_settings().await }).await
}

#[tauri::command]
pub async fn update_server_settings(
    state: State<'_, AppState>,
    name: String,
    description: String,
    greeting: String,
    max_users: u32,
) -> CmdResult<ServerSettings> {
    with_client(&state, |c| async move {
        c.update_server_settings(&name, &description, &greeting, max_users).await
    })
    .await
}

#[tauri::command]
pub async fn broadcast(state: State<'_, AppState>, text: String) -> CmdResult<()> {
    with_client(&state, |c| async move { c.broadcast(&text).await }).await
}

#[tauri::command]
pub async fn shutdown_server(state: State<'_, AppState>, message: String) -> CmdResult<()> {
    with_client(&state, |c| async move { c.shutdown_server(&message).await }).await
}

#[tauri::command]
pub async fn list_history(state: State<'_, AppState>, limit: u32) -> CmdResult<Vec<HistoryEntry>> {
    with_client(&state, |c| async move { c.list_history(limit).await }).await
}

#[tauri::command]
pub async fn list_ip_rules(state: State<'_, AppState>) -> CmdResult<Vec<IpRule>> {
    with_client(&state, |c| async move { c.list_ip_rules().await }).await
}

#[tauri::command]
pub async fn create_ip_rule(
    state: State<'_, AppState>,
    position: i32,
    action: String,
    cidr: String,
    note: String,
) -> CmdResult<Vec<IpRule>> {
    with_client(&state, |c| async move {
        c.create_ip_rule(position, &action, &cidr, &note).await
    })
    .await
}

#[tauri::command]
pub async fn delete_ip_rule(state: State<'_, AppState>, id: String) -> CmdResult<Vec<IpRule>> {
    with_client(&state, |c| async move { c.delete_ip_rule(&id).await }).await
}

#[tauri::command]
pub async fn list_connections(state: State<'_, AppState>) -> CmdResult<Vec<PresenceUser>> {
    with_client(&state, |c| async move { c.list_connections().await }).await
}

#[tauri::command]
pub async fn set_room_flags(
    state: State<'_, AppState>,
    room: String,
    min_class_join: u8,
    interview_mode: bool,
) -> CmdResult<()> {
    with_client(&state, |c| async move {
        c.set_room_flags(&room, min_class_join, interview_mode).await
    })
    .await
}

#[tauri::command]
pub async fn get_user_info(state: State<'_, AppState>, username: String) -> CmdResult<PresenceUser> {
    with_client(&state, |c| async move { c.get_user_info(&username).await }).await
}

#[tauri::command]
pub async fn send_private(state: State<'_, AppState>, to: String, text: String) -> CmdResult<()> {
    with_client(&state, |c| async move { c.send_private(&to, &text).await }).await
}

#[tauri::command]
pub async fn invite_to_chat(
    state: State<'_, AppState>,
    to: String,
) -> CmdResult<Option<String>> {
    with_client(&state, |c| async move {
        c.invite_to_chat(&to).await.map(InviteResult::room_id)
    })
    .await
}

/// What client-core's `invite_to_chat` resolves to: `()` today, or the new
/// private room's id once client-core reports it. Either way the webview
/// gets `null` or the id (and otherwise adopts the room from its first
/// user_list).
trait InviteResult {
    fn room_id(self) -> Option<String>;
}

impl InviteResult for () {
    fn room_id(self) -> Option<String> {
        None
    }
}

impl InviteResult for String {
    fn room_id(self) -> Option<String> {
        Some(self)
    }
}

/// Ask the user for a local path with a native dialog (never from the
/// webview). `None` if they cancelled.
async fn ask_path<R: Runtime>(dialog: FileDialogBuilder<R>, save: bool) -> Option<PathBuf> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let done = move |path: Option<FilePath>| {
        let _ = tx.send(path);
    };
    if save {
        dialog.save_file(done);
    } else {
        dialog.pick_file(done);
    }
    rx.await.ok().flatten().and_then(|p| p.into_path().ok())
}

/// Pick a local file with the native Open dialog and upload it into
/// `remote_dir`. Resolves `false` if the user cancelled, `true` once the
/// transfer verified.
#[tauri::command]
pub async fn upload<R: Runtime>(
    app: AppHandle<R>,
    window: Window<R>,
    state: State<'_, AppState>,
    remote_dir: String,
) -> CmdResult<bool> {
    let handle = current_handle(&*state.conn.lock().await)?;
    let dialog = app
        .dialog()
        .file()
        .set_title("Upload a file")
        .set_parent(&window);
    let Some(local) = ask_path(dialog, false).await else {
        return Ok(false);
    };
    let is_file = std::fs::metadata(&local).map(|m| m.is_file()).unwrap_or(false);
    if !local.is_absolute() || !is_file {
        return Err(CmdError::msg("pick a regular file to upload"));
    }
    handle.upload(local, &remote_dir).await.map_err(transfer_error)?;
    Ok(true)
}

/// A transfer's failure for the webview. A connection that ended mid-way
/// (whichever side hung up) reads as such, not as "closed by server".
fn transfer_error(e: ClientError) -> CmdError {
    match e {
        ClientError::Disconnected => {
            CmdError::msg("the connection ended before the transfer finished")
        }
        e => CmdError::msg(e),
    }
}

/// Download `remote_path` to a location the user picks in the native Save
/// dialog. The dialog opens in the Downloads folder with the server's name
/// reduced to a safe basename (no directories, UNC paths, bidi tricks or
/// reserved device names). Resolves `false` if the user cancelled.
///
/// Sandbox-safe: the dialog grants write access to the chosen file only, and
/// client-core writes nothing else there — partial bytes and resume state
/// stay in [`data_dir`] until the verified file is moved into place.
/// Choosing the same file again resumes an interrupted download.
#[tauri::command]
pub async fn download<R: Runtime>(
    app: AppHandle<R>,
    window: Window<R>,
    state: State<'_, AppState>,
    remote_path: String,
) -> CmdResult<bool> {
    let handle = current_handle(&*state.conn.lock().await)?;
    let suggested = safe_local_file_name(remote_path.rsplit('/').next().unwrap_or(""));
    let mut dialog = app
        .dialog()
        .file()
        .set_title("Save download as")
        .set_file_name(suggested)
        .set_parent(&window);
    if let Ok(dir) = app.path().download_dir() {
        dialog = dialog.set_directory(dir);
    }
    let Some(local) = ask_path(dialog, true).await else {
        return Ok(false);
    };
    if !local.is_absolute() {
        return Err(CmdError::msg("pick an absolute save location"));
    }
    handle
        .download(&remote_path, local)
        .await
        .map_err(transfer_error)?;
    Ok(true)
}

/// Abort the connection's active upload or download (one runs at a time).
/// Its `upload`/`download` call then fails with "cancelled"; a cancelled
/// download keeps its resume state. Resolves whether one was running.
#[tauri::command]
pub async fn cancel_transfer(state: State<'_, AppState>) -> CmdResult<bool> {
    with_client(&state, |c| async move { c.cancel_transfer().await }).await
}

/// Hang up the current connection. Never holds the state lock across an
/// await, and never waits on a wedged actor for more than
/// [`DISCONNECT_TIMEOUT`]; the UI is told immediately.
#[tauri::command]
pub async fn disconnect<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
) -> CmdResult<()> {
    let conn = state.conn.lock().await.take();
    if let Some(conn) = conn {
        retire(&app, &state, conn, "disconnected").await;
    }
    Ok(())
}

#[tauri::command]
pub async fn list_roles(state: State<'_, AppState>) -> CmdResult<Vec<RoleInfo>> {
    with_client(&state, |c| async move { c.list_roles().await }).await
}

#[tauri::command]
pub async fn create_role(
    state: State<'_, AppState>,
    name: String,
    privileges: u32,
    rank: i32,
    color: String,
) -> CmdResult<Vec<RoleInfo>> {
    with_client(&state, |c| async move {
        c.create_role(&name, privileges, rank, &color).await
    })
    .await
}

#[tauri::command]
pub async fn update_role(
    state: State<'_, AppState>,
    id: String,
    name: String,
    privileges: u32,
    rank: i32,
    color: String,
) -> CmdResult<Vec<RoleInfo>> {
    with_client(&state, |c| async move {
        c.update_role(&id, &name, privileges, rank, &color).await
    })
    .await
}

#[tauri::command]
pub async fn delete_role(state: State<'_, AppState>, id: String) -> CmdResult<Vec<RoleInfo>> {
    with_client(&state, |c| async move { c.delete_role(&id).await }).await
}

#[tauri::command]
pub async fn assign_role(
    state: State<'_, AppState>,
    username: String,
    role_id: String,
) -> CmdResult<Vec<RoleInfo>> {
    with_client(&state, |c| async move { c.assign_role(&username, &role_id).await }).await
}

#[tauri::command]
pub async fn unassign_role(
    state: State<'_, AppState>,
    username: String,
    role_id: String,
) -> CmdResult<Vec<RoleInfo>> {
    with_client(&state, |c| async move { c.unassign_role(&username, &role_id).await }).await
}

#[tauri::command]
pub async fn account_roles(state: State<'_, AppState>, username: String) -> CmdResult<Vec<String>> {
    with_client(&state, |c| async move { c.account_roles(&username).await }).await
}

#[tauri::command]
pub async fn disconnect_user(
    state: State<'_, AppState>,
    username: String,
    reason: String,
    ban_secs: u32,
) -> CmdResult<()> {
    with_client(&state, |c| async move {
        c.disconnect_user(&username, &reason, ban_secs).await
    })
    .await
}

#[tauri::command]
pub async fn list_accounts(state: State<'_, AppState>) -> CmdResult<Vec<AccountSummary>> {
    with_client(&state, |c| async move { c.list_accounts().await }).await
}

/// Create an account. Its credential is derived from `password` in
/// client-core; the password itself never goes to the server.
#[tauri::command]
pub async fn create_account(
    state: State<'_, AppState>,
    username: String,
    password: String,
    base_class: u8,
    granted: u32,
    revoked: u32,
) -> CmdResult<Vec<AccountSummary>> {
    with_client(&state, |c| async move {
        c.create_account(&username, &password, base_class, granted, revoked)
            .await
    })
    .await
}

#[tauri::command]
pub async fn update_account(
    state: State<'_, AppState>,
    username: String,
    base_class: u8,
    granted: u32,
    revoked: u32,
) -> CmdResult<Vec<AccountSummary>> {
    with_client(&state, |c| async move {
        c.update_account(&username, base_class, granted, revoked).await
    })
    .await
}

/// Reset another account's password (Accounts window). The credential is
/// derived from `new_password` in client-core; the server never sees it.
#[tauri::command]
pub async fn set_account_password(
    state: State<'_, AppState>,
    username: String,
    new_password: String,
) -> CmdResult<Vec<AccountSummary>> {
    with_client(&state, |c| async move {
        c.set_account_password(&username, &new_password).await
    })
    .await
}

/// Change the logged-in account's own password (Connect window). Proves the
/// current password and sends a credential derived from the new one;
/// neither password leaves this process. Returns the server's message.
#[tauri::command]
pub async fn change_password(
    state: State<'_, AppState>,
    current_password: String,
    new_password: String,
) -> CmdResult<String> {
    with_client(&state, |c| async move {
        c.change_password(&current_password, &new_password).await
    })
    .await
}

#[tauri::command]
pub async fn list_newsgroups(state: State<'_, AppState>) -> CmdResult<Vec<NewsgroupInfo>> {
    with_client(&state, |c| async move { c.list_newsgroups().await }).await
}

#[tauri::command]
pub async fn create_newsgroup(
    state: State<'_, AppState>,
    name: String,
    description: String,
    min_read_class: u8,
    min_post_class: u8,
) -> CmdResult<Vec<NewsgroupInfo>> {
    with_client(&state, |c| async move {
        c.create_newsgroup(&name, &description, min_read_class, min_post_class)
            .await
    })
    .await
}

#[tauri::command]
pub async fn list_thread(
    state: State<'_, AppState>,
    newsgroup_id: String,
) -> CmdResult<Vec<NewsPost>> {
    with_client(&state, |c| async move { c.list_thread(&newsgroup_id).await }).await
}

#[tauri::command]
pub async fn create_post(
    state: State<'_, AppState>,
    newsgroup_id: String,
    parent_id: String,
    subject: String,
    body: String,
) -> CmdResult<Vec<NewsPost>> {
    with_client(&state, |c| async move {
        c.create_post(&newsgroup_id, &parent_id, &subject, &body).await
    })
    .await
}

#[tauri::command]
pub async fn delete_post(state: State<'_, AppState>, post_id: String) -> CmdResult<Vec<NewsPost>> {
    with_client(&state, |c| async move { c.delete_post(&post_id).await }).await
}

#[tauri::command]
pub async fn update_newsgroup(
    state: State<'_, AppState>,
    id: String,
    name: String,
    description: String,
    min_read_class: u8,
    min_post_class: u8,
) -> CmdResult<Vec<NewsgroupInfo>> {
    with_client(&state, |c| async move {
        c.update_newsgroup(&id, &name, &description, min_read_class, min_post_class)
            .await
    })
    .await
}

#[tauri::command]
pub async fn delete_newsgroup(state: State<'_, AppState>, id: String) -> CmdResult<Vec<NewsgroupInfo>> {
    with_client(&state, |c| async move { c.delete_newsgroup(&id).await }).await
}

#[tauri::command]
pub async fn list_bans(state: State<'_, AppState>) -> CmdResult<BanList> {
    with_client(&state, |c| async move { c.list_bans().await }).await
}

#[tauri::command]
pub async fn remove_ban(state: State<'_, AppState>, username: String) -> CmdResult<BanList> {
    with_client(&state, |c| async move { c.remove_ban(&username).await }).await
}

#[derive(Serialize)]
pub struct FileInfoDto {
    pub name: String,
    pub kind: u8,
    pub size: u64,
    pub sha256: Option<String>,
    pub min_read_class: u8,
    pub min_write_class: u8,
    pub owner: Option<String>,
}

impl From<FileInfoResponse> for FileInfoDto {
    fn from(r: FileInfoResponse) -> Self {
        Self {
            name: r.name,
            kind: r.kind,
            size: r.size,
            sha256: r.sha256.map(hex),
            min_read_class: r.min_read_class,
            min_write_class: r.min_write_class,
            owner: r.owner,
        }
    }
}

fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tauri::command]
pub async fn get_file_info(state: State<'_, AppState>, path: String) -> CmdResult<FileInfoDto> {
    with_client(&state, |c| async move { c.get_file_info(&path).await })
        .await
        .map(FileInfoDto::from)
}

#[tauri::command]
pub async fn set_identity(
    state: State<'_, AppState>,
    name: String,
    description: String,
) -> CmdResult<()> {
    with_client(&state, |c| async move { c.set_identity(&name, &description).await }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(e: CmdError) -> String {
        match e {
            CmdError::Message { message } => message,
            other => panic!("unexpected {other:?}"),
        }
    }

    /// C-5: a transfer cut off by the user's own Disconnect no longer reads
    /// "connection closed by server".
    #[test]
    fn a_transfer_cut_off_by_a_disconnect_says_so() {
        let text = message(transfer_error(ClientError::Disconnected));
        assert!(!text.contains("server"), "{text}");
        assert!(text.contains("connection ended"), "{text}");
        let text = message(transfer_error(ClientError::Transfer("cancelled".into())));
        assert_eq!(text, "transfer failed: cancelled");
    }

    /// `login` resolves to, and `get_session` reports, the session's
    /// effective privileges next to its class — the shape the webview's
    /// session.js / connect.js read.
    #[test]
    fn the_session_carries_privileges_to_the_webview() {
        let session = kdx_client_core::Session {
            session_id: [7; 16],
            class: 1,
            privileges: 0x0001_000B,
        };
        let user = SessionUser::new("deputy".into(), &session);
        assert_eq!(
            serde_json::to_value(&user).unwrap(),
            serde_json::json!({ "username": "deputy", "class": 1, "privileges": 0x0001_000B })
        );
        let dto = SessionDto {
            gen: 3,
            host: "kdx.example".into(),
            port: 10700,
            user: Some(user),
        };
        let json = serde_json::to_value(&dto).unwrap();
        assert_eq!(json["user"]["privileges"], 0x0001_000B);
        assert_eq!(json["user"]["class"], 1);
        // Every bit a u32 can carry survives (JSON numbers, not i32).
        let every_bit = kdx_client_core::Session {
            privileges: u32::MAX,
            ..session
        };
        let all = SessionUser::new("sysop".into(), &every_bit);
        assert_eq!(serde_json::to_value(&all).unwrap()["privileges"], u32::MAX);
    }

    fn pending(previous: Option<&str>) -> PendingTrust {
        PendingTrust {
            host: "kdx.example".into(),
            port: 10700,
            fingerprint: "sha256:AbCdEfGh1234567890+/xyz=".into(),
            previous: previous.map(str::to_string),
        }
    }

    #[test]
    fn trust_pins_only_the_pending_certificate() {
        let p = pending(None);
        assert_eq!(
            check_trust(Some(&p), "kdx.example", 10700, None).unwrap(),
            p.fingerprint
        );
        // Nothing pending, or pending for another host:port: refuse (a script
        // can't plant a pin for a server the user never tried).
        assert!(check_trust(None, "kdx.example", 10700, None).is_err());
        assert!(check_trust(Some(&p), "other.example", 10700, None).is_err());
        assert!(check_trust(Some(&p), "kdx.example", 10701, None).is_err());
    }

    #[test]
    fn changed_key_needs_typed_confirmation() {
        let p = pending(Some("sha256:OLD"));
        assert_eq!(key_change_code(&p.fingerprint), "AbCdEfGh");
        assert!(check_trust(Some(&p), "kdx.example", 10700, None).is_err());
        assert!(check_trust(Some(&p), "kdx.example", 10700, Some("abcdefgh")).is_err());
        assert!(check_trust(Some(&p), "kdx.example", 10700, Some("AbCdEfG")).is_err());
        assert_eq!(
            check_trust(Some(&p), "kdx.example", 10700, Some(" AbCdEfGh ")).unwrap(),
            p.fingerprint
        );
    }
}
