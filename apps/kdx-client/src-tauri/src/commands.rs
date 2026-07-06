//! Tauri commands: thin async forwards from the webview into the client-core
//! `ClientHandle`. Core events are pushed to the webview by a forwarder task
//! spawned in [`connect`].

use std::path::PathBuf;

use kdx_client_core::{
    connect as core_connect, trust_server, AccountSummary, ClientConfig, ClientError, Event,
    FileSearchEntry, HistoryEntry, IpRule, NewsPost, NewsgroupInfo, PresenceUser, RoleInfo,
    ServerSettings, TrackerServer,
};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::state::AppState;

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

fn data_dir(app: &AppHandle) -> Result<PathBuf, CmdError> {
    app.path().app_data_dir().map_err(CmdError::msg)
}

#[tauri::command]
pub async fn connect(
    app: AppHandle,
    state: State<'_, AppState>,
    host: String,
    port: u16,
) -> CmdResult<String> {
    let cfg = ClientConfig::new(host.clone(), port, data_dir(&app)?);
    let (handle, mut events) = match core_connect(cfg).await {
        Ok(pair) => pair,
        Err(ClientError::UntrustedCertificate {
            host,
            fingerprint,
            previous,
        }) => {
            return Err(CmdError::UntrustedCertificate {
                host,
                port,
                fingerprint,
                previous,
            })
        }
        Err(e) => return Err(CmdError::msg(e)),
    };

    // Forward every core event to the webview as a "kdx" event.
    let forward = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(ev) = events.recv().await {
            let disconnected = matches!(ev, Event::Disconnected { .. });
            let _ = forward.emit("kdx", &ev);
            if disconnected {
                break;
            }
        }
    });

    *state.client.lock().await = Some(handle);
    Ok("connected".into())
}

#[tauri::command]
pub async fn trust(app: AppHandle, host: String, port: u16, fingerprint: String) -> CmdResult<()> {
    trust_server(&data_dir(&app)?, &host, port, &fingerprint).map_err(CmdError::msg)
}

async fn with_client<T, F, Fut>(state: &State<'_, AppState>, f: F) -> CmdResult<T>
where
    F: FnOnce(kdx_client_core::ClientHandle) -> Fut,
    Fut: std::future::Future<Output = Result<T, ClientError>>,
{
    let handle = {
        let guard = state.client.lock().await;
        guard.clone().ok_or_else(|| CmdError::msg("not connected"))?
    };
    f(handle).await.map_err(CmdError::msg)
}

#[tauri::command]
pub async fn login(state: State<'_, AppState>, username: String, password: String) -> CmdResult<u8> {
    with_client(&state, |c| async move {
        c.login(&username, &password).await.map(|s| s.class)
    })
    .await
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
) -> CmdResult<FileListDto> {
    with_client(&state, |c| async move {
        c.create_folder(&path, &name, kind, min_read_class, min_write_class)
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
pub async fn get_user_info(state: State<'_, AppState>, username: String) -> CmdResult<PresenceUser> {
    with_client(&state, |c| async move { c.get_user_info(&username).await }).await
}

#[tauri::command]
pub async fn send_private(state: State<'_, AppState>, to: String, text: String) -> CmdResult<()> {
    with_client(&state, |c| async move { c.send_private(&to, &text).await }).await
}

#[tauri::command]
pub async fn invite_to_chat(state: State<'_, AppState>, to: String) -> CmdResult<()> {
    with_client(&state, |c| async move { c.invite_to_chat(&to).await }).await
}

#[tauri::command]
pub async fn upload(state: State<'_, AppState>, local: String, remote_dir: String) -> CmdResult<()> {
    with_client(&state, |c| async move {
        c.upload(PathBuf::from(local), &remote_dir).await
    })
    .await
}

#[tauri::command]
pub async fn download(
    state: State<'_, AppState>,
    remote_path: String,
    local: String,
) -> CmdResult<()> {
    with_client(&state, |c| async move {
        c.download(&remote_path, PathBuf::from(local)).await
    })
    .await
}

#[tauri::command]
pub async fn disconnect(state: State<'_, AppState>) -> CmdResult<()> {
    if let Some(client) = state.client.lock().await.take() {
        client.disconnect().await;
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
