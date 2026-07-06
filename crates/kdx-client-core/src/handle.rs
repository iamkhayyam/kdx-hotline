use std::path::PathBuf;

use tokio::sync::{mpsc, oneshot};

use kdx_protocol::messages::FileListResponse;

use crate::error::ClientError;
use crate::event::{AccountSummary, PresenceUser, RoleInfo};

/// A logged-in session's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    pub session_id: [u8; 16],
    pub class: u8,
}

/// Commands sent from a `ClientHandle` into the connection actor. Each
/// carries a `oneshot` for its result where the operation has one.
#[derive(Debug)]
pub(crate) enum Command {
    Login {
        username: String,
        password: String,
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
    ListUsers {
        reply: oneshot::Sender<Result<Vec<PresenceUser>, ClientError>>,
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
    Upload {
        local: PathBuf,
        remote_dir: String,
        reply: oneshot::Sender<Result<(), ClientError>>,
    },
    Download {
        remote_path: String,
        local: PathBuf,
        reply: oneshot::Sender<Result<(), ClientError>>,
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
        password: String,
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
    Disconnect,
}

/// Handle to a connected KDX client. Cloneable; every method round-trips a
/// command into the single connection actor.
#[derive(Clone, Debug)]
pub struct ClientHandle {
    pub(crate) tx: mpsc::Sender<Command>,
}

impl ClientHandle {
    async fn send<T>(
        &self,
        make: impl FnOnce(oneshot::Sender<Result<T, ClientError>>) -> Command,
    ) -> Result<T, ClientError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(make(reply))
            .await
            .map_err(|_| ClientError::Disconnected)?;
        rx.await.map_err(|_| ClientError::Disconnected)?
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<Session, ClientError> {
        self.send(|reply| Command::Login {
            username: username.to_owned(),
            password: password.to_owned(),
            reply,
        })
        .await
    }

    pub async fn join(&self, room: &str) -> Result<(), ClientError> {
        self.send(|reply| Command::Join {
            room: room.to_owned(),
            reply,
        })
        .await
    }

    pub async fn leave(&self, room: &str) -> Result<(), ClientError> {
        self.send(|reply| Command::Leave {
            room: room.to_owned(),
            reply,
        })
        .await
    }

    /// Send a chat message. `flags` may include `kdx_protocol::messages::CHAT_ACTION`.
    pub async fn send_chat(&self, room: &str, flags: u8, text: &str) -> Result<(), ClientError> {
        self.send(|reply| Command::SendChat {
            room: room.to_owned(),
            flags,
            text: text.to_owned(),
            reply,
        })
        .await
    }

    pub async fn set_topic(&self, room: &str, topic: &str) -> Result<(), ClientError> {
        self.send(|reply| Command::SetTopic {
            room: room.to_owned(),
            topic: topic.to_owned(),
            reply,
        })
        .await
    }

    pub async fn list_files(&self, path: &str) -> Result<FileListResponse, ClientError> {
        self.send(|reply| Command::ListFiles {
            path: path.to_owned(),
            reply,
        })
        .await
    }

    /// Fetch the server-wide roster of currently online users (the global
    /// User List, distinct from a chat room's member list).
    pub async fn list_users(&self) -> Result<Vec<PresenceUser>, ClientError> {
        self.send(|reply| Command::ListUsers { reply }).await
    }

    /// Fetch one user's detail (login/idle time, address) for the User Info
    /// window. Errors if the user isn't currently online.
    pub async fn get_user_info(&self, username: &str) -> Result<PresenceUser, ClientError> {
        self.send(|reply| Command::GetUserInfo {
            username: username.to_owned(),
            reply,
        })
        .await
    }

    /// Send a private (direct) message to `to`. Resolves once the send frame
    /// is written; delivery and the sender-echo arrive as
    /// `Event::PrivateMessage`. Errors surface via `Event::ServerError` (e.g.
    /// the recipient is offline).
    pub async fn send_private(&self, to: &str, text: &str) -> Result<(), ClientError> {
        self.send(|reply| Command::SendPrivate {
            to: to.to_owned(),
            text: text.to_owned(),
            reply,
        })
        .await
    }

    /// Upload a local file into `remote_dir`; the remote name is the local
    /// file's basename. Resolves when the transfer verifies (or fails);
    /// `Event::TransferProgress` is emitted throughout.
    pub async fn upload(&self, local: PathBuf, remote_dir: &str) -> Result<(), ClientError> {
        self.send(|reply| Command::Upload {
            local,
            remote_dir: remote_dir.to_owned(),
            reply,
        })
        .await
    }

    /// Download `remote_path` (a `/dir/file` path) to `local`, resuming from a
    /// `.kdxpart` sidecar if one is present. Resolves on completion.
    pub async fn download(&self, remote_path: &str, local: PathBuf) -> Result<(), ClientError> {
        self.send(|reply| Command::Download {
            remote_path: remote_path.to_owned(),
            local,
            reply,
        })
        .await
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
        self.send(|reply| Command::CreateRole {
            name: name.to_owned(),
            privileges,
            rank,
            color: color.to_owned(),
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
        self.send(|reply| Command::UpdateRole {
            id: id.to_owned(),
            name: name.to_owned(),
            privileges,
            rank,
            color: color.to_owned(),
            reply,
        })
        .await
    }

    /// Delete a role outright. Requires `USER_ADMIN`.
    pub async fn delete_role(&self, id: &str) -> Result<Vec<RoleInfo>, ClientError> {
        self.send(|reply| Command::DeleteRole {
            id: id.to_owned(),
            reply,
        })
        .await
    }

    /// Attach a role to an account by username. Requires `USER_ADMIN`.
    /// Idempotent server-side.
    pub async fn assign_role(&self, username: &str, role_id: &str) -> Result<Vec<RoleInfo>, ClientError> {
        self.send(|reply| Command::AssignRole {
            username: username.to_owned(),
            role_id: role_id.to_owned(),
            reply,
        })
        .await
    }

    /// Detach a role from an account by username. Requires `USER_ADMIN`.
    pub async fn unassign_role(&self, username: &str, role_id: &str) -> Result<Vec<RoleInfo>, ClientError> {
        self.send(|reply| Command::UnassignRole {
            username: username.to_owned(),
            role_id: role_id.to_owned(),
            reply,
        })
        .await
    }

    /// Which roles does `username` currently hold? Requires `USER_ADMIN`.
    /// Returns role ids (UUID strings, matching `RoleInfo::id`).
    pub async fn account_roles(&self, username: &str) -> Result<Vec<String>, ClientError> {
        self.send(|reply| Command::AccountRoles {
            username: username.to_owned(),
            reply,
        })
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
        self.send(|reply| Command::DisconnectUser {
            username: username.to_owned(),
            reason: reason.to_owned(),
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

    /// Provision a new account. The `password` is its initial password (sent
    /// only over TLS and hashed server-side). Requires `USER_ADMIN`. Resolves
    /// with the server's full, updated account list.
    pub async fn create_account(
        &self,
        username: &str,
        password: &str,
        base_class: u8,
        granted: u32,
        revoked: u32,
    ) -> Result<Vec<AccountSummary>, ClientError> {
        self.send(|reply| Command::CreateAccount {
            username: username.to_owned(),
            password: password.to_owned(),
            base_class,
            granted,
            revoked,
            reply,
        })
        .await
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
        self.send(|reply| Command::UpdateAccount {
            username: username.to_owned(),
            base_class,
            granted,
            revoked,
            reply,
        })
        .await
    }

    /// Ask the actor to close the connection. Best-effort.
    pub async fn disconnect(&self) {
        let _ = self.tx.send(Command::Disconnect).await;
    }
}
