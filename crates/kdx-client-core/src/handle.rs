use tokio::sync::{mpsc, oneshot};

use kdx_protocol::messages::FileListResponse;

use crate::error::ClientError;

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

    /// Ask the actor to close the connection. Best-effort.
    pub async fn disconnect(&self) {
        let _ = self.tx.send(Command::Disconnect).await;
    }
}
