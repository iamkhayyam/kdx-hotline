//! Directory of live rooms. Rooms are created on demand (privilege
//! permitting) and a default lobby always exists.

use dashmap::DashMap;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use super::room::{spawn_room, Member, RoomCommand, RoomError};
use crate::auth::Privileges;

pub const DEFAULT_ROOM: &str = "lobby";
/// Room names are user input; keep them sane.
const MAX_ROOM_NAME: usize = 64;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JoinError {
    #[error("invalid room name")]
    InvalidName,
    #[error("room does not exist and you lack CHAT_CREATE_ROOM")]
    CannotCreate,
    #[error(transparent)]
    Room(#[from] RoomError),
    #[error("room actor unavailable")]
    Unavailable,
}

pub struct RoomManager {
    rooms: DashMap<String, mpsc::Sender<RoomCommand>>,
}

impl Default for RoomManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RoomManager {
    pub fn new() -> Self {
        let rooms = DashMap::new();
        rooms.insert(DEFAULT_ROOM.to_string(), spawn_room(DEFAULT_ROOM.to_string()));
        Self { rooms }
    }

    /// Join `member` to `room`, creating it if allowed. Returns the room's
    /// command sender for subsequent messages/leave.
    pub async fn join(
        &self,
        room: &str,
        member: Member,
    ) -> Result<mpsc::Sender<RoomCommand>, JoinError> {
        if room.is_empty() || room.len() > MAX_ROOM_NAME {
            return Err(JoinError::InvalidName);
        }
        let handle = match self.rooms.get(room) {
            Some(existing) => existing.clone(),
            None => {
                if !member.privileges.contains(Privileges::CHAT_CREATE_ROOM) {
                    return Err(JoinError::CannotCreate);
                }
                self.rooms
                    .entry(room.to_string())
                    .or_insert_with(|| spawn_room(room.to_string()))
                    .clone()
            }
        };

        let (reply, rx) = oneshot::channel();
        handle
            .send(RoomCommand::Join { member, reply })
            .await
            .map_err(|_| JoinError::Unavailable)?;
        rx.await.map_err(|_| JoinError::Unavailable)??;
        Ok(handle)
    }

    /// Best-effort leave used on disconnect cleanup.
    pub async fn leave(&self, room: &str, session_id: Uuid) {
        if let Some(handle) = self.rooms.get(room) {
            let _ = handle.send(RoomCommand::Leave { session_id }).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::BaseClass;
    use crate::chat::room::Outbound;

    fn member(username: &str, class: BaseClass) -> (Member, mpsc::Receiver<Outbound>) {
        let (tx, rx) = mpsc::channel(64);
        (
            Member {
                session_id: Uuid::new_v4(),
                username: username.into(),
                privileges: class.privileges(),
                tx,
            },
            rx,
        )
    }

    #[tokio::test]
    async fn lobby_exists_for_everyone() {
        let mgr = RoomManager::new();
        let (m, _rx) = member("guest", BaseClass::Guest);
        assert!(mgr.join(DEFAULT_ROOM, m).await.is_ok());
    }

    #[tokio::test]
    async fn plain_user_cannot_create_rooms() {
        let mgr = RoomManager::new();
        let (m, _rx) = member("user", BaseClass::User);
        assert_eq!(
            mgr.join("secret-hideout", m).await.unwrap_err(),
            JoinError::CannotCreate
        );
    }

    #[tokio::test]
    async fn power_user_creates_room_others_can_join() {
        let mgr = RoomManager::new();
        let (power, _rx1) = member("power", BaseClass::PowerUser);
        mgr.join("hideout", power).await.unwrap();
        // Now a plain user can join the existing room.
        let (user, _rx2) = member("user", BaseClass::User);
        assert!(mgr.join("hideout", user).await.is_ok());
    }

    #[tokio::test]
    async fn double_join_rejected() {
        let mgr = RoomManager::new();
        let (m, _rx) = member("user", BaseClass::User);
        let dup = Member {
            session_id: m.session_id,
            username: m.username.clone(),
            privileges: m.privileges,
            tx: m.tx.clone(),
        };
        mgr.join(DEFAULT_ROOM, m).await.unwrap();
        assert_eq!(
            mgr.join(DEFAULT_ROOM, dup).await.unwrap_err(),
            JoinError::Room(RoomError::AlreadyJoined)
        );
    }
}
