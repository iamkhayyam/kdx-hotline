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

/// A room's manager-side entry: its command sender plus whether it should be
/// dropped once empty (a private, invite-created chat) rather than persist
/// like the lobby or an admin-created named room.
struct RoomEntry {
    tx: mpsc::Sender<RoomCommand>,
    temporary: bool,
}

pub struct RoomManager {
    rooms: DashMap<String, RoomEntry>,
}

impl Default for RoomManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RoomManager {
    pub fn new() -> Self {
        let rooms = DashMap::new();
        rooms.insert(
            DEFAULT_ROOM.to_string(),
            RoomEntry {
                tx: spawn_room(DEFAULT_ROOM.to_string()),
                temporary: false,
            },
        );
        Self { rooms }
    }

    /// Join `member` to `room`, creating it (as a permanent, publicly-listed
    /// room) if allowed. Returns the room's command sender for subsequent
    /// messages/leave.
    pub async fn join(
        &self,
        room: &str,
        member: Member,
    ) -> Result<mpsc::Sender<RoomCommand>, JoinError> {
        if room.is_empty() || room.len() > MAX_ROOM_NAME {
            return Err(JoinError::InvalidName);
        }
        let tx = match self.rooms.get(room) {
            Some(existing) => existing.tx.clone(),
            None => {
                if !member.privileges.contains(Privileges::CHAT_CREATE_ROOM) {
                    return Err(JoinError::CannotCreate);
                }
                self.rooms
                    .entry(room.to_string())
                    .or_insert_with(|| RoomEntry {
                        tx: spawn_room(room.to_string()),
                        temporary: false,
                    })
                    .tx
                    .clone()
            }
        };
        self.do_join(&tx, member).await?;
        Ok(tx)
    }

    /// Create (if missing) and join a private, invite-only room — bypassing
    /// `CHAT_CREATE_ROOM`, since starting a private chat is not the same
    /// privilege as founding a persistent public room. The room is marked
    /// temporary: once its last member leaves, `leave` drops it so its actor
    /// task winds down (mirrors real KDX's private chats vanishing when
    /// empty). Callers should pick a room name unlikely to collide with a
    /// user-typed public room (a UUID, say).
    pub async fn join_private(
        &self,
        room: &str,
        member: Member,
    ) -> Result<mpsc::Sender<RoomCommand>, JoinError> {
        if room.is_empty() || room.len() > MAX_ROOM_NAME {
            return Err(JoinError::InvalidName);
        }
        let tx = self
            .rooms
            .entry(room.to_string())
            .or_insert_with(|| RoomEntry {
                tx: spawn_room(room.to_string()),
                temporary: true,
            })
            .tx
            .clone();
        self.do_join(&tx, member).await?;
        Ok(tx)
    }

    async fn do_join(
        &self,
        tx: &mpsc::Sender<RoomCommand>,
        member: Member,
    ) -> Result<(), JoinError> {
        let (reply, rx) = oneshot::channel();
        tx.send(RoomCommand::Join { member, reply })
            .await
            .map_err(|_| JoinError::Unavailable)?;
        rx.await.map_err(|_| JoinError::Unavailable)??;
        Ok(())
    }

    /// Best-effort leave used on disconnect cleanup. If `room` is temporary
    /// and this was its last member, drops the manager's own sender so the
    /// room actor's channel closes and its task exits.
    pub async fn leave(&self, room: &str, session_id: Uuid) {
        let Some(entry) = self.rooms.get(room) else {
            return;
        };
        let tx = entry.tx.clone();
        let temporary = entry.temporary;
        drop(entry); // release the DashMap shard lock before any `.remove()`

        let _ = tx.send(RoomCommand::Leave { session_id }).await;

        if temporary {
            let (reply, rx) = oneshot::channel();
            if tx.send(RoomCommand::MemberCount { reply }).await.is_ok() {
                if let Ok(0) = rx.await {
                    // Check-then-remove has an ABA hazard: between our
                    // MemberCount reply and this call, the same room name
                    // could in principle have been evicted and recreated
                    // (e.g. by a concurrent `leave`/`join_private` pair). A
                    // plain `remove(room)` matches by key alone and would
                    // delete whatever now sits there — possibly a brand-new,
                    // non-empty room. `remove_if` makes the removal atomic
                    // with a same-instance check, so we only ever remove the
                    // exact entry we just measured as empty.
                    self.rooms.remove_if(room, |_, e| e.tx.same_channel(&tx));
                }
            }
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

    #[tokio::test]
    async fn join_private_bypasses_create_room_privilege() {
        let mgr = RoomManager::new();
        // A plain user (no CHAT_CREATE_ROOM) can still start a private room.
        let (guest, _rx) = member("guest", BaseClass::Guest);
        assert!(mgr.join_private("priv-1", guest).await.is_ok());
    }

    #[tokio::test]
    async fn private_room_survives_until_the_last_member_leaves() {
        let mgr = RoomManager::new();
        let (a, _rx_a) = member("alice", BaseClass::User);
        let (b, _rx_b) = member("bob", BaseClass::User);
        let a_id = a.session_id;
        let b_id = b.session_id;

        mgr.join_private("priv-2", a).await.unwrap();
        mgr.join_private("priv-2", b).await.unwrap();
        assert!(mgr.rooms.contains_key("priv-2"));

        // One member leaving doesn't evict the room — bob is still in it.
        mgr.leave("priv-2", a_id).await;
        assert!(mgr.rooms.contains_key("priv-2"), "room should survive with bob still in it");

        // The last member leaving does evict it.
        mgr.leave("priv-2", b_id).await;
        assert!(!mgr.rooms.contains_key("priv-2"), "room should be gone once empty");
    }

    #[tokio::test]
    async fn a_fresh_join_private_after_eviction_starts_a_clean_room() {
        let mgr = RoomManager::new();
        let (a, _rx_a) = member("alice", BaseClass::User);
        let a_id = a.session_id;
        mgr.join_private("priv-3", a).await.unwrap();
        mgr.leave("priv-3", a_id).await;
        assert!(!mgr.rooms.contains_key("priv-3"));

        // Reusing the same name after eviction spins up a brand new room,
        // not a stale reference to the torn-down one.
        let (b, _rx_b) = member("bob", BaseClass::User);
        assert!(mgr.join_private("priv-3", b).await.is_ok());
        assert!(mgr.rooms.contains_key("priv-3"));
    }

    #[tokio::test]
    async fn stale_eviction_does_not_delete_a_recreated_room_with_the_same_name() {
        // Regression test for an ABA hazard: `leave()` used to check
        // emptiness then call a plain `remove(room)`, which matches by key
        // alone. If the same room name were evicted and then recreated
        // before a (delayed) stale removal ran, that removal would delete
        // the brand-new room instead of a no-op. `remove_if` closes this by
        // requiring the entry removed to be the exact instance measured.
        let mgr = RoomManager::new();
        let old_tx = mgr.rooms.get("priv-4").map(|e| e.tx.clone());
        assert!(old_tx.is_none()); // doesn't exist yet

        let (a, _rx_a) = member("alice", BaseClass::User);
        let a_id = a.session_id;
        mgr.join_private("priv-4", a).await.unwrap();
        let stale_tx = mgr.rooms.get("priv-4").unwrap().tx.clone();

        // Alice leaves — the room is evicted normally.
        mgr.leave("priv-4", a_id).await;
        assert!(!mgr.rooms.contains_key("priv-4"));

        // A new room is created under the SAME name (simulating a name
        // reused right in the eviction window).
        let (b, _rx_b) = member("bob", BaseClass::User);
        mgr.join_private("priv-4", b).await.unwrap();
        let fresh_tx = mgr.rooms.get("priv-4").unwrap().tx.clone();
        assert!(!fresh_tx.same_channel(&stale_tx), "test setup: must be a different room instance");

        // A delayed, stale removal keyed on the OLD room's sender must NOT
        // touch the fresh room.
        mgr.rooms.remove_if("priv-4", |_, e| e.tx.same_channel(&stale_tx));
        assert!(mgr.rooms.contains_key("priv-4"), "fresh room must survive a stale eviction attempt");
    }
}
