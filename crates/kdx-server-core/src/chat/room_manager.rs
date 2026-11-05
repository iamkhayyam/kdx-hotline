//! Directory of live rooms. Rooms are created on demand (privilege
//! permitting) and a default lobby always exists. Every other room is
//! evicted once its last member leaves, and the total is capped
//! (`limits::MAX_ROOMS`).

use std::collections::HashSet;

use dashmap::DashMap;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use super::room::{spawn_room, Member, RoomCommand, RoomError};
use crate::auth::Privileges;
use crate::limits;

pub const DEFAULT_ROOM: &str = "lobby";
/// Name prefix reserved for invite-only private rooms (`ChatInvite`). A
/// public `join` never creates a room under it.
pub const PRIVATE_ROOM_PREFIX: &str = "priv-";
/// How often `join` retries after losing a race with an eviction.
const JOIN_ATTEMPTS: usize = 3;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JoinError {
    #[error("invalid room name")]
    InvalidName,
    #[error("room does not exist and you lack CHAT_CREATE_ROOM")]
    CannotCreate,
    #[error("you were not invited to that room")]
    NotInvited,
    #[error("the server has too many chat rooms")]
    TooManyRooms,
    #[error(transparent)]
    Room(#[from] RoomError),
    #[error("room actor unavailable")]
    Unavailable,
}

/// A room's manager-side entry: its command sender, and for a private
/// (invite-created) room, who may join it.
struct RoomEntry {
    tx: mpsc::Sender<RoomCommand>,
    /// Invite-only: only usernames in `invited` may join.
    private: bool,
    invited: HashSet<String>,
}

pub struct RoomManager {
    rooms: DashMap<String, RoomEntry>,
}

impl Default for RoomManager {
    fn default() -> Self {
        Self::new()
    }
}

fn check_name(room: &str) -> Result<(), JoinError> {
    if room.is_empty() || room.len() > limits::MAX_NAME_LEN {
        return Err(JoinError::InvalidName);
    }
    Ok(())
}

impl RoomManager {
    pub fn new() -> Self {
        let rooms = DashMap::new();
        rooms.insert(
            DEFAULT_ROOM.to_string(),
            RoomEntry {
                tx: spawn_room(DEFAULT_ROOM.to_string()),
                private: false,
                invited: HashSet::new(),
            },
        );
        Self { rooms }
    }

    /// Join `member` to `room`, creating it (as a public room) if allowed.
    /// Private rooms admit only invited usernames, and a name under the
    /// private prefix is never created here. Returns the room's command
    /// sender for subsequent messages/leave.
    pub async fn join(
        &self,
        room: &str,
        member: Member,
    ) -> Result<mpsc::Sender<RoomCommand>, JoinError> {
        check_name(room)?;
        for _ in 0..JOIN_ATTEMPTS {
            // Copy what we need out of the entry so no shard guard is held
            // across an await (or across the `create` below).
            let existing = self.rooms.get(room).map(|e| {
                let allowed = !e.private || e.invited.contains(&member.username);
                (e.tx.clone(), allowed)
            });
            let tx = match existing {
                Some((_, false)) => return Err(JoinError::NotInvited),
                Some((tx, true)) => tx,
                None => {
                    if room.starts_with(PRIVATE_ROOM_PREFIX) {
                        return Err(JoinError::NotInvited);
                    }
                    if !member.privileges.contains(Privileges::CHAT_CREATE_ROOM) {
                        return Err(JoinError::CannotCreate);
                    }
                    self.create(room, false, None)?
                }
            };
            match self.do_join(&tx, member.clone()).await {
                Err(JoinError::Room(RoomError::Closed)) => self.forget(room, &tx),
                result => return result.map(|()| tx),
            }
        }
        Err(JoinError::Unavailable)
    }

    /// Create (if missing) and join a private, invite-only room — bypassing
    /// `CHAT_CREATE_ROOM`, since starting a private chat is not the same
    /// privilege as founding a public room. The creator is on the room's
    /// invite list (so they can rejoin); add others with [`Self::invite`].
    /// Like every non-lobby room it is dropped once its last member leaves.
    /// Callers should pick a name under [`PRIVATE_ROOM_PREFIX`] that can't
    /// collide (a UUID, say).
    pub async fn join_private(
        &self,
        room: &str,
        member: Member,
    ) -> Result<mpsc::Sender<RoomCommand>, JoinError> {
        check_name(room)?;
        for _ in 0..JOIN_ATTEMPTS {
            let tx = self.create(room, true, Some(&member.username))?;
            match self.do_join(&tx, member.clone()).await {
                Err(JoinError::Room(RoomError::Closed)) => self.forget(room, &tx),
                result => return result.map(|()| tx),
            }
        }
        Err(JoinError::Unavailable)
    }

    /// Allow `username` to join the private room `room`. Returns `false` if
    /// there's no such private room.
    pub fn invite(&self, room: &str, username: &str) -> bool {
        match self.rooms.get_mut(room) {
            Some(mut entry) if entry.private => {
                entry.invited.insert(username.to_owned());
                true
            }
            _ => false,
        }
    }

    /// The room's sender, creating the room if it doesn't exist (subject to
    /// `MAX_ROOMS`). `invitee` is added to a private room's invite list.
    fn create(
        &self,
        room: &str,
        private: bool,
        invitee: Option<&str>,
    ) -> Result<mpsc::Sender<RoomCommand>, JoinError> {
        // `len()` locks every shard, so call it with no guard held.
        if !self.rooms.contains_key(room) && self.rooms.len() >= limits::MAX_ROOMS {
            return Err(JoinError::TooManyRooms);
        }
        let mut entry = self
            .rooms
            .entry(room.to_string())
            .or_insert_with(|| RoomEntry {
                tx: spawn_room(room.to_string()),
                private,
                invited: HashSet::new(),
            });
        if let Some(name) = invitee {
            entry.invited.insert(name.to_owned());
        }
        Ok(entry.tx.clone())
    }

    /// Drop `room` from the directory if it is still the instance behind
    /// `tx` (never a same-named room created since).
    fn forget(&self, room: &str, tx: &mpsc::Sender<RoomCommand>) {
        self.rooms.remove_if(room, |_, e| e.tx.same_channel(tx));
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

    /// Change `room`'s admin-configurable flags on behalf of the member with
    /// `session_id`. The room actor enforces `CHAT_SET_TOPIC` (and
    /// SERVER_ADMIN for the lobby) on the caller; non-members receive
    /// `NotMember`.
    pub async fn set_flags(
        &self,
        room: &str,
        session_id: Uuid,
        min_class_join: u8,
        interview_mode: bool,
    ) -> Result<(), RoomError> {
        let tx = self
            .rooms
            .get(room)
            .map(|e| e.tx.clone())
            .ok_or(RoomError::NotMember)?;
        let (reply, rx) = oneshot::channel();
        tx.send(RoomCommand::SetFlags {
            session_id,
            min_class_join,
            interview_mode,
            reply,
        })
        .await
        .map_err(|_| RoomError::NotMember)?;
        rx.await.map_err(|_| RoomError::NotMember)?
    }

    /// Leave `room` (also used on disconnect cleanup). If this emptied a
    /// room other than the lobby, the room is closed and dropped so its
    /// actor task winds down.
    pub async fn leave(&self, room: &str, session_id: Uuid) {
        let Some(tx) = self.rooms.get(room).map(|e| e.tx.clone()) else {
            return;
        };
        let _ = tx.send(RoomCommand::Leave { session_id }).await;
        if room == DEFAULT_ROOM {
            return;
        }
        // The actor closes itself only if empty, so a join racing this
        // eviction is refused (and retried against a fresh room) rather
        // than landing in a room nobody can find. `remove_if` only drops
        // the exact instance we closed, never a same-named successor.
        let (reply, rx) = oneshot::channel();
        if tx.send(RoomCommand::CloseIfEmpty { reply }).await.is_ok() && rx.await == Ok(true) {
            self.forget(room, &tx);
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
                class: class as u8,
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
            class: m.class,
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
    async fn min_class_join_flag_refuses_below_threshold() {
        let mgr = RoomManager::new();
        // A PowerUser (has CHAT_SET_TOPIC) founds the room and tightens
        // the class gate to PowerUser (2) — anyone below is refused.
        let (power, _rx1) = member("power", BaseClass::PowerUser);
        let power_id = power.session_id;
        mgr.join("green-room", power).await.unwrap();
        mgr.set_flags("green-room", power_id, /*min*/ 2, /*interview*/ false)
            .await
            .unwrap();

        // A plain User can't join the tightened room…
        let (user, _rx2) = member("user", BaseClass::User);
        assert_eq!(
            mgr.join("green-room", user).await.unwrap_err(),
            JoinError::Room(RoomError::ClassTooLow)
        );
        // …but another PowerUser or above can.
        let (poweruser2, _rx3) = member("admin", BaseClass::Admin);
        assert!(mgr.join("green-room", poweruser2).await.is_ok());
    }

    #[tokio::test]
    async fn plain_member_cannot_change_flags() {
        let mgr = RoomManager::new();
        let (m, _rx) = member("user", BaseClass::User);
        let m_id = m.session_id;
        mgr.join(DEFAULT_ROOM, m).await.unwrap();
        assert_eq!(
            mgr.set_flags(DEFAULT_ROOM, m_id, 2, true).await.unwrap_err(),
            RoomError::NoPrivilege
        );
    }

    #[tokio::test]
    async fn non_member_cannot_change_flags() {
        let mgr = RoomManager::new();
        let (m, _rx) = member("power", BaseClass::PowerUser);
        // Deliberately NOT joining: we're testing that a caller who
        // isn't in the room can't change its flags.
        assert_eq!(
            mgr.set_flags(DEFAULT_ROOM, m.session_id, 2, true).await.unwrap_err(),
            RoomError::NotMember
        );
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

    #[tokio::test]
    async fn empty_public_room_is_evicted_on_last_leave() {
        let mgr = RoomManager::new();
        let (power, _rx) = member("power", BaseClass::PowerUser);
        let power_id = power.session_id;
        mgr.join("hideout", power).await.unwrap();
        assert!(mgr.rooms.contains_key("hideout"));
        mgr.leave("hideout", power_id).await;
        assert!(!mgr.rooms.contains_key("hideout"), "empty room should be evicted");
    }

    #[tokio::test]
    async fn lobby_is_never_evicted() {
        let mgr = RoomManager::new();
        let (m, _rx) = member("user", BaseClass::User);
        let id = m.session_id;
        mgr.join(DEFAULT_ROOM, m).await.unwrap();
        mgr.leave(DEFAULT_ROOM, id).await;
        assert!(mgr.rooms.contains_key(DEFAULT_ROOM));
        let (again, _rx2) = member("user", BaseClass::User);
        assert!(mgr.join(DEFAULT_ROOM, again).await.is_ok());
    }

    #[tokio::test]
    async fn room_count_is_capped() {
        let mgr = RoomManager::new();
        let (power, _rx) = member("power", BaseClass::PowerUser);
        // The lobby counts toward the cap.
        for i in 1..limits::MAX_ROOMS {
            let m = Member {
                session_id: Uuid::new_v4(),
                ..power.clone()
            };
            mgr.join(&format!("room-{i}"), m).await.unwrap();
        }
        assert_eq!(
            mgr.join("one-too-many", power.clone()).await.unwrap_err(),
            JoinError::TooManyRooms
        );
        assert_eq!(
            mgr.join_private("priv-x", power.clone()).await.unwrap_err(),
            JoinError::TooManyRooms
        );
        // Existing rooms stay joinable.
        assert!(mgr.join("room-1", power).await.is_ok());
    }

    #[tokio::test]
    async fn private_room_admits_only_invitees() {
        let mgr = RoomManager::new();
        let (alice, _rx_a) = member("alice", BaseClass::User);
        let alice_id = alice.session_id;
        mgr.join_private("priv-5", alice).await.unwrap();
        assert!(mgr.invite("priv-5", "bob"));

        // An uninvited user (even one who may create rooms) is refused.
        let (carol, _rx_c) = member("carol", BaseClass::Admin);
        assert_eq!(mgr.join("priv-5", carol).await.unwrap_err(), JoinError::NotInvited);

        // The invitee gets in, and the creator may rejoin after leaving.
        let (bob, _rx_b) = member("bob", BaseClass::User);
        assert!(mgr.join("priv-5", bob).await.is_ok());
        mgr.leave("priv-5", alice_id).await;
        let (alice_again, _rx_a2) = member("alice", BaseClass::User);
        assert!(mgr.join("priv-5", alice_again).await.is_ok());
    }

    #[tokio::test]
    async fn public_join_never_creates_a_private_name() {
        let mgr = RoomManager::new();
        let (admin, _rx) = member("admin", BaseClass::Admin);
        assert_eq!(mgr.join("priv-gone", admin).await.unwrap_err(), JoinError::NotInvited);
        assert!(!mgr.rooms.contains_key("priv-gone"));
        assert!(!mgr.invite(DEFAULT_ROOM, "anyone"), "public rooms have no invite list");
    }

    #[tokio::test]
    async fn join_racing_an_eviction_lands_in_a_live_room() {
        let mgr = RoomManager::new();
        let (power, _rx) = member("power", BaseClass::PowerUser);
        mgr.join("den", power.clone()).await.unwrap();
        let old_tx = mgr.rooms.get("den").unwrap().tx.clone();
        // Simulate an eviction that closed the actor but hasn't removed the
        // directory entry yet.
        old_tx
            .send(RoomCommand::Leave {
                session_id: power.session_id,
            })
            .await
            .unwrap();
        let (reply, rx) = oneshot::channel();
        old_tx.send(RoomCommand::CloseIfEmpty { reply }).await.unwrap();
        assert!(rx.await.unwrap());

        let (user, _rx2) = member("user", BaseClass::PowerUser);
        let tx = mgr.join("den", user).await.unwrap();
        assert!(!tx.same_channel(&old_tx), "must not join the closed room");
        assert!(mgr.rooms.get("den").unwrap().tx.same_channel(&tx));
    }
}
