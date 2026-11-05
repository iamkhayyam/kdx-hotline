//! One chat room = one actor task. The task exclusively owns membership,
//! topic, and room flags; connection tasks talk to it through
//! `RoomCommand`s and receive broadcasts on their outbound channel. This
//! keeps the hot broadcast path free of shared locks. Chat flood control
//! lives with the connection (see `FloodGate`), not here, so leaving and
//! rejoining a room can't reset it.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use kdx_protocol::messages::{ChatEvent, ChatTopic, ChatUserList, CHAT_ACTION, CHAT_SYSTEM};
use kdx_protocol::{PacketFlags, PacketType};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};
use tracing::debug;
use uuid::Uuid;

use super::room_manager::DEFAULT_ROOM;
use crate::auth::Privileges;

/// Command-channel depth per room.
pub const ROOM_QUEUE: usize = 256;

/// A pre-encoded frame ready for a connection task to write to its socket.
#[derive(Debug, Clone)]
pub struct Outbound {
    pub packet_type: PacketType,
    pub flags: PacketFlags,
    pub payload: Bytes,
}

/// A room member as the room actor sees it.
#[derive(Debug, Clone)]
pub struct Member {
    pub session_id: Uuid,
    pub username: String,
    /// The member's `BaseClass` as a raw u8 (0..=3). Kept as a plain integer
    /// here so the room actor stays independent of the auth module's type;
    /// callers just pass `session.class as u8`. Used for the per-room
    /// `min_class_join` gate.
    pub class: u8,
    pub privileges: Privileges,
    /// The member's connection outbound channel.
    pub tx: mpsc::Sender<Outbound>,
}

#[derive(Debug)]
pub enum RoomCommand {
    Join {
        member: Member,
        reply: oneshot::Sender<Result<(), RoomError>>,
    },
    Leave {
        session_id: Uuid,
    },
    Message {
        session_id: Uuid,
        flags: u8,
        text: String,
    },
    SetTopic {
        session_id: Uuid,
        topic: String,
        reply: oneshot::Sender<Result<(), RoomError>>,
    },
    /// Number of members, for tests/introspection.
    MemberCount {
        reply: oneshot::Sender<usize>,
    },
    /// Change the room's admin-configurable flags. Requires CHAT_SET_TOPIC,
    /// plus SERVER_ADMIN for the lobby; the join gate can't be raised above
    /// the caller's own class.
    SetFlags {
        session_id: Uuid,
        min_class_join: u8,
        interview_mode: bool,
        reply: oneshot::Sender<Result<(), RoomError>>,
    },
    /// Read back the current flags — used by the manager's join gate so a
    /// class-below-threshold caller is refused at the manager, not left
    /// hanging as an in-room error.
    GetFlags {
        reply: oneshot::Sender<(u8, bool)>,
    },
    /// Eviction handshake: if the room is empty, mark it closed (every later
    /// `Join` is refused with `RoomError::Closed`) and reply `true`. The
    /// manager then drops the room from its directory. Closing inside the
    /// actor makes "empty, so evict" atomic with respect to joins.
    CloseIfEmpty {
        reply: oneshot::Sender<bool>,
    },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RoomError {
    #[error("not a member of this room")]
    NotMember,
    #[error("missing privilege")]
    NoPrivilege,
    #[error("already joined")]
    AlreadyJoined,
    #[error("class too low for this room")]
    ClassTooLow,
    #[error("interview mode: only the panelist may speak")]
    InterviewMuted,
    #[error("cannot set a join class above your own class")]
    AboveOwnClass,
    #[error("room was closed")]
    Closed,
}

struct RoomState {
    name: String,
    topic: String,
    members: HashMap<Uuid, Member>,
    /// Minimum `BaseClass` (0..=3) needed to join. Defaults to 0 (open to
    /// everyone connected). Existing members are never evicted when this
    /// tightens — the gate only applies to future joins.
    min_class_join: u8,
    /// When set, only members with `CHAT_SET_TOPIC` may `Message`. Every
    /// other member's send is refused with an `Info` naming the mode; the
    /// message is silently dropped (not surfaced to the room).
    interview_mode: bool,
    /// Set by `CloseIfEmpty`; a closed room refuses every join.
    closed: bool,
}

/// Spawn a room actor; returns its command sender. The task exits when every
/// command sender is dropped (RoomManager holds one for the room's lifetime).
pub fn spawn_room(name: String) -> mpsc::Sender<RoomCommand> {
    let (tx, mut rx) = mpsc::channel(ROOM_QUEUE);
    let mut room = RoomState {
        name,
        topic: String::new(),
        members: HashMap::new(),
        min_class_join: 0,
        interview_mode: false,
        closed: false,
    };
    tokio::spawn(async move {
        while let Some(command) = rx.recv().await {
            room.handle(command);
        }
        debug!(room = %room.name, "room actor stopped");
    });
    tx
}

impl RoomState {
    fn handle(&mut self, command: RoomCommand) {
        match command {
            RoomCommand::Join { member, reply } => {
                if self.closed {
                    let _ = reply.send(Err(RoomError::Closed));
                    return;
                }
                if self.members.contains_key(&member.session_id) {
                    let _ = reply.send(Err(RoomError::AlreadyJoined));
                    return;
                }
                // Per-room class gate — checked here in the actor so a
                // client that raced the manager's cache still gets a
                // clean refusal.
                if member.class < self.min_class_join {
                    let _ = reply.send(Err(RoomError::ClassTooLow));
                    return;
                }
                let session_id = member.session_id;
                let username = member.username.clone();
                self.members.insert(session_id, member);
                let _ = reply.send(Ok(()));

                // Current topic goes to the joiner; everyone gets the fresh
                // member list and a join notice.
                if !self.topic.is_empty() {
                    let topic = ChatTopic {
                        room: self.name.clone(),
                        topic: self.topic.clone(),
                    };
                    self.send_to(
                        session_id,
                        Outbound {
                            packet_type: PacketType::ChatTopicSet,
                            flags: PacketFlags::empty(),
                            payload: topic.encode(),
                        },
                    );
                }
                self.broadcast(self.user_list());
                self.broadcast(self.system(format!("{username} joined")));
            }
            RoomCommand::Leave { session_id } => {
                if self.members.contains_key(&session_id) {
                    self.prune(vec![session_id]);
                }
            }
            RoomCommand::Message {
                session_id,
                flags,
                text,
            } => {
                let Some(member) = self.members.get(&session_id) else {
                    return; // silently drop from non-members
                };
                // Interview mode: only panelists (CHAT_SET_TOPIC) may speak.
                // Rejected sends get an Info back to the sender explaining
                // the mode, and are NOT broadcast to the room.
                if self.interview_mode
                    && !member.privileges.contains(Privileges::CHAT_SET_TOPIC)
                {
                    let notice = format!(
                        "#{}: interview mode is on — only the panelist may speak",
                        self.name
                    );
                    self.send_to(
                        session_id,
                        Outbound {
                            packet_type: PacketType::Info,
                            flags: PacketFlags::SYSTEM_MESSAGE,
                            payload: Bytes::copy_from_slice(notice.as_bytes()),
                        },
                    );
                    return;
                }
                let event = ChatEvent {
                    room: self.name.clone(),
                    sender: member.username.clone(),
                    timestamp: unix_now(),
                    // Only the action bit is the client's to set: system
                    // notices and undefined bits can't be forged.
                    flags: flags & CHAT_ACTION,
                    text,
                };
                self.broadcast(Outbound {
                    packet_type: PacketType::ChatMessage,
                    flags: PacketFlags::empty(),
                    payload: event.encode(),
                });
            }
            RoomCommand::SetTopic {
                session_id,
                topic,
                reply,
            } => {
                let Some(member) = self.members.get(&session_id) else {
                    let _ = reply.send(Err(RoomError::NotMember));
                    return;
                };
                if !member.privileges.contains(Privileges::CHAT_SET_TOPIC) {
                    let _ = reply.send(Err(RoomError::NoPrivilege));
                    return;
                }
                self.topic = topic.clone();
                let _ = reply.send(Ok(()));
                let announce = ChatTopic {
                    room: self.name.clone(),
                    topic,
                };
                self.broadcast(Outbound {
                    packet_type: PacketType::ChatTopicSet,
                    flags: PacketFlags::empty(),
                    payload: announce.encode(),
                });
            }
            RoomCommand::MemberCount { reply } => {
                let _ = reply.send(self.members.len());
            }
            RoomCommand::SetFlags {
                session_id,
                min_class_join,
                interview_mode,
                reply,
            } => {
                let Some(member) = self.members.get(&session_id) else {
                    let _ = reply.send(Err(RoomError::NotMember));
                    return;
                };
                if !member.privileges.contains(Privileges::CHAT_SET_TOPIC) {
                    let _ = reply.send(Err(RoomError::NoPrivilege));
                    return;
                }
                // The lobby is everyone's landing room: only a server admin
                // may gate or mute it.
                if self.name == DEFAULT_ROOM
                    && !member.privileges.contains(Privileges::SERVER_ADMIN)
                {
                    let _ = reply.send(Err(RoomError::NoPrivilege));
                    return;
                }
                let clamped = min_class_join.min(3);
                // Never lock a room above your own class.
                if clamped > member.class {
                    let _ = reply.send(Err(RoomError::AboveOwnClass));
                    return;
                }
                let prior_interview = self.interview_mode;
                self.min_class_join = clamped;
                self.interview_mode = interview_mode;
                let _ = reply.send(Ok(()));
                // System-message the room so every joined member sees the
                // change without having to poll.
                let mut parts = Vec::new();
                if prior_interview != interview_mode {
                    parts.push(
                        if interview_mode { "interview mode on" } else { "interview mode off" }
                            .to_string(),
                    );
                }
                parts.push(format!("min class {clamped}"));
                self.broadcast(self.system(format!("room flags: {}", parts.join(", "))));
            }
            RoomCommand::GetFlags { reply } => {
                let _ = reply.send((self.min_class_join, self.interview_mode));
            }
            RoomCommand::CloseIfEmpty { reply } => {
                let empty = self.members.is_empty();
                if empty {
                    self.closed = true;
                }
                let _ = reply.send(empty);
            }
        }
    }

    /// Send to every member. A slow/full member channel drops that member's
    /// copy rather than stalling the whole room; a closed one means the
    /// member's connection is gone, so the member is dropped from the room.
    fn broadcast(&mut self, outbound: Outbound) {
        let dead = self.fan_out(&outbound);
        self.prune(dead);
    }

    /// Try-send `outbound` to every member; returns the members whose
    /// channel is closed.
    fn fan_out(&self, outbound: &Outbound) -> Vec<Uuid> {
        let mut dead = Vec::new();
        for (session_id, member) in &self.members {
            if let Err(TrySendError::Closed(_)) = member.tx.try_send(outbound.clone()) {
                dead.push(*session_id);
            }
        }
        dead
    }

    /// Remove the `gone` members and tell the rest (a fresh user list plus a
    /// "left" notice each). Members found dead while announcing are removed
    /// in the next round.
    fn prune(&mut self, mut gone: Vec<Uuid>) {
        while !gone.is_empty() {
            let names: Vec<String> = gone
                .drain(..)
                .filter_map(|id| self.members.remove(&id).map(|m| m.username))
                .collect();
            if names.is_empty() {
                break;
            }
            gone.extend(self.fan_out(&self.user_list()));
            for name in names {
                gone.extend(self.fan_out(&self.system(format!("{name} left"))));
            }
        }
    }

    fn user_list(&self) -> Outbound {
        let list = ChatUserList {
            room: self.name.clone(),
            users: self.members.values().map(|m| m.username.clone()).collect(),
        };
        Outbound {
            packet_type: PacketType::ChatUserList,
            flags: PacketFlags::empty(),
            payload: list.encode(),
        }
    }

    fn system(&self, text: String) -> Outbound {
        let event = ChatEvent {
            room: self.name.clone(),
            sender: String::new(),
            timestamp: unix_now(),
            flags: CHAT_SYSTEM,
            text,
        };
        Outbound {
            packet_type: PacketType::ChatMessage,
            flags: PacketFlags::SYSTEM_MESSAGE,
            payload: event.encode(),
        }
    }

    fn send_to(&self, session_id: Uuid, outbound: Outbound) {
        if let Some(member) = self.members.get(&session_id) {
            let _ = member.tx.try_send(outbound);
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::BaseClass;

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

    async fn join(room: &mpsc::Sender<RoomCommand>, m: Member) -> Result<(), RoomError> {
        let (reply, rx) = oneshot::channel();
        room.send(RoomCommand::Join { member: m, reply }).await.unwrap();
        rx.await.unwrap()
    }

    async fn count(room: &mpsc::Sender<RoomCommand>) -> usize {
        let (reply, rx) = oneshot::channel();
        room.send(RoomCommand::MemberCount { reply }).await.unwrap();
        rx.await.unwrap()
    }

    async fn set_flags(
        room: &mpsc::Sender<RoomCommand>,
        session_id: Uuid,
        min_class_join: u8,
        interview_mode: bool,
    ) -> Result<(), RoomError> {
        let (reply, rx) = oneshot::channel();
        room.send(RoomCommand::SetFlags {
            session_id,
            min_class_join,
            interview_mode,
            reply,
        })
        .await
        .unwrap();
        rx.await.unwrap()
    }

    fn chat_texts(rx: &mut mpsc::Receiver<Outbound>) -> Vec<ChatEvent> {
        let mut events = Vec::new();
        while let Ok(out) = rx.try_recv() {
            if out.packet_type == PacketType::ChatMessage {
                events.push(ChatEvent::decode(&out.payload).unwrap());
            }
        }
        events
    }

    #[tokio::test]
    async fn member_with_a_closed_channel_is_dropped_on_broadcast() {
        let room = spawn_room("den".into());
        let (alice, mut rx_a) = member("alice", BaseClass::User);
        let (bob, rx_b) = member("bob", BaseClass::User);
        join(&room, alice).await.unwrap();
        join(&room, bob).await.unwrap();
        assert_eq!(count(&room).await, 2);

        // Bob's connection dies without a Leave (its receiver is dropped).
        drop(rx_b);
        // The next broadcast notices the closed channel and evicts him.
        let (carol, _rx_c) = member("carol", BaseClass::User);
        join(&room, carol).await.unwrap();
        assert_eq!(count(&room).await, 2, "bob should have been pruned");

        // Alice was told bob left.
        assert!(chat_texts(&mut rx_a).iter().any(|e| e.text == "bob left"));
    }

    #[tokio::test]
    async fn closed_room_refuses_joins() {
        let room = spawn_room("den".into());
        let (reply, rx) = oneshot::channel();
        room.send(RoomCommand::CloseIfEmpty { reply }).await.unwrap();
        assert!(rx.await.unwrap());
        let (alice, _rx) = member("alice", BaseClass::User);
        assert_eq!(join(&room, alice).await, Err(RoomError::Closed));
    }

    #[tokio::test]
    async fn non_empty_room_is_not_closed() {
        let room = spawn_room("den".into());
        let (alice, _rx) = member("alice", BaseClass::User);
        join(&room, alice).await.unwrap();
        let (reply, rx) = oneshot::channel();
        room.send(RoomCommand::CloseIfEmpty { reply }).await.unwrap();
        assert!(!rx.await.unwrap());
        let (bob, _rx_b) = member("bob", BaseClass::User);
        assert!(join(&room, bob).await.is_ok());
    }

    #[tokio::test]
    async fn power_user_cannot_gate_or_mute_the_lobby() {
        let lobby = spawn_room(DEFAULT_ROOM.into());
        let (power, _rx) = member("power", BaseClass::PowerUser);
        let power_id = power.session_id;
        join(&lobby, power).await.unwrap();
        assert_eq!(set_flags(&lobby, power_id, 0, true).await, Err(RoomError::NoPrivilege));

        // An admin may.
        let (admin, _rx2) = member("admin", BaseClass::Admin);
        let admin_id = admin.session_id;
        join(&lobby, admin).await.unwrap();
        assert!(set_flags(&lobby, admin_id, 1, true).await.is_ok());
    }

    #[tokio::test]
    async fn join_gate_cannot_exceed_the_callers_class() {
        let room = spawn_room("hideout".into());
        let (power, _rx) = member("power", BaseClass::PowerUser);
        let power_id = power.session_id;
        join(&room, power).await.unwrap();
        assert_eq!(
            set_flags(&room, power_id, 3, false).await,
            Err(RoomError::AboveOwnClass)
        );
        assert!(set_flags(&room, power_id, 2, false).await.is_ok());
    }

    #[tokio::test]
    async fn chat_flags_are_masked_to_the_action_bit() {
        let room = spawn_room("den".into());
        let (alice, mut rx) = member("alice", BaseClass::User);
        let alice_id = alice.session_id;
        join(&room, alice).await.unwrap();
        room.send(RoomCommand::Message {
            session_id: alice_id,
            flags: 0xFF,
            text: "hi".into(),
        })
        .await
        .unwrap();
        count(&room).await; // round-trip so the message was handled
        let flags = chat_texts(&mut rx)
            .into_iter()
            .find(|e| e.text == "hi")
            .map(|e| e.flags);
        assert_eq!(flags, Some(CHAT_ACTION));
    }
}
