//! One chat room = one actor task. The task exclusively owns membership,
//! topic, and per-member flood gates; connection tasks talk to it through
//! `RoomCommand`s and receive broadcasts on their outbound channel. This
//! keeps the hot broadcast path free of shared locks.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use kdx_protocol::messages::{ChatEvent, ChatTopic, ChatUserList, CHAT_SYSTEM};
use kdx_protocol::{PacketFlags, PacketType};
use tokio::sync::{mpsc, oneshot};
use tracing::debug;
use uuid::Uuid;

use super::flood::FloodGate;
use crate::auth::Privileges;

/// Messages a member may receive per burst / refill rate per second.
const FLOOD_BURST: u32 = 5;
const FLOOD_REFILL_PER_SEC: f64 = 1.0;
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
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RoomError {
    #[error("not a member of this room")]
    NotMember,
    #[error("missing privilege")]
    NoPrivilege,
    #[error("already joined")]
    AlreadyJoined,
}

struct RoomState {
    name: String,
    topic: String,
    members: HashMap<Uuid, Member>,
    gates: HashMap<Uuid, FloodGate>,
}

/// Spawn a room actor; returns its command sender. The task exits when every
/// command sender is dropped (RoomManager holds one for the room's lifetime).
pub fn spawn_room(name: String) -> mpsc::Sender<RoomCommand> {
    let (tx, mut rx) = mpsc::channel(ROOM_QUEUE);
    let mut room = RoomState {
        name,
        topic: String::new(),
        members: HashMap::new(),
        gates: HashMap::new(),
    };
    tokio::spawn(async move {
        while let Some(command) = rx.recv().await {
            room.handle(command).await;
        }
        debug!(room = %room.name, "room actor stopped");
    });
    tx
}

impl RoomState {
    async fn handle(&mut self, command: RoomCommand) {
        match command {
            RoomCommand::Join { member, reply } => {
                if self.members.contains_key(&member.session_id) {
                    let _ = reply.send(Err(RoomError::AlreadyJoined));
                    return;
                }
                let session_id = member.session_id;
                let username = member.username.clone();
                self.gates
                    .insert(session_id, FloodGate::new(FLOOD_BURST, FLOOD_REFILL_PER_SEC));
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
                    )
                    .await;
                }
                self.broadcast_user_list().await;
                self.broadcast_system(format!("{username} joined")).await;
            }
            RoomCommand::Leave { session_id } => {
                if let Some(member) = self.members.remove(&session_id) {
                    self.gates.remove(&session_id);
                    self.broadcast_user_list().await;
                    self.broadcast_system(format!("{} left", member.username))
                        .await;
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
                let sender = member.username.clone();
                let gate = self
                    .gates
                    .get_mut(&session_id)
                    .expect("gate exists for every member");
                if !gate.allow() {
                    self.send_to(
                        session_id,
                        Outbound {
                            packet_type: PacketType::Warning,
                            flags: PacketFlags::SYSTEM_MESSAGE,
                            payload: Bytes::from_static(b"flood protection: slow down"),
                        },
                    )
                    .await;
                    return;
                }
                let event = ChatEvent {
                    room: self.name.clone(),
                    sender,
                    timestamp: unix_now(),
                    flags: flags & !CHAT_SYSTEM, // clients cannot forge system notices
                    text,
                };
                self.broadcast(Outbound {
                    packet_type: PacketType::ChatMessage,
                    flags: PacketFlags::empty(),
                    payload: event.encode(),
                })
                .await;
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
                })
                .await;
            }
            RoomCommand::MemberCount { reply } => {
                let _ = reply.send(self.members.len());
            }
        }
    }

    async fn broadcast(&self, outbound: Outbound) {
        for member in self.members.values() {
            // A slow/full member channel drops that member's copy rather
            // than stalling the whole room.
            let _ = member.tx.try_send(outbound.clone());
        }
    }

    async fn broadcast_user_list(&self) {
        let list = ChatUserList {
            room: self.name.clone(),
            users: self.members.values().map(|m| m.username.clone()).collect(),
        };
        self.broadcast(Outbound {
            packet_type: PacketType::ChatUserList,
            flags: PacketFlags::empty(),
            payload: list.encode(),
        })
        .await;
    }

    async fn broadcast_system(&self, text: String) {
        let event = ChatEvent {
            room: self.name.clone(),
            sender: String::new(),
            timestamp: unix_now(),
            flags: CHAT_SYSTEM,
            text,
        };
        self.broadcast(Outbound {
            packet_type: PacketType::ChatMessage,
            flags: PacketFlags::SYSTEM_MESSAGE,
            payload: event.encode(),
        })
        .await;
    }

    async fn send_to(&self, session_id: Uuid, outbound: Outbound) {
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
