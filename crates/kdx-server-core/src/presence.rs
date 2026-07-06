//! Server-wide presence: who's online, for the global User List and User
//! Info windows. One actor task owns the roster (mirrors the tracker/chat
//! room actor pattern); connections join on authentication and leave on
//! disconnect, and every join/leave is broadcast live to all present
//! connections via their outbound channel.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use kdx_protocol::messages::PresenceChange;
use kdx_protocol::messages::PresenceEntry as WireEntry;
use kdx_protocol::{PacketFlags, PacketType};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use uuid::Uuid;

use crate::chat::Outbound;

/// Command-channel depth.
const QUEUE: usize = 256;

#[derive(Debug)]
pub enum PresenceCommand {
    Join {
        session_id: Uuid,
        username: String,
        class: u8,
        address: String,
        tx: mpsc::Sender<Outbound>,
    },
    Leave {
        session_id: Uuid,
    },
    /// Reset a user's idle clock (call on observed activity: chat, ping).
    Touch {
        session_id: Uuid,
    },
    /// Full roster, sorted by username.
    List {
        reply: oneshot::Sender<Vec<WireEntry>>,
    },
    /// One user's entry, if online (case-sensitive exact username match).
    Get {
        username: String,
        reply: oneshot::Sender<Option<WireEntry>>,
    },
    /// Push an outbound frame to every connection of `username`. Replies with
    /// the number of sessions it reached (0 = the user is offline).
    Deliver {
        username: String,
        outbound: Outbound,
        reply: oneshot::Sender<usize>,
    },
    /// Forcibly disconnect every connection of `username`: push a `Disconnect`
    /// frame carrying `reason`, which the target's dispatch loop sends and then
    /// closes on. Replies with the number of sessions signalled.
    Disconnect {
        username: String,
        reason: String,
        reply: oneshot::Sender<usize>,
    },
}

struct Entry {
    username: String,
    class: u8,
    login_at: u64,
    last_active: Instant,
    address: String,
    tx: mpsc::Sender<Outbound>,
}

impl Entry {
    fn to_wire(&self, now: Instant) -> WireEntry {
        WireEntry {
            username: self.username.clone(),
            class: self.class,
            login_at: self.login_at,
            idle_secs: now.duration_since(self.last_active).as_secs() as u32,
            address: self.address.clone(),
        }
    }
}

/// Handle to the running presence actor.
#[derive(Clone)]
pub struct Presence {
    tx: mpsc::Sender<PresenceCommand>,
}

impl Default for Presence {
    fn default() -> Self {
        Self::spawn()
    }
}

impl Presence {
    pub fn spawn() -> Self {
        let (tx, mut rx) = mpsc::channel::<PresenceCommand>(QUEUE);
        tokio::spawn(async move {
            let mut entries: HashMap<Uuid, Entry> = HashMap::new();
            while let Some(command) = rx.recv().await {
                handle(&mut entries, command).await;
            }
        });
        Self { tx }
    }

    pub async fn join(
        &self,
        session_id: Uuid,
        username: String,
        class: u8,
        address: String,
        tx: mpsc::Sender<Outbound>,
    ) {
        let _ = self
            .tx
            .send(PresenceCommand::Join {
                session_id,
                username,
                class,
                address,
                tx,
            })
            .await;
    }

    pub async fn leave(&self, session_id: Uuid) {
        let _ = self.tx.send(PresenceCommand::Leave { session_id }).await;
    }

    pub async fn touch(&self, session_id: Uuid) {
        let _ = self.tx.send(PresenceCommand::Touch { session_id }).await;
    }

    pub async fn list(&self) -> Vec<WireEntry> {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(PresenceCommand::List { reply }).await.is_err() {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    pub async fn get(&self, username: &str) -> Option<WireEntry> {
        let (reply, rx) = oneshot::channel();
        if self
            .tx
            .send(PresenceCommand::Get {
                username: username.to_owned(),
                reply,
            })
            .await
            .is_err()
        {
            return None;
        }
        rx.await.ok().flatten()
    }

    /// Push `outbound` to every connection of `username`. Returns the number
    /// of sessions reached (0 = offline).
    pub async fn deliver(&self, username: &str, outbound: Outbound) -> usize {
        let (reply, rx) = oneshot::channel();
        if self
            .tx
            .send(PresenceCommand::Deliver {
                username: username.to_owned(),
                outbound,
                reply,
            })
            .await
            .is_err()
        {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Forcibly disconnect every connection of `username`, delivering `reason`.
    /// Returns the number of sessions signalled (0 = offline). The target's
    /// dispatch loop closes after sending the `Disconnect` frame, which runs
    /// the usual room-leave / presence-leave / session-end cleanup.
    pub async fn disconnect(&self, username: &str, reason: &str) -> usize {
        let (reply, rx) = oneshot::channel();
        if self
            .tx
            .send(PresenceCommand::Disconnect {
                username: username.to_owned(),
                reason: reason.to_owned(),
                reply,
            })
            .await
            .is_err()
        {
            return 0;
        }
        rx.await.unwrap_or(0)
    }
}

async fn handle(entries: &mut HashMap<Uuid, Entry>, command: PresenceCommand) {
    match command {
        PresenceCommand::Join {
            session_id,
            username,
            class,
            address,
            tx,
        } => {
            let now = Instant::now();
            let entry = Entry {
                username,
                class,
                login_at: unix_now(),
                last_active: now,
                address,
                tx,
            };
            entries.insert(session_id, entry);
            let wire = entries[&session_id].to_wire(now);
            // Broadcast to everyone *except* the joining connection — it
            // doesn't need to be told about its own presence (its login
            // response already established that), and this avoids a race
            // where the self-notification arrives interleaved with whatever
            // the client immediately requests next.
            broadcast_except(
                entries,
                session_id,
                PresenceChange {
                    entry: wire,
                    online: true,
                },
            )
            .await;
        }
        PresenceCommand::Leave { session_id } => {
            if let Some(entry) = entries.remove(&session_id) {
                let wire = entry.to_wire(Instant::now());
                broadcast(
                    entries,
                    PresenceChange {
                        entry: wire,
                        online: false,
                    },
                )
                .await;
            }
        }
        PresenceCommand::Touch { session_id } => {
            if let Some(entry) = entries.get_mut(&session_id) {
                entry.last_active = Instant::now();
            }
        }
        PresenceCommand::List { reply } => {
            let now = Instant::now();
            let mut list: Vec<WireEntry> = entries.values().map(|e| e.to_wire(now)).collect();
            list.sort_by(|a, b| a.username.cmp(&b.username));
            let _ = reply.send(list);
        }
        PresenceCommand::Get { username, reply } => {
            let now = Instant::now();
            let found = entries
                .values()
                .find(|e| e.username == username)
                .map(|e| e.to_wire(now));
            let _ = reply.send(found);
        }
        PresenceCommand::Deliver {
            username,
            outbound,
            reply,
        } => {
            let mut reached = 0;
            for entry in entries.values().filter(|e| e.username == username) {
                if entry.tx.try_send(outbound.clone()).is_ok() {
                    reached += 1;
                }
            }
            let _ = reply.send(reached);
        }
        PresenceCommand::Disconnect {
            username,
            reason,
            reply,
        } => {
            let payload = Bytes::copy_from_slice(reason.as_bytes());
            let mut reached = 0;
            for entry in entries.values().filter(|e| e.username == username) {
                let signal = Outbound {
                    packet_type: PacketType::Disconnect,
                    flags: PacketFlags::empty(),
                    payload: payload.clone(),
                };
                if entry.tx.try_send(signal).is_ok() {
                    reached += 1;
                }
            }
            let _ = reply.send(reached);
        }
    }
}

async fn broadcast(entries: &HashMap<Uuid, Entry>, change: PresenceChange) {
    broadcast_filtered(entries, None, change).await;
}

async fn broadcast_except(entries: &HashMap<Uuid, Entry>, exclude: Uuid, change: PresenceChange) {
    broadcast_filtered(entries, Some(exclude), change).await;
}

async fn broadcast_filtered(
    entries: &HashMap<Uuid, Entry>,
    exclude: Option<Uuid>,
    change: PresenceChange,
) {
    let payload = change.encode();
    for (session_id, entry) in entries {
        if Some(*session_id) == exclude {
            continue;
        }
        let _ = entry.tx.try_send(Outbound {
            packet_type: PacketType::PresenceChange,
            flags: PacketFlags::empty(),
            payload: payload.clone(),
        });
    }
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::channel;

    fn member_channel() -> (mpsc::Sender<Outbound>, mpsc::Receiver<Outbound>) {
        channel(16)
    }

    #[tokio::test]
    async fn join_then_list() {
        let presence = Presence::spawn();
        let (tx_a, _rx_a) = member_channel();
        presence
            .join(Uuid::new_v4(), "alice".into(), 1, "1.2.3.4:1".into(), tx_a)
            .await;
        let (tx_b, _rx_b) = member_channel();
        presence
            .join(Uuid::new_v4(), "bob".into(), 2, "1.2.3.4:2".into(), tx_b)
            .await;

        let roster = presence.list().await;
        assert_eq!(roster.len(), 2);
        assert_eq!(roster[0].username, "alice"); // sorted
        assert_eq!(roster[1].username, "bob");
    }

    #[tokio::test]
    async fn leave_removes_from_roster() {
        let presence = Presence::spawn();
        let id = Uuid::new_v4();
        let (tx, _rx) = member_channel();
        presence.join(id, "alice".into(), 1, "addr".into(), tx).await;
        assert_eq!(presence.list().await.len(), 1);
        presence.leave(id).await;
        assert!(presence.list().await.is_empty());
    }

    #[tokio::test]
    async fn join_and_leave_broadcast_to_others_not_self() {
        let presence = Presence::spawn();
        let id_a = Uuid::new_v4();
        let (tx_a, mut rx_a) = member_channel();
        presence.join(id_a, "alice".into(), 1, "addr".into(), tx_a).await;

        let id_b = Uuid::new_v4();
        let (tx_b, mut rx_b) = member_channel();
        presence.join(id_b, "bob".into(), 2, "addr2".into(), tx_b).await;

        // Alice sees bob's join (but never her own).
        let first = rx_a.recv().await.unwrap();
        let change = PresenceChange::decode(&first.payload).unwrap();
        assert!(change.online);
        assert_eq!(change.entry.username, "bob");

        presence.leave(id_b).await;
        let second = rx_a.recv().await.unwrap();
        let change = PresenceChange::decode(&second.payload).unwrap();
        assert!(!change.online);
        assert_eq!(change.entry.username, "bob");

        // Bob never received a self-notification for his own join: once the
        // actor shuts down (dropping the handle closes its command channel,
        // and with it every stored member sender), his channel is empty and
        // closes with nothing ever having been sent.
        drop(presence);
        assert!(rx_b.recv().await.is_none());
    }

    #[tokio::test]
    async fn get_finds_one_user_case_sensitive() {
        let presence = Presence::spawn();
        let (tx, _rx) = member_channel();
        presence.join(Uuid::new_v4(), "phraq".into(), 2, "a".into(), tx).await;

        assert!(presence.get("phraq").await.is_some());
        assert!(presence.get("Phraq").await.is_none());
        assert!(presence.get("nobody").await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn touch_resets_idle() {
        let presence = Presence::spawn();
        let id = Uuid::new_v4();
        let (tx, _rx) = member_channel();
        presence.join(id, "alice".into(), 1, "addr".into(), tx).await;
        // Round-trip through the actor once so we know Join was actually
        // processed (and last_active captured) before advancing the clock —
        // join()/touch() only guarantee the command was *enqueued*.
        presence.list().await;

        tokio::time::advance(std::time::Duration::from_secs(30)).await;
        let before = presence.get("alice").await.unwrap();
        assert!(before.idle_secs >= 30);

        presence.touch(id).await;
        let after = presence.get("alice").await.unwrap();
        assert!(after.idle_secs < before.idle_secs);
    }
}
