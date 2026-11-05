//! Server-wide presence: who's online, for the global User List and User
//! Info windows. One actor task owns the roster (mirrors the tracker/chat
//! room actor pattern); connections join on authentication and leave on
//! disconnect, and every join/leave is broadcast live to all present
//! connections via their outbound channel.
//!
//! Each entry also carries a non-lossy kill signal: `disconnect` and
//! `disconnect_all` fire it instead of queueing a frame on the (bounded,
//! best-effort) outbound channel, so a kick reaches a session even when its
//! queue is full or it has stopped reading. Once `disconnect_all` ran (the
//! server is shutting down), a session that joins later — a login that was
//! in flight — has its kill signal fired as it joins.
//!
//! Peer addresses are only shown to sessions that may act on them (those
//! that joined with `sees_addresses`, i.e. USER_KICK holders): broadcasts
//! are encoded per recipient, and `list`/`get` return the full entry for
//! the caller to redact (see [`redact_address`]).

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use kdx_protocol::messages::PresenceChange;
use kdx_protocol::messages::PresenceEntry as WireEntry;
use kdx_protocol::{PacketFlags, PacketType};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot, watch};
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
        sees_addresses: bool,
        tx: mpsc::Sender<Outbound>,
        kill: watch::Sender<Option<String>>,
        /// Answered once the session is in the roster.
        joined: oneshot::Sender<()>,
    },
    Leave {
        session_id: Uuid,
    },
    /// Reset a user's idle clock (call on observed activity: chat, ping).
    Touch {
        session_id: Uuid,
    },
    /// Set a user's display name / description (`/name`, `/desc`) and
    /// rebroadcast their presence so every client sees the change live.
    SetIdentity {
        session_id: Uuid,
        name: String,
        description: String,
    },
    /// Full roster, sorted by username (addresses included).
    List {
        reply: oneshot::Sender<Vec<WireEntry>>,
    },
    /// One user's entry, if online (case-sensitive exact username match;
    /// address included).
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
    /// Forcibly disconnect every connection of `username` by firing its kill
    /// signal with `reason`; the target's dispatch loop sends a `Disconnect`
    /// frame carrying it and closes. Replies with the number of sessions
    /// signalled.
    Disconnect {
        username: String,
        reason: String,
        reply: oneshot::Sender<usize>,
    },
    /// [`PresenceCommand::Disconnect`] for every connection of `username`
    /// except session `except` (the caller's own, after a password change).
    DisconnectOthers {
        username: String,
        except: Uuid,
        reason: String,
        reply: oneshot::Sender<usize>,
    },
    /// Push an outbound frame to literally every connected session, regardless
    /// of username. Replies with the number of sessions it reached.
    BroadcastAll {
        outbound: Outbound,
        reply: oneshot::Sender<usize>,
    },
    /// Forcibly disconnect every connected session (including the caller's
    /// own, if it's among them) — the presence side of a server shutdown.
    /// Sessions joining afterwards are disconnected as they join. Replies
    /// with the number of sessions signalled.
    DisconnectAll {
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
    name: String,
    description: String,
    /// Whether this session may see other users' addresses in broadcasts.
    sees_addresses: bool,
    tx: mpsc::Sender<Outbound>,
    kill: watch::Sender<Option<String>>,
}

impl Entry {
    fn to_wire(&self, now: Instant) -> WireEntry {
        WireEntry {
            username: self.username.clone(),
            class: self.class,
            login_at: self.login_at,
            idle_secs: now.duration_since(self.last_active).as_secs() as u32,
            address: self.address.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

/// Blank the peer address of `entry` — what a viewer without USER_KICK sees.
pub fn redact_address(entry: &mut WireEntry) {
    entry.address.clear();
}

/// The receiving end of a session's kill signal (see [`Presence::join`]).
pub struct KillSignal {
    rx: watch::Receiver<Option<String>>,
}

impl KillSignal {
    /// Resolves once the session has been told to disconnect, yielding the
    /// reason. Also resolves — with `None` — if presence dropped the session
    /// (or shut down), since nothing could reach it any more. Cancel-safe.
    pub async fn fired(&mut self) -> Option<String> {
        loop {
            if let Some(reason) = self.rx.borrow_and_update().clone() {
                return Some(reason);
            }
            if self.rx.changed().await.is_err() {
                return self.rx.borrow().clone();
            }
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
            let mut roster = Roster::default();
            while let Some(command) = rx.recv().await {
                handle(&mut roster, command);
            }
        });
        Self { tx }
    }

    /// Add a session to the roster. `sees_addresses` controls whether the
    /// presence broadcasts it receives carry other users' addresses. Returns
    /// the session's kill signal, which `disconnect`/`disconnect_all` fire,
    /// once the session is in the roster: every kick processed from then on
    /// reaches it. (Fired already if the server is shutting down.)
    pub async fn join(
        &self,
        session_id: Uuid,
        username: String,
        class: u8,
        address: String,
        sees_addresses: bool,
        tx: mpsc::Sender<Outbound>,
    ) -> KillSignal {
        let (kill, rx) = watch::channel(None);
        let (joined, ack) = oneshot::channel();
        let sent = self
            .tx
            .send(PresenceCommand::Join {
                session_id,
                username,
                class,
                address,
                sees_addresses,
                tx,
                kill,
                joined,
            })
            .await;
        if sent.is_ok() {
            let _ = ack.await;
        }
        KillSignal { rx }
    }

    pub async fn leave(&self, session_id: Uuid) {
        let _ = self.tx.send(PresenceCommand::Leave { session_id }).await;
    }

    /// Reset the idle clock. Never waits: if the presence queue is full the
    /// touch is simply skipped (it only feeds the "idle" column).
    pub fn touch(&self, session_id: Uuid) {
        let _ = self.tx.try_send(PresenceCommand::Touch { session_id });
    }

    /// Set the display name / description of one session (`/name`, `/desc`).
    pub async fn set_identity(&self, session_id: Uuid, name: String, description: String) {
        let _ = self
            .tx
            .send(PresenceCommand::SetIdentity {
                session_id,
                name,
                description,
            })
            .await;
    }

    /// The full roster, addresses included — redact before showing it to a
    /// viewer without USER_KICK.
    pub async fn list(&self) -> Vec<WireEntry> {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(PresenceCommand::List { reply }).await.is_err() {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// One user's entry, address included — redact before showing it to a
    /// viewer without USER_KICK.
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
    /// Returns the number of sessions signalled (0 = offline). The signal
    /// can't be lost to a full queue: the target's dispatch loop polls it
    /// ahead of everything else, sends a `Disconnect` frame carrying
    /// `reason`, closes, and runs the usual room-leave / presence-leave /
    /// session-end cleanup.
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

    /// Like [`Presence::disconnect`], but spares session `except` — after a
    /// password change, every *other* session of the account is signed out.
    pub async fn disconnect_others(&self, username: &str, except: Uuid, reason: &str) -> usize {
        let (reply, rx) = oneshot::channel();
        if self
            .tx
            .send(PresenceCommand::DisconnectOthers {
                username: username.to_owned(),
                except,
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

    /// Push `outbound` to literally every connected session. Returns the
    /// number of sessions reached.
    pub async fn broadcast_all(&self, outbound: Outbound) -> usize {
        let (reply, rx) = oneshot::channel();
        if self
            .tx
            .send(PresenceCommand::BroadcastAll { outbound, reply })
            .await
            .is_err()
        {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Forcibly disconnect every connected session, delivering `reason`.
    /// Returns the number of sessions signalled.
    pub async fn disconnect_all(&self, reason: &str) -> usize {
        let (reply, rx) = oneshot::channel();
        if self
            .tx
            .send(PresenceCommand::DisconnectAll {
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

/// The presence actor's state.
#[derive(Default)]
struct Roster {
    entries: HashMap<Uuid, Entry>,
    /// Set by `DisconnectAll` (shutdown): the reason every later join is
    /// disconnected with.
    closing: Option<String>,
}

fn handle(roster: &mut Roster, command: PresenceCommand) {
    let Roster { entries, closing } = roster;
    match command {
        PresenceCommand::Join {
            session_id,
            username,
            class,
            address,
            sees_addresses,
            tx,
            kill,
            joined,
        } => {
            if let Some(reason) = closing.as_ref() {
                // A login that was in flight when the server began shutting
                // down: it closes as soon as its dispatch loop starts.
                kill.send_replace(Some(reason.clone()));
            }
            let now = Instant::now();
            let entry = Entry {
                username,
                class,
                login_at: unix_now(),
                last_active: now,
                address,
                name: String::new(),
                description: String::new(),
                sees_addresses,
                tx,
                kill,
            };
            let wire = entry.to_wire(now);
            entries.insert(session_id, entry);
            // Broadcast to everyone *except* the joining connection — it
            // doesn't need to be told about its own presence (its login
            // response already established that), and this avoids a race
            // where the self-notification arrives interleaved with whatever
            // the client immediately requests next.
            broadcast(
                entries,
                Some(session_id),
                PresenceChange {
                    entry: wire,
                    online: true,
                },
            );
            let _ = joined.send(());
        }
        PresenceCommand::Leave { session_id } => {
            remove(entries, vec![session_id]);
        }
        PresenceCommand::Touch { session_id } => {
            if let Some(entry) = entries.get_mut(&session_id) {
                entry.last_active = Instant::now();
            }
        }
        PresenceCommand::SetIdentity {
            session_id,
            name,
            description,
        } => {
            if let Some(entry) = entries.get_mut(&session_id) {
                entry.name = name;
                entry.description = description;
                // Re-broadcast so every client sees the new identity live.
                let wire = entry.to_wire(Instant::now());
                broadcast(
                    entries,
                    None,
                    PresenceChange {
                        entry: wire,
                        online: true,
                    },
                );
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
            let (reached, dead) = try_send_where(entries, &outbound, |e| e.username == username);
            remove(entries, dead);
            let _ = reply.send(reached);
        }
        PresenceCommand::Disconnect {
            username,
            reason,
            reply,
        } => {
            let (reached, dead) = kill_where(entries, &reason, |e| e.username == username);
            remove(entries, dead);
            let _ = reply.send(reached);
        }
        PresenceCommand::DisconnectOthers {
            username,
            except,
            reason,
            reply,
        } => {
            let (reached, dead) =
                kill_where_id(entries, &reason, |id, e| *id != except && e.username == username);
            remove(entries, dead);
            let _ = reply.send(reached);
        }
        PresenceCommand::BroadcastAll { outbound, reply } => {
            let (reached, dead) = try_send_where(entries, &outbound, |_| true);
            remove(entries, dead);
            let _ = reply.send(reached);
        }
        PresenceCommand::DisconnectAll { reason, reply } => {
            let (reached, dead) = kill_where(entries, &reason, |_| true);
            *closing = Some(reason);
            remove(entries, dead);
            let _ = reply.send(reached);
        }
    }
}

/// Try-send `outbound` to every entry matching `filter`. Returns how many
/// accepted it, and the entries whose connection is gone (channel closed).
fn try_send_where(
    entries: &HashMap<Uuid, Entry>,
    outbound: &Outbound,
    filter: impl Fn(&Entry) -> bool,
) -> (usize, Vec<Uuid>) {
    let mut reached = 0;
    let mut dead = Vec::new();
    for (session_id, entry) in entries.iter().filter(|(_, e)| filter(e)) {
        match entry.tx.try_send(outbound.clone()) {
            Ok(()) => reached += 1,
            Err(TrySendError::Full(_)) => {}
            Err(TrySendError::Closed(_)) => dead.push(*session_id),
        }
    }
    (reached, dead)
}

/// Fire the kill signal of every entry matching `filter`. Returns how many
/// live sessions were signalled, and the entries whose connection is gone.
fn kill_where(
    entries: &HashMap<Uuid, Entry>,
    reason: &str,
    filter: impl Fn(&Entry) -> bool,
) -> (usize, Vec<Uuid>) {
    let mut reached = 0;
    let mut dead = Vec::new();
    for (session_id, entry) in entries.iter().filter(|(_, e)| filter(e)) {
        // Fails only when the receiver (the connection's dispatch loop) is
        // gone.
        if entry.kill.send(Some(reason.to_owned())).is_ok() {
            reached += 1;
        } else {
            dead.push(*session_id);
        }
    }
    (reached, dead)
}

/// [`kill_where`] with a filter that also sees each session's id.
fn kill_where_id(
    entries: &HashMap<Uuid, Entry>,
    reason: &str,
    filter: impl Fn(&Uuid, &Entry) -> bool,
) -> (usize, Vec<Uuid>) {
    let mut reached = 0;
    let mut dead = Vec::new();
    for (session_id, entry) in entries.iter().filter(|(id, e)| filter(id, e)) {
        if entry.kill.send(Some(reason.to_owned())).is_ok() {
            reached += 1;
        } else {
            dead.push(*session_id);
        }
    }
    (reached, dead)
}

/// Remove `gone` entries and broadcast each one going offline. Entries found
/// dead while broadcasting are removed (and announced) in turn.
fn remove(entries: &mut HashMap<Uuid, Entry>, gone: Vec<Uuid>) {
    let now = Instant::now();
    for session_id in gone {
        if let Some(entry) = entries.remove(&session_id) {
            broadcast(
                entries,
                None,
                PresenceChange {
                    entry: entry.to_wire(now),
                    online: false,
                },
            );
        }
    }
}

/// Send `change` to every entry except `exclude`, encoded per recipient:
/// only sessions that may see addresses get the subject's address.
/// Recipients whose connection is gone are removed (and announced) too.
fn broadcast(entries: &mut HashMap<Uuid, Entry>, exclude: Option<Uuid>, change: PresenceChange) {
    let mut pending = vec![(exclude, change)];
    while let Some((exclude, mut change)) = pending.pop() {
        let full = change.encode();
        redact_address(&mut change.entry);
        let redacted = change.encode();
        let mut dead = Vec::new();
        for (session_id, entry) in entries.iter() {
            if Some(*session_id) == exclude {
                continue;
            }
            let payload = if entry.sees_addresses {
                full.clone()
            } else {
                redacted.clone()
            };
            let outbound = Outbound {
                packet_type: PacketType::PresenceChange,
                flags: PacketFlags::empty(),
                payload,
            };
            if let Err(TrySendError::Closed(_)) = entry.tx.try_send(outbound) {
                dead.push(*session_id);
            }
        }
        let now = Instant::now();
        for session_id in dead {
            if let Some(gone) = entries.remove(&session_id) {
                pending.push((
                    None,
                    PresenceChange {
                        entry: gone.to_wire(now),
                        online: false,
                    },
                ));
            }
        }
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures_util::FutureExt;
    use tokio::sync::mpsc::channel;

    fn member_channel() -> (mpsc::Sender<Outbound>, mpsc::Receiver<Outbound>) {
        channel(16)
    }

    /// Join with no address visibility; the kill signal is returned so the
    /// caller can keep the session "alive" (dropping it marks the session
    /// as gone for `disconnect`).
    async fn join(
        presence: &Presence,
        id: Uuid,
        username: &str,
        class: u8,
        address: &str,
        tx: mpsc::Sender<Outbound>,
    ) -> KillSignal {
        presence
            .join(id, username.into(), class, address.into(), false, tx)
            .await
    }

    #[tokio::test]
    async fn join_then_list() {
        let presence = Presence::spawn();
        let (tx_a, _rx_a) = member_channel();
        let _ka = join(&presence, Uuid::new_v4(), "alice", 1, "1.2.3.4:1", tx_a).await;
        let (tx_b, _rx_b) = member_channel();
        let _kb = join(&presence, Uuid::new_v4(), "bob", 2, "1.2.3.4:2", tx_b).await;

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
        let _k = join(&presence, id, "alice", 1, "addr", tx).await;
        assert_eq!(presence.list().await.len(), 1);
        presence.leave(id).await;
        assert!(presence.list().await.is_empty());
    }

    #[tokio::test]
    async fn join_and_leave_broadcast_to_others_not_self() {
        let presence = Presence::spawn();
        let id_a = Uuid::new_v4();
        let (tx_a, mut rx_a) = member_channel();
        let _ka = join(&presence, id_a, "alice", 1, "addr", tx_a).await;

        let id_b = Uuid::new_v4();
        let (tx_b, mut rx_b) = member_channel();
        let _kb = join(&presence, id_b, "bob", 2, "addr2", tx_b).await;

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
        let _k = join(&presence, Uuid::new_v4(), "phraq", 2, "a", tx).await;

        assert!(presence.get("phraq").await.is_some());
        assert!(presence.get("Phraq").await.is_none());
        assert!(presence.get("nobody").await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn touch_resets_idle() {
        let presence = Presence::spawn();
        let id = Uuid::new_v4();
        let (tx, _rx) = member_channel();
        let _k = join(&presence, id, "alice", 1, "addr", tx).await;
        // Round-trip through the actor once so we know Join was actually
        // processed (and last_active captured) before advancing the clock —
        // join()/touch() only guarantee the command was *enqueued*.
        presence.list().await;

        tokio::time::advance(std::time::Duration::from_secs(30)).await;
        let before = presence.get("alice").await.unwrap();
        assert!(before.idle_secs >= 30);

        presence.touch(id);
        let after = presence.get("alice").await.unwrap();
        assert!(after.idle_secs < before.idle_secs);
    }

    #[tokio::test]
    async fn broadcast_all_reaches_every_session() {
        let presence = Presence::spawn();
        let (tx_a, mut rx_a) = member_channel();
        let _ka = join(&presence, Uuid::new_v4(), "alice", 1, "a", tx_a).await;
        let (tx_b, mut rx_b) = member_channel();
        let _kb = join(&presence, Uuid::new_v4(), "bob", 1, "b", tx_b).await;
        // Drain each one's join-broadcast-of-the-other before asserting.
        rx_a.recv().await.unwrap();

        let outbound = Outbound {
            packet_type: PacketType::Info,
            flags: PacketFlags::empty(),
            payload: Bytes::from_static(b"server message"),
        };
        let reached = presence.broadcast_all(outbound).await;
        assert_eq!(reached, 2);
        assert_eq!(rx_a.recv().await.unwrap().payload, Bytes::from_static(b"server message"));
        assert_eq!(rx_b.recv().await.unwrap().payload, Bytes::from_static(b"server message"));
    }

    #[tokio::test]
    async fn disconnect_all_signals_every_session_including_caller() {
        let presence = Presence::spawn();
        let (tx_a, _rx_a) = member_channel();
        let mut ka = join(&presence, Uuid::new_v4(), "alice", 1, "a", tx_a).await;
        let (tx_b, _rx_b) = member_channel();
        let mut kb = join(&presence, Uuid::new_v4(), "bob", 1, "b", tx_b).await;

        let reached = presence.disconnect_all("server is shutting down").await;
        assert_eq!(reached, 2);
        assert_eq!(ka.fired().await.as_deref(), Some("server is shutting down"));
        assert_eq!(kb.fired().await.as_deref(), Some("server is shutting down"));
    }

    #[tokio::test]
    async fn sessions_joining_after_disconnect_all_are_disconnected_at_once() {
        let presence = Presence::spawn();
        assert_eq!(presence.disconnect_all("server is shutting down").await, 0);
        // A login that was in flight during the shutdown joins afterwards.
        let (tx, _rx) = member_channel();
        let mut late = join(&presence, Uuid::new_v4(), "late", 1, "a", tx).await;
        let fired = tokio::time::timeout(std::time::Duration::from_secs(5), late.fired())
            .await
            .expect("the late joiner must be told to go");
        assert_eq!(fired.as_deref(), Some("server is shutting down"));
    }

    #[tokio::test]
    async fn disconnect_others_spares_the_given_session() {
        let presence = Presence::spawn();
        let me = Uuid::new_v4();
        let (tx_a, _rx_a) = member_channel();
        let mut mine = join(&presence, me, "phraq", 1, "a", tx_a).await;
        let (tx_b, _rx_b) = member_channel();
        let mut other = join(&presence, Uuid::new_v4(), "phraq", 1, "b", tx_b).await;
        let (tx_c, _rx_c) = member_channel();
        let mut stranger = join(&presence, Uuid::new_v4(), "bob", 1, "c", tx_c).await;

        let reached = presence
            .disconnect_others("phraq", me, "your password was changed")
            .await;
        assert_eq!(reached, 1);
        assert_eq!(other.fired().await.as_deref(), Some("your password was changed"));
        // The kill is sent before the reply, so an unfired signal stays so.
        assert!(mine.fired().now_or_never().is_none());
        assert!(stranger.fired().now_or_never().is_none());
    }

    #[tokio::test]
    async fn disconnect_reaches_a_session_whose_queue_is_full() {
        let presence = Presence::spawn();
        let (tx, _rx) = channel(1);
        let mut kill = join(&presence, Uuid::new_v4(), "stuck", 1, "a", tx).await;
        // Fill the outbound queue: further try_sends fail with Full.
        for _ in 0..4 {
            presence
                .broadcast_all(Outbound {
                    packet_type: PacketType::Info,
                    flags: PacketFlags::empty(),
                    payload: Bytes::from_static(b"spam"),
                })
                .await;
        }
        assert_eq!(presence.disconnect("stuck", "bye").await, 1);
        assert_eq!(kill.fired().await.as_deref(), Some("bye"));
        // The entry stays until the connection's own cleanup leaves.
        assert!(presence.get("stuck").await.is_some());
    }

    #[tokio::test]
    async fn dead_sessions_are_dropped_not_counted() {
        let presence = Presence::spawn();
        let (tx_a, mut rx_a) = member_channel();
        let _ka = join(&presence, Uuid::new_v4(), "alice", 1, "a", tx_a).await;

        // Bob's connection vanished without leaving: its outbound receiver
        // and kill signal are gone.
        let (tx_b, rx_b) = member_channel();
        let kb = join(&presence, Uuid::new_v4(), "bob", 1, "b", tx_b).await;
        rx_a.recv().await.unwrap(); // bob's join
        drop(rx_b);
        drop(kb);

        assert_eq!(presence.disconnect("bob", "bye").await, 0, "nobody left to signal");
        assert!(presence.get("bob").await.is_none(), "ghost dropped");
        let change = PresenceChange::decode(&rx_a.recv().await.unwrap().payload).unwrap();
        assert!(!change.online);
        assert_eq!(change.entry.username, "bob");

        // Same for a delivery to a closed channel.
        let (tx_c, rx_c) = member_channel();
        let _kc = join(&presence, Uuid::new_v4(), "carol", 1, "c", tx_c).await;
        rx_a.recv().await.unwrap(); // carol's join
        drop(rx_c);
        let outbound = Outbound {
            packet_type: PacketType::Info,
            flags: PacketFlags::empty(),
            payload: Bytes::from_static(b"hi"),
        };
        assert_eq!(presence.deliver("carol", outbound).await, 0);
        assert!(presence.get("carol").await.is_none());
    }

    #[tokio::test]
    async fn broadcast_addresses_only_reach_privileged_viewers() {
        let presence = Presence::spawn();
        let (tx_admin, mut rx_admin) = member_channel();
        let _k1 = presence
            .join(Uuid::new_v4(), "admin".into(), 3, "10.0.0.1:1".into(), true, tx_admin)
            .await;
        let (tx_user, mut rx_user) = member_channel();
        let _k2 = join(&presence, Uuid::new_v4(), "user", 1, "10.0.0.2:2", tx_user).await;
        // The admin saw the user's join with the address.
        let change = PresenceChange::decode(&rx_admin.recv().await.unwrap().payload).unwrap();
        assert_eq!(change.entry.address, "10.0.0.2:2");

        let (tx_late, _rx_late) = member_channel();
        let _k3 = join(&presence, Uuid::new_v4(), "late", 1, "10.0.0.3:3", tx_late).await;
        let to_admin = PresenceChange::decode(&rx_admin.recv().await.unwrap().payload).unwrap();
        let to_user = PresenceChange::decode(&rx_user.recv().await.unwrap().payload).unwrap();
        assert_eq!(to_admin.entry.address, "10.0.0.3:3");
        assert_eq!(to_user.entry.username, "late");
        assert!(to_user.entry.address.is_empty(), "address leaked to a plain user");
    }
}
