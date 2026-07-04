//! Tracker: a directory of live KDX servers. One actor task owns the entry
//! map; heartbeats refresh entries and a sweep evicts the silent. Low
//! volume by design — simplicity over throughput.

use std::collections::HashMap;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tracing::debug;

/// Entries older than this are evicted (3 missed 30-second heartbeats).
pub const DEFAULT_TTL: Duration = Duration::from_secs(90);
/// How often the sweep runs.
const SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// A registered server as reported by its heartbeat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEntry {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub users: u32,
    pub max_users: u32,
    pub description: String,
}

#[derive(Debug)]
pub enum TrackerCommand {
    /// Register or refresh (heartbeat) a server.
    Heartbeat(ServerEntry),
    /// List servers, optionally filtered by a case-insensitive name
    /// substring.
    Query {
        filter: Option<String>,
        reply: oneshot::Sender<Vec<ServerEntry>>,
    },
    /// Explicit deregistration.
    Remove { host: String, port: u16 },
}

/// Handle to a running tracker actor.
#[derive(Clone)]
pub struct Tracker {
    tx: mpsc::Sender<TrackerCommand>,
}

impl Tracker {
    /// Spawn the tracker actor with the given entry TTL.
    pub fn spawn(ttl: Duration) -> Self {
        let (tx, mut rx) = mpsc::channel::<TrackerCommand>(64);
        tokio::spawn(async move {
            let mut entries: HashMap<(String, u16), (ServerEntry, Instant)> = HashMap::new();
            let mut sweep = tokio::time::interval(SWEEP_INTERVAL);
            sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    command = rx.recv() => {
                        let Some(command) = command else { break };
                        match command {
                            TrackerCommand::Heartbeat(entry) => {
                                debug!(name = %entry.name, host = %entry.host, port = entry.port, "heartbeat");
                                entries.insert(
                                    (entry.host.clone(), entry.port),
                                    (entry, Instant::now()),
                                );
                            }
                            TrackerCommand::Query { filter, reply } => {
                                let needle = filter.map(|f| f.to_lowercase());
                                let mut result: Vec<ServerEntry> = entries
                                    .values()
                                    .filter(|(entry, _)| match &needle {
                                        Some(n) => entry.name.to_lowercase().contains(n),
                                        None => true,
                                    })
                                    .map(|(entry, _)| entry.clone())
                                    .collect();
                                result.sort_by(|a, b| a.name.cmp(&b.name));
                                let _ = reply.send(result);
                            }
                            TrackerCommand::Remove { host, port } => {
                                entries.remove(&(host, port));
                            }
                        }
                    }
                    _ = sweep.tick() => {
                        let now = Instant::now();
                        entries.retain(|_, (entry, seen)| {
                            let alive = now.duration_since(*seen) < ttl;
                            if !alive {
                                debug!(name = %entry.name, "tracker entry expired");
                            }
                            alive
                        });
                    }
                }
            }
        });
        Self { tx }
    }

    pub async fn heartbeat(&self, entry: ServerEntry) {
        let _ = self.tx.send(TrackerCommand::Heartbeat(entry)).await;
    }

    pub async fn query(&self, filter: Option<&str>) -> Vec<ServerEntry> {
        let (reply, rx) = oneshot::channel();
        if self
            .tx
            .send(TrackerCommand::Query {
                filter: filter.map(str::to_owned),
                reply,
            })
            .await
            .is_err()
        {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    pub async fn remove(&self, host: &str, port: u16) {
        let _ = self
            .tx
            .send(TrackerCommand::Remove {
                host: host.to_owned(),
                port,
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, port: u16) -> ServerEntry {
        ServerEntry {
            name: name.into(),
            host: "kdx.example.net".into(),
            port,
            users: 7,
            max_users: 100,
            description: "test server".into(),
        }
    }

    #[tokio::test]
    async fn heartbeat_then_query() {
        let tracker = Tracker::spawn(DEFAULT_TTL);
        tracker.heartbeat(entry("The Underground", 10700)).await;
        tracker.heartbeat(entry("Warez Palace", 10701)).await;

        let all = tracker.query(None).await;
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].name, "The Underground"); // sorted

        let filtered = tracker.query(Some("under")).await;
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "The Underground");

        let none = tracker.query(Some("corporate")).await;
        assert!(none.is_empty());
    }

    #[tokio::test]
    async fn heartbeat_refreshes_not_duplicates() {
        let tracker = Tracker::spawn(DEFAULT_TTL);
        let mut e = entry("Refresher", 10700);
        tracker.heartbeat(e.clone()).await;
        e.users = 12;
        tracker.heartbeat(e).await;
        let all = tracker.query(None).await;
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].users, 12);
    }

    #[tokio::test]
    async fn remove_deregisters() {
        let tracker = Tracker::spawn(DEFAULT_TTL);
        tracker.heartbeat(entry("Ephemeral", 10700)).await;
        tracker.remove("kdx.example.net", 10700).await;
        assert!(tracker.query(None).await.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn silent_server_ages_out() {
        let tracker = Tracker::spawn(Duration::from_secs(90));
        tracker.heartbeat(entry("Ghost", 10700)).await;
        assert_eq!(tracker.query(None).await.len(), 1);

        // Advance past the TTL; the sweep interval fires along the way.
        tokio::time::advance(Duration::from_secs(120)).await;
        assert!(tracker.query(None).await.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeats_keep_entry_alive_past_ttl() {
        let tracker = Tracker::spawn(Duration::from_secs(90));
        for _ in 0..6 {
            tracker.heartbeat(entry("Persistent", 10700)).await;
            tokio::time::advance(Duration::from_secs(30)).await;
        }
        // 180s elapsed, but heartbeats every 30s kept it alive.
        assert_eq!(tracker.query(None).await.len(), 1);
    }
}
