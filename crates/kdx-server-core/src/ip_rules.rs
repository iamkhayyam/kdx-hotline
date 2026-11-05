//! Allow-Deny IP rules. Domain wrapper over `kdx_storage::ip_rules` that
//! parses each row's `cidr` into an `IpNet` once and answers "does an IP
//! match?" without touching the DB on every accept.
//!
//! Match semantics:
//! - Rules are checked in `position ASC` order (lowest wins), so an
//!   allow-exception ahead of a broader deny works as expected.
//! - The first matching rule decides; a matching `allow` returns `Allow`,
//!   a matching `deny` returns `Deny(note)`.
//! - If no rule matches, the default is `Allow` (fail-open) — this is a
//!   targeted ban/exception tool, not a firewall.
//! - Addresses are compared in canonical form: an IPv4-mapped IPv6 peer
//!   (`::ffff:a.b.c.d`, how IPv4 clients appear on a dual-stack `[::]`
//!   listener) matches IPv4 rules, and an IPv4-mapped rule matches plain
//!   IPv4 peers.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use ipnet::{IpNet, Ipv4Net};
use kdx_storage::ip_rules as storage;
use kdx_storage::SqlitePool;
use tokio::sync::{Mutex, RwLock};

use crate::presence::Presence;

/// An IPv4-mapped IPv6 network (`::ffff:0:0/96` and narrower) as the
/// equivalent IPv4 network; anything else unchanged. Also drops host bits.
fn canonical_net(net: IpNet) -> IpNet {
    if let IpNet::V6(v6) = net {
        if v6.prefix_len() >= 96 {
            if let Some(v4) = v6.network().to_ipv4_mapped() {
                if let Ok(v4net) = Ipv4Net::new(v4, v6.prefix_len() - 96) {
                    return IpNet::V4(v4net.trunc());
                }
            }
        }
    }
    net.trunc()
}

/// Parse a presence / peer address (`"1.2.3.4:5678"`, `"[::1]:5678"`, or a
/// bare IP) into its canonical IP. `None` for anything else (e.g. the
/// `"unknown"` address of an in-memory test stream).
pub fn parse_peer_ip(address: &str) -> Option<IpAddr> {
    let ip = match address.parse::<SocketAddr>() {
        Ok(sock) => sock.ip(),
        Err(_) => address.parse::<IpAddr>().ok()?,
    };
    Some(ip.to_canonical())
}

#[derive(Debug, thiserror::Error)]
pub enum IpRuleError {
    #[error("invalid CIDR: {0}")]
    InvalidCidr(String),
    #[error("invalid action (must be 'allow' or 'deny'): {0}")]
    InvalidAction(String),
    #[error("storage error: {0}")]
    Storage(#[from] kdx_storage::StorageError),
}

/// One rule, presented to callers (server-history logs, admin UI).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpRule {
    pub id: String,
    pub position: i32,
    pub action: Action,
    pub cidr: String,
    pub note: String,
    pub created_by: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
}

impl Action {
    fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
        }
    }
    fn parse(s: &str) -> Result<Self, IpRuleError> {
        match s {
            "allow" => Ok(Action::Allow),
            "deny" => Ok(Action::Deny),
            other => Err(IpRuleError::InvalidAction(other.into())),
        }
    }
}

/// Result of matching a peer IP against the rule set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No rule matched (fall-through default is allow), OR the first
    /// matching rule was `allow`.
    Allow,
    /// The first matching rule was `deny`. Carries its `note` so callers
    /// can include it in the audit log / disconnect reason.
    Deny { note: String },
}

/// A single compiled rule; `net` is the parsed CIDR so match_ip() is O(rules)
/// without any allocation.
#[derive(Debug, Clone)]
struct Compiled {
    net: IpNet,
    action: Action,
    note: String,
}

pub struct IpRuleManager {
    pool: SqlitePool,
    /// Compiled rules in priority order. `Arc<Vec<_>>` so `match_ip()` and
    /// admin `list()` can hold a snapshot without keeping the write lock.
    cache: RwLock<Arc<Vec<Compiled>>>,
    /// Serializes (storage mutation + reload) so two admins' concurrent
    /// changes can't leave the cache holding an older rule set than the
    /// database (STORE-10).
    mutations: Mutex<()>,
}

impl IpRuleManager {
    /// Load current rules from storage into the match cache. Call once at
    /// startup right after `IpRuleManager::new`.
    pub async fn load(pool: SqlitePool) -> Result<Self, IpRuleError> {
        let mgr = Self {
            pool,
            cache: RwLock::new(Arc::new(Vec::new())),
            mutations: Mutex::new(()),
        };
        mgr.reload().await?;
        Ok(mgr)
    }

    /// Full rebuild of the compiled cache from storage. Cheap enough to
    /// call after every create/delete since the rule set is small.
    pub async fn reload(&self) -> Result<(), IpRuleError> {
        let _guard = self.mutations.lock().await;
        self.reload_locked().await
    }

    /// `reload` for callers already holding `mutations`.
    async fn reload_locked(&self) -> Result<(), IpRuleError> {
        let rows = storage::list(&self.pool).await?;
        let mut compiled = Vec::with_capacity(rows.len());
        for row in rows {
            let net: IpNet = row
                .cidr
                .parse()
                .map_err(|_| IpRuleError::InvalidCidr(row.cidr.clone()))?;
            let action = Action::parse(&row.action)?;
            compiled.push(Compiled {
                net: canonical_net(net),
                action,
                note: row.note,
            });
        }
        *self.cache.write().await = Arc::new(compiled);
        Ok(())
    }

    /// Verdict for a peer IP against the current rule set. First match wins;
    /// no match ⇒ `Allow`. The address is canonicalized first, so an
    /// IPv4-mapped IPv6 peer is judged by the IPv4 rules.
    pub async fn match_ip(&self, ip: IpAddr) -> Verdict {
        let ip = ip.to_canonical();
        let snap = self.cache.read().await.clone();
        for rule in snap.iter() {
            if rule.net.contains(&ip) {
                return match rule.action {
                    Action::Allow => Verdict::Allow,
                    Action::Deny => Verdict::Deny {
                        note: rule.note.clone(),
                    },
                };
            }
        }
        Verdict::Allow
    }

    /// The rules an admin sees in the IP Rules window, priority order.
    pub async fn list(&self) -> Result<Vec<IpRule>, IpRuleError> {
        let rows = storage::list(&self.pool).await?;
        rows.into_iter()
            .map(|r| {
                Ok(IpRule {
                    id: r.id,
                    position: r.position as i32,
                    action: Action::parse(&r.action)?,
                    cidr: r.cidr,
                    note: r.note,
                    created_by: r.created_by,
                    created_at: r.created_at as u64,
                })
            })
            .collect()
    }

    /// Create a rule. Validates the CIDR up front so a bad value can't
    /// slip into storage and later fail every `reload()`.
    pub async fn create(
        &self,
        position: i32,
        action: Action,
        cidr: &str,
        note: &str,
        created_by: &str,
        created_at: u64,
    ) -> Result<String, IpRuleError> {
        let parsed: IpNet = cidr
            .parse()
            .map_err(|_| IpRuleError::InvalidCidr(cidr.into()))?;
        // Store the canonical network ("10.0.0.0/8", not "10.1.2.3/8").
        let cidr = canonical_net(parsed).to_string();
        let _guard = self.mutations.lock().await;
        let id = storage::create(
            &self.pool,
            position as i64,
            action.as_str(),
            &cidr,
            note,
            created_by,
            created_at as i64,
        )
        .await?;
        self.reload_locked().await?;
        Ok(id)
    }

    pub async fn delete(&self, id: &str) -> Result<(), IpRuleError> {
        let _guard = self.mutations.lock().await;
        storage::delete(&self.pool, id).await?;
        self.reload_locked().await?;
        Ok(())
    }

    /// Apply the current rules to sessions already connected (rules are
    /// otherwise only checked at accept): disconnect every user with a live
    /// session from an address the rules now deny. Returns the usernames
    /// disconnected.
    ///
    /// `exempt` (the admin who just changed the rules) keeps their session,
    /// so a rule that would lock them out can still be undone; it applies to
    /// them on their next connect. Presence can only disconnect by username,
    /// so a matching user's sessions from other addresses are dropped too.
    pub async fn disconnect_denied(&self, presence: &Presence, reason: &str, exempt: &str) -> Vec<String> {
        let mut denied = BTreeSet::new();
        for entry in presence.list().await {
            if entry.username == exempt {
                continue;
            }
            let Some(ip) = parse_peer_ip(&entry.address) else {
                continue;
            };
            if let Verdict::Deny { .. } = self.match_ip(ip).await {
                denied.insert(entry.username);
            }
        }
        for username in &denied {
            presence.disconnect(username, reason).await;
        }
        denied.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn mgr() -> (IpRuleManager, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = kdx_storage::connect(&dir.path().join("test.db")).await.unwrap();
        (IpRuleManager::load(pool).await.unwrap(), dir)
    }

    #[tokio::test]
    async fn empty_ruleset_allows_everything() {
        let (m, _d) = mgr().await;
        assert_eq!(m.match_ip("1.2.3.4".parse().unwrap()).await, Verdict::Allow);
        assert_eq!(m.match_ip("::1".parse().unwrap()).await, Verdict::Allow);
    }

    #[tokio::test]
    async fn deny_by_cidr_takes_effect_after_reload() {
        let (m, _d) = mgr().await;
        m.create(10, Action::Deny, "10.0.0.0/8", "internal", "sysop", 0)
            .await
            .unwrap();
        match m.match_ip("10.7.7.7".parse().unwrap()).await {
            Verdict::Deny { note } => assert_eq!(note, "internal"),
            v => panic!("expected Deny, got {v:?}"),
        }
        // Untouched by that rule.
        assert_eq!(m.match_ip("8.8.8.8".parse().unwrap()).await, Verdict::Allow);
    }

    #[tokio::test]
    async fn allow_exception_ahead_of_broader_deny() {
        let (m, _d) = mgr().await;
        // Deny the /24…
        m.create(20, Action::Deny, "1.2.3.0/24", "spammy", "sysop", 0)
            .await
            .unwrap();
        // …but explicitly allow one host inside it at a lower (higher-priority) position.
        m.create(10, Action::Allow, "1.2.3.4/32", "our office", "sysop", 0)
            .await
            .unwrap();

        assert_eq!(m.match_ip("1.2.3.4".parse().unwrap()).await, Verdict::Allow);
        match m.match_ip("1.2.3.5".parse().unwrap()).await {
            Verdict::Deny { .. } => {}
            v => panic!("expected Deny, got {v:?}"),
        }
    }

    #[tokio::test]
    async fn delete_lifts_the_rule() {
        let (m, _d) = mgr().await;
        let id = m
            .create(10, Action::Deny, "5.5.5.0/24", "", "sysop", 0)
            .await
            .unwrap();
        assert!(matches!(
            m.match_ip("5.5.5.7".parse().unwrap()).await,
            Verdict::Deny { .. }
        ));
        m.delete(&id).await.unwrap();
        assert_eq!(m.match_ip("5.5.5.7".parse().unwrap()).await, Verdict::Allow);
    }

    #[tokio::test]
    async fn create_refuses_bogus_cidr_before_touching_storage() {
        let (m, _d) = mgr().await;
        let err = m.create(0, Action::Deny, "not-a-cidr", "", "sysop", 0).await;
        assert!(matches!(err, Err(IpRuleError::InvalidCidr(_))));
        // Confirm nothing landed in storage.
        assert!(m.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn ipv4_mapped_peer_matches_ipv4_rule() {
        let (m, _d) = mgr().await;
        m.create(10, Action::Deny, "10.0.0.0/8", "internal", "sysop", 0)
            .await
            .unwrap();
        // How an IPv4 client looks on a dual-stack [::] listener.
        assert!(matches!(
            m.match_ip("::ffff:10.1.2.3".parse().unwrap()).await,
            Verdict::Deny { .. }
        ));
        assert_eq!(m.match_ip("::ffff:11.1.2.3".parse().unwrap()).await, Verdict::Allow);
    }

    #[tokio::test]
    async fn ipv4_mapped_rule_matches_ipv4_peer_and_is_stored_canonically() {
        let (m, _d) = mgr().await;
        m.create(10, Action::Deny, "::ffff:192.0.2.0/120", "", "sysop", 0)
            .await
            .unwrap();
        m.create(20, Action::Deny, "198.51.100.77/24", "", "sysop", 0)
            .await
            .unwrap();
        assert!(matches!(
            m.match_ip("192.0.2.9".parse().unwrap()).await,
            Verdict::Deny { .. }
        ));
        let cidrs: Vec<_> = m.list().await.unwrap().into_iter().map(|r| r.cidr).collect();
        assert_eq!(cidrs, ["192.0.2.0/24", "198.51.100.0/24"]);
    }

    #[test]
    fn peer_addresses_parse_canonically() {
        assert_eq!(parse_peer_ip("10.9.9.9:1"), Some("10.9.9.9".parse().unwrap()));
        assert_eq!(parse_peer_ip("[::ffff:10.9.9.9]:1"), Some("10.9.9.9".parse().unwrap()));
        assert_eq!(parse_peer_ip("[2001:db8::1]:443"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(parse_peer_ip("10.9.9.9"), Some("10.9.9.9".parse().unwrap()));
        assert_eq!(parse_peer_ip("unknown"), None);
    }

    #[tokio::test]
    async fn concurrent_mutations_leave_cache_in_step_with_storage() {
        let (m, _d) = mgr().await;
        let m = Arc::new(m);
        let mut ids = Vec::new();
        for i in 0..20u8 {
            let id = m
                .create(i as i32, Action::Deny, &format!("10.{i}.0.0/16"), "", "sysop", 0)
                .await
                .unwrap();
            ids.push(id);
        }
        // Interleave deletes of the first half with creates of new rules.
        let mut tasks = Vec::new();
        for (i, id) in ids.iter().take(10).enumerate() {
            let (m1, m2, id) = (m.clone(), m.clone(), id.clone());
            tasks.push(tokio::spawn(async move { m1.delete(&id).await.unwrap() }));
            tasks.push(tokio::spawn(async move {
                m2.create(100, Action::Deny, &format!("172.16.{i}.0/24"), "", "sysop", 0)
                    .await
                    .unwrap();
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        // The cache must agree with a fresh load for every rule's network.
        let fresh = IpRuleManager::load(m.pool.clone()).await.unwrap();
        for i in 0..20u8 {
            let ip: IpAddr = format!("10.{i}.1.1").parse().unwrap();
            assert_eq!(m.match_ip(ip).await, fresh.match_ip(ip).await, "10.{i}.1.1");
        }
        for i in 0..10u8 {
            let ip: IpAddr = format!("172.16.{i}.1").parse().unwrap();
            assert_eq!(m.match_ip(ip).await, fresh.match_ip(ip).await, "172.16.{i}.1");
        }
    }

    #[tokio::test]
    async fn disconnect_denied_kicks_only_matching_live_sessions() {
        let (m, _d) = mgr().await;
        let presence = Presence::spawn();
        let (bad_tx, mut bad_rx) = tokio::sync::mpsc::channel(8);
        let (good_tx, mut good_rx) = tokio::sync::mpsc::channel(8);
        let (admin_tx, mut admin_rx) = tokio::sync::mpsc::channel(8);
        let mut bad_kill = presence
            .join(uuid::Uuid::new_v4(), "abuser".into(), 1, "[::ffff:10.9.9.9]:4242".into(), false, bad_tx)
            .await;
        let mut good_kill = presence
            .join(uuid::Uuid::new_v4(), "bystander".into(), 1, "8.8.8.8:4242".into(), false, good_tx)
            .await;
        // The admin who made the rule, connected from inside the range.
        let mut admin_kill = presence
            .join(uuid::Uuid::new_v4(), "sysop".into(), 3, "10.0.0.1:4242".into(), false, admin_tx)
            .await;
        m.create(10, Action::Deny, "10.0.0.0/8", "", "sysop", 0)
            .await
            .unwrap();

        let kicked = m.disconnect_denied(&presence, "denied", "sysop").await;
        assert_eq!(kicked, ["abuser"]);
        // Kicks travel on each session's kill signal (not its event queue).
        let fired = tokio::time::timeout(std::time::Duration::from_secs(1), bad_kill.fired()).await;
        assert_eq!(fired.expect("abuser was not kicked").as_deref(), Some("denied"));
        for kill in [&mut good_kill, &mut admin_kill] {
            let fired = tokio::time::timeout(std::time::Duration::from_millis(50), kill.fired()).await;
            assert!(fired.is_err(), "a session outside the rule was kicked");
        }
        for rx in [&mut bad_rx, &mut good_rx, &mut admin_rx] {
            while let Ok(event) = rx.try_recv() {
                assert_ne!(event.packet_type, kdx_protocol::PacketType::Disconnect);
            }
        }
    }

    #[tokio::test]
    async fn ipv6_deny_works() {
        let (m, _d) = mgr().await;
        m.create(10, Action::Deny, "2001:db8::/32", "example", "sysop", 0)
            .await
            .unwrap();
        assert!(matches!(
            m.match_ip("2001:db8::1".parse().unwrap()).await,
            Verdict::Deny { .. }
        ));
        assert_eq!(
            m.match_ip("2001:db9::1".parse().unwrap()).await,
            Verdict::Allow
        );
    }
}
