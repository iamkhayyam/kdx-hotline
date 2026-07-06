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

use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;
use kdx_storage::ip_rules as storage;
use kdx_storage::SqlitePool;
use tokio::sync::RwLock;

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
}

impl IpRuleManager {
    /// Load current rules from storage into the match cache. Call once at
    /// startup right after `IpRuleManager::new`.
    pub async fn load(pool: SqlitePool) -> Result<Self, IpRuleError> {
        let mgr = Self {
            pool,
            cache: RwLock::new(Arc::new(Vec::new())),
        };
        mgr.reload().await?;
        Ok(mgr)
    }

    /// Full rebuild of the compiled cache from storage. Cheap enough to
    /// call after every create/delete since the rule set is small.
    pub async fn reload(&self) -> Result<(), IpRuleError> {
        let rows = storage::list(&self.pool).await?;
        let mut compiled = Vec::with_capacity(rows.len());
        for row in rows {
            let net: IpNet = row
                .cidr
                .parse()
                .map_err(|_| IpRuleError::InvalidCidr(row.cidr.clone()))?;
            let action = Action::parse(&row.action)?;
            compiled.push(Compiled {
                net,
                action,
                note: row.note,
            });
        }
        *self.cache.write().await = Arc::new(compiled);
        Ok(())
    }

    /// Verdict for a peer IP against the current rule set. First match wins;
    /// no match ⇒ `Allow`.
    pub async fn match_ip(&self, ip: IpAddr) -> Verdict {
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
        let _parsed: IpNet = cidr
            .parse()
            .map_err(|_| IpRuleError::InvalidCidr(cidr.into()))?;
        let id = storage::create(
            &self.pool,
            position as i64,
            action.as_str(),
            cidr,
            note,
            created_by,
            created_at as i64,
        )
        .await?;
        self.reload().await?;
        Ok(id)
    }

    pub async fn delete(&self, id: &str) -> Result<(), IpRuleError> {
        storage::delete(&self.pool, id).await?;
        self.reload().await?;
        Ok(())
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
