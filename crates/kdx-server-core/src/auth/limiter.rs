//! Server-wide brute-force throttle for logins.
//!
//! Failures are counted per peer IP and per (peer IP, username). Each key
//! gets a few free failures; after that every further failure blocks that
//! key for an exponentially growing backoff (1 s, 2 s, 4 s, ... capped at
//! 15 min). A key with no failures for [`FAILURE_WINDOW`] is forgotten.
//! There is deliberately no per-account lockout independent of the source
//! address: that would let anyone lock any user out.
//!
//! IPv6 peers are grouped by /64 (one subscriber's allocation), IPv4-mapped
//! IPv6 addresses by their IPv4 address.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;
use tracing::warn;

/// Failures one (IP, username) pair may make before backoff starts.
pub const PAIR_FREE_FAILURES: u32 = 5;
/// Failures one IP may make across all usernames before backoff starts.
pub const IP_FREE_FAILURES: u32 = 20;
/// First backoff once a key's free failures are used up; doubles with each
/// further failure.
pub const BASE_BACKOFF: Duration = Duration::from_secs(1);
/// Longest single backoff.
pub const MAX_BACKOFF: Duration = Duration::from_secs(15 * 60);
/// A key with no failure for this long (and no active block) starts over.
pub const FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Most keys tracked at once (memory bound). When full, expired keys are
/// pruned; if it's still full, new keys go untracked until space frees up.
pub const MAX_TRACKED: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Ip(IpAddr),
    Pair(IpAddr, String),
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    failures: u32,
    last_failure: Instant,
    blocked_until: Instant,
}

impl Bucket {
    fn fresh(now: Instant) -> Self {
        Self {
            failures: 0,
            last_failure: now,
            blocked_until: now,
        }
    }

    fn expired(&self, now: Instant) -> bool {
        now >= self.blocked_until && now.duration_since(self.last_failure) >= FAILURE_WINDOW
    }
}

/// Shared login throttle; lives in `ServerCtx`.
#[derive(Debug, Default)]
pub struct LoginLimiter {
    buckets: Mutex<HashMap<Key, Bucket>>,
}

impl LoginLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// `Err(retry_after)` if a login from `ip` for `username` must be refused
    /// right now.
    pub fn check(&self, ip: IpAddr, username: &str) -> Result<(), Duration> {
        let now = Instant::now();
        let ip = normalize(ip);
        let buckets = self.buckets.lock().expect("limiter lock poisoned");
        let mut wait = Duration::ZERO;
        for key in [Key::Ip(ip), Key::Pair(ip, username.to_owned())] {
            if let Some(bucket) = buckets.get(&key) {
                wait = wait.max(bucket.blocked_until.saturating_duration_since(now));
            }
        }
        if wait.is_zero() {
            Ok(())
        } else {
            Err(wait)
        }
    }

    /// Count a failed attempt (wrong password, unknown user, banned account,
    /// invalid username) against both the IP and the (IP, username) pair.
    pub fn record_failure(&self, ip: IpAddr, username: &str) {
        let now = Instant::now();
        let ip = normalize(ip);
        let mut buckets = self.buckets.lock().expect("limiter lock poisoned");
        if buckets.len() + 2 > MAX_TRACKED {
            buckets.retain(|_, b| !b.expired(now));
        }
        bump(&mut buckets, Key::Ip(ip), IP_FREE_FAILURES, now);
        bump(
            &mut buckets,
            Key::Pair(ip, username.to_owned()),
            PAIR_FREE_FAILURES,
            now,
        );
    }

    /// Current failure count for (IP, username) within the window (0 if
    /// none or forgotten). For diagnostics and tests.
    pub fn failure_count(&self, ip: IpAddr, username: &str) -> u32 {
        let now = Instant::now();
        let buckets = self.buckets.lock().expect("limiter lock poisoned");
        match buckets.get(&Key::Pair(normalize(ip), username.to_owned())) {
            Some(bucket) if !bucket.expired(now) => bucket.failures,
            _ => 0,
        }
    }

    /// A successful login clears its (IP, username) pair. The IP-wide count
    /// is left alone, so logging into your own account can't launder
    /// guesses against others.
    pub fn record_success(&self, ip: IpAddr, username: &str) {
        let ip = normalize(ip);
        self.buckets
            .lock()
            .expect("limiter lock poisoned")
            .remove(&Key::Pair(ip, username.to_owned()));
    }
}

fn bump(buckets: &mut HashMap<Key, Bucket>, key: Key, free: u32, now: Instant) {
    if !buckets.contains_key(&key) && buckets.len() >= MAX_TRACKED {
        warn!("login limiter full; not tracking a new source");
        return;
    }
    let bucket = buckets.entry(key).or_insert_with(|| Bucket::fresh(now));
    if bucket.expired(now) {
        *bucket = Bucket::fresh(now);
    }
    bucket.failures = bucket.failures.saturating_add(1);
    bucket.last_failure = now;
    if bucket.failures > free {
        let doublings = (bucket.failures - free - 1).min(20);
        let backoff = BASE_BACKOFF.saturating_mul(1 << doublings).min(MAX_BACKOFF);
        bucket.blocked_until = now + backoff;
    }
}

/// Group addresses the way a single attacker's allocation is usually sized.
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn pair_backs_off_after_free_failures_and_recovers() {
        let limiter = LoginLimiter::new();
        let attacker = ip("10.0.0.1");
        for _ in 0..PAIR_FREE_FAILURES {
            assert!(limiter.check(attacker, "sysop").is_ok());
            limiter.record_failure(attacker, "sysop");
        }
        assert!(limiter.check(attacker, "sysop").is_ok());

        // One more failure: blocked for BASE_BACKOFF.
        limiter.record_failure(attacker, "sysop");
        assert_eq!(limiter.check(attacker, "sysop"), Err(BASE_BACKOFF));
        // Next failure doubles it.
        limiter.record_failure(attacker, "sysop");
        assert_eq!(limiter.check(attacker, "sysop"), Err(BASE_BACKOFF * 2));

        // The block lapses on its own.
        tokio::time::advance(BASE_BACKOFF * 2).await;
        assert!(limiter.check(attacker, "sysop").is_ok());

        // Other users from the same IP, and the same user from elsewhere,
        // are unaffected (no account lockout).
        assert!(limiter.check(attacker, "plain").is_ok());
        assert!(limiter.check(ip("10.0.0.2"), "sysop").is_ok());

        // After a quiet window the pair starts from scratch.
        tokio::time::advance(FAILURE_WINDOW).await;
        limiter.record_failure(attacker, "sysop");
        assert!(limiter.check(attacker, "sysop").is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_is_capped() {
        let limiter = LoginLimiter::new();
        let attacker = ip("10.0.0.1");
        for _ in 0..100 {
            limiter.record_failure(attacker, "sysop");
        }
        assert_eq!(limiter.check(attacker, "sysop"), Err(MAX_BACKOFF));
    }

    #[tokio::test(start_paused = true)]
    async fn spraying_many_usernames_trips_the_ip_limit() {
        let limiter = LoginLimiter::new();
        let attacker = ip("192.0.2.7");
        for i in 0..=IP_FREE_FAILURES {
            limiter.record_failure(attacker, &format!("user{i}"));
        }
        // A fresh username from that IP is now refused...
        assert!(limiter.check(attacker, "never-tried").is_err());
        // ...but not from another IP.
        assert!(limiter.check(ip("192.0.2.8"), "never-tried").is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn success_clears_only_the_pair() {
        let limiter = LoginLimiter::new();
        let peer = ip("10.0.0.1");
        for _ in 0..PAIR_FREE_FAILURES {
            limiter.record_failure(peer, "phraq");
        }
        limiter.record_success(peer, "phraq");
        // The pair's count restarted: another failure isn't blocked yet.
        limiter.record_failure(peer, "phraq");
        assert!(limiter.check(peer, "phraq").is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn ipv6_is_grouped_by_slash_64() {
        let limiter = LoginLimiter::new();
        for i in 0..=PAIR_FREE_FAILURES {
            limiter.record_failure(ip(&format!("2001:db8:1:2::{:x}", i + 1)), "sysop");
        }
        assert!(limiter.check(ip("2001:db8:1:2::ffff"), "sysop").is_err());
        assert!(limiter.check(ip("2001:db8:1:3::1"), "sysop").is_ok());
        // IPv4-mapped addresses count as their IPv4 address.
        for _ in 0..=PAIR_FREE_FAILURES {
            limiter.record_failure(ip("::ffff:10.1.1.1"), "sysop");
        }
        assert!(limiter.check(ip("10.1.1.1"), "sysop").is_err());
    }
}
