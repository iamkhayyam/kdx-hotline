//! Per-sender flood protection: a small token bucket. Each message
//! costs one token; the bucket refills at a fixed rate up to a burst cap.
//! Connections keep one of these per throttled command (chat, private
//! messages, identity changes, ...) for the life of the connection, so
//! leaving and rejoining a room can't reset it.

use std::time::Duration;

use tokio::time::Instant;

#[derive(Debug)]
pub struct FloodGate {
    tokens: f64,
    burst: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl FloodGate {
    pub fn new(burst: u32, refill_per_sec: f64) -> Self {
        Self {
            tokens: burst as f64,
            burst: burst as f64,
            refill_per_sec,
            last: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.burst);
    }

    /// Try to spend one token. Returns `false` when the sender is flooding.
    pub fn allow(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// When the next token becomes available, or `None` if one is available
    /// right now. Spends nothing — pair with [`FloodGate::allow`].
    pub fn ready_at(&mut self) -> Option<Instant> {
        self.refill();
        if self.tokens >= 1.0 || self.refill_per_sec <= 0.0 {
            return None;
        }
        let wait = (1.0 - self.tokens) / self.refill_per_sec;
        Some(self.last + Duration::from_secs_f64(wait))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn burst_then_throttle_then_recover() {
        let mut gate = FloodGate::new(3, 1.0);
        assert!(gate.allow());
        assert!(gate.allow());
        assert!(gate.allow());
        assert!(!gate.allow(), "burst exhausted");

        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(gate.allow(), "refilled after waiting");
        assert!(gate.allow());
        assert!(!gate.allow(), "only 2 tokens refilled in 2s");
    }

    #[tokio::test(start_paused = true)]
    async fn ready_at_reports_when_the_next_token_lands() {
        let mut gate = FloodGate::new(1, 2.0);
        assert!(gate.ready_at().is_none(), "a full bucket is ready now");
        assert!(gate.allow());
        let at = gate.ready_at().expect("empty bucket must wait");
        assert_eq!(at - Instant::now(), Duration::from_millis(500));
        tokio::time::sleep_until(at).await;
        assert!(gate.ready_at().is_none());
        assert!(gate.allow());
    }
}
