//! Per-member chat flood protection: a small token bucket. Each message
//! costs one token; the bucket refills at a fixed rate up to a burst cap.

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

    /// Try to spend one token. Returns `false` when the sender is flooding.
    pub fn allow(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
}
