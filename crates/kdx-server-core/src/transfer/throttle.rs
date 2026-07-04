//! Token-bucket bandwidth throttle for transfers. Hand-rolled because the
//! needed semantics (per-transfer bucket, async wait for capacity) are tiny
//! and this way they're precisely testable.

use std::time::Duration;

use tokio::time::Instant;

#[derive(Debug)]
pub struct TokenBucket {
    /// Bytes per second; `None` = unlimited.
    rate: Option<f64>,
    capacity: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// `bytes_per_sec` of 0 disables throttling. Burst capacity is one
    /// second of traffic (min 64 KiB so single chunks always fit).
    pub fn new(bytes_per_sec: u64) -> Self {
        let rate = (bytes_per_sec > 0).then_some(bytes_per_sec as f64);
        let capacity = rate.unwrap_or(f64::INFINITY).max(64.0 * 1024.0);
        Self {
            rate,
            capacity,
            tokens: capacity,
            last: Instant::now(),
        }
    }

    /// Consume `bytes` of budget, sleeping until the bucket can cover it.
    pub async fn consume(&mut self, bytes: usize) {
        let Some(rate) = self.rate else { return };
        let now = Instant::now();
        self.tokens =
            (self.tokens + now.duration_since(self.last).as_secs_f64() * rate).min(self.capacity);
        self.last = now;

        let need = bytes as f64;
        if self.tokens >= need {
            self.tokens -= need;
            return;
        }
        let deficit = need - self.tokens;
        self.tokens = 0.0;
        let wait = Duration::from_secs_f64(deficit / rate);
        tokio::time::sleep(wait).await;
        self.last = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn unlimited_never_waits() {
        let mut bucket = TokenBucket::new(0);
        let start = Instant::now();
        bucket.consume(100 * 1024 * 1024).await;
        assert_eq!(Instant::now(), start);
    }

    #[tokio::test(start_paused = true)]
    async fn throttles_past_burst() {
        // 64 KiB/s rate, 64 KiB burst. Consuming 256 KiB must take ~3s
        // (first 64 KiB free from the full bucket, then 192 KiB at rate).
        let mut bucket = TokenBucket::new(64 * 1024);
        let start = Instant::now();
        for _ in 0..8 {
            bucket.consume(32 * 1024).await;
        }
        let elapsed = Instant::now().duration_since(start);
        assert!(
            elapsed >= Duration::from_secs(2) && elapsed <= Duration::from_secs(4),
            "elapsed {elapsed:?}"
        );
    }
}
