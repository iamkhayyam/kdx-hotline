//! Token-bucket bandwidth throttle for transfers. Hand-rolled because the
//! needed semantics (a bucket shared by every transfer of one account, async
//! wait for capacity, cancel-safe reservations) are tiny and this way they're
//! precisely testable.
//!
//! Implemented as a virtual-clock bucket (GCRA): each charge pushes a
//! "theoretical arrival time" forward by `bytes / rate`, and the caller may
//! proceed once that time is no more than one burst ahead of now. Charging is
//! synchronous and returns the instant to wait for, so a caller that gets
//! cancelled mid-sleep can remember the instant and resume waiting without
//! being charged twice.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

#[derive(Debug)]
pub struct TokenBucket {
    /// Bytes per second; `None` = unlimited.
    rate: Option<f64>,
    /// How far the virtual clock may run ahead of real time before callers
    /// have to wait (the burst capacity, expressed as time).
    burst: Duration,
    /// Theoretical arrival time: when everything charged so far is "paid".
    tat: Instant,
}

/// A bucket shared by every transfer of one account in one direction.
pub type SharedBucket = Arc<Mutex<TokenBucket>>;

impl TokenBucket {
    /// `bytes_per_sec` of 0 disables throttling. Burst capacity is one
    /// second of traffic (min 64 KiB so single chunks always fit).
    pub fn new(bytes_per_sec: u64) -> Self {
        let rate = (bytes_per_sec > 0).then_some(bytes_per_sec as f64);
        let burst = match rate {
            Some(rate) => Duration::from_secs_f64(rate.max(64.0 * 1024.0) / rate),
            None => Duration::ZERO,
        };
        Self {
            rate,
            burst,
            tat: Instant::now(),
        }
    }

    /// A new bucket wrapped for sharing between transfers.
    pub fn shared(bytes_per_sec: u64) -> SharedBucket {
        Arc::new(Mutex::new(Self::new(bytes_per_sec)))
    }

    /// Charge `bytes` against the budget and return when the caller may
    /// proceed (now, if the burst still covers it). Never blocks.
    pub fn reserve(&mut self, bytes: usize) -> Instant {
        let now = Instant::now();
        let Some(rate) = self.rate else { return now };
        let start = self.tat.max(now);
        self.tat = start + Duration::from_secs_f64(bytes as f64 / rate);
        self.tat
            .checked_sub(self.burst)
            .map_or(now, |ready| ready.max(now))
    }

    /// Consume `bytes` of budget, sleeping until the bucket can cover it.
    pub async fn consume(&mut self, bytes: usize) {
        let ready = self.reserve(bytes);
        wait_until(ready).await;
    }
}

/// Sleep until `ready`, without touching the timer when it has already
/// passed (an unthrottled or within-burst transfer shouldn't pay a timer
/// tick per chunk).
pub async fn wait_until(ready: Instant) {
    if ready > Instant::now() {
        tokio::time::sleep_until(ready).await;
    }
}

/// Charge `bytes` to a shared bucket and return when the caller may proceed.
pub fn reserve_shared(bucket: &SharedBucket, bytes: usize) -> Instant {
    bucket
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .reserve(bytes)
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

    #[tokio::test(start_paused = true)]
    async fn shared_bucket_caps_the_sum_of_two_transfers() {
        // Two "transfers" drawing on one 64 KiB/s bucket in parallel get
        // 64 KiB/s between them, not each.
        let bucket = TokenBucket::shared(64 * 1024);
        let start = Instant::now();
        let run = |bucket: SharedBucket| async move {
            for _ in 0..4 {
                let ready = reserve_shared(&bucket, 32 * 1024);
                tokio::time::sleep_until(ready).await;
            }
        };
        tokio::join!(run(bucket.clone()), run(bucket.clone()));
        // 256 KiB total: 64 KiB burst + 192 KiB at 64 KiB/s = 3 s.
        let elapsed = Instant::now().duration_since(start);
        assert!(
            elapsed >= Duration::from_millis(2900) && elapsed <= Duration::from_secs(4),
            "elapsed {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn idle_time_refills_only_up_to_the_burst() {
        let mut bucket = TokenBucket::new(64 * 1024);
        tokio::time::sleep(Duration::from_secs(60)).await;
        // A minute idle must not bank a minute of traffic.
        let start = Instant::now();
        for _ in 0..4 {
            bucket.consume(32 * 1024).await;
        }
        let elapsed = Instant::now().duration_since(start);
        assert!(elapsed >= Duration::from_millis(900), "elapsed {elapsed:?}");
    }
}
