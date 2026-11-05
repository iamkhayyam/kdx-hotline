//! Forwarding client-core events to the webview.
//!
//! Every event goes out as `{ gen, seq, type, ... }` on the "kdx" channel:
//! - `gen` is the connection generation, so windows can drop stragglers from
//!   a connection that has since been replaced (the forwarder of a replaced
//!   connection is also aborted, so this is belt and braces);
//! - `seq` is an app-wide sequence number, the dedupe key when the launcher
//!   replays an event to a window that wasn't open yet.
//!
//! Transfer progress is throttled, its chunk bitmap is downsampled to at most
//! [`MAX_BUCKETS`] cells, and it is sent only to the windows that draw it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use kdx_client_core::{Direction, Event};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, Runtime};
use tokio::sync::mpsc;

use crate::state::AppState;

/// Event channel name the webview listens on.
pub const KDX_EVENT: &str = "kdx";
/// Most cells the Transfers window's chunk grid ever draws.
pub const MAX_BUCKETS: usize = 1024;
/// Minimum spacing between progress events for one transfer.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);
/// The only windows that render transfer progress.
const PROGRESS_WINDOWS: [&str; 2] = ["main", "transfers"];

#[derive(Serialize, Clone)]
struct Envelope<'a, T: Serialize> {
    gen: u64,
    seq: u64,
    #[serde(flatten)]
    event: &'a T,
}

/// Webview shape of `Event::TransferProgress`: `buckets` replaces the raw
/// bitmap (0 = no chunk done, 1 = some, 2 = all, per cell).
#[derive(Serialize, Clone)]
#[serde(tag = "type", rename = "transfer_progress")]
struct ProgressDto {
    id: String,
    direction: Direction,
    done: u32,
    total: u32,
    buckets: Vec<u8>,
}

/// A synthetic `Disconnected` for connection `gen` (explicit disconnect, a
/// replaced connection, or an actor that died without saying goodbye).
pub fn emit_disconnected<R: Runtime>(app: &AppHandle<R>, gen: u64, seq: &AtomicU64, reason: &str) {
    let ev = Event::Disconnected {
        reason: reason.to_string(),
    };
    emit_all(app, gen, next_seq(seq), &ev);
}

fn next_seq(seq: &AtomicU64) -> u64 {
    seq.fetch_add(1, Ordering::Relaxed) + 1
}

fn emit_all<R: Runtime, T: Serialize + Clone>(app: &AppHandle<R>, gen: u64, seq: u64, event: &T) {
    let _ = app.emit(KDX_EVENT, Envelope { gen, seq, event });
}

/// Pump `events` (connection `gen`) to the webview until the connection
/// ends. If the stream closes without a `Disconnected` (the actor died), one
/// is synthesized so the UI doesn't sit "online" on a dead handle. Either
/// way the connection is cleared from [`AppState`] if it is still current.
pub async fn forward<R: Runtime>(app: AppHandle<R>, gen: u64, mut events: mpsc::Receiver<Event>) {
    let mut throttle = ProgressThrottle::default();
    let mut reason = None;
    while let Some(ev) = events.recv().await {
        let seq = next_seq(&app.state::<AppState>().seq);
        match &ev {
            Event::TransferProgress {
                id,
                direction,
                done,
                total,
                bitmap,
                bitmap_bits,
            } => {
                if !throttle.admit(id, *done, *total, Instant::now()) {
                    continue;
                }
                let dto = ProgressDto {
                    id: id.clone(),
                    direction: *direction,
                    done: *done,
                    total: *total,
                    // client-core already downsamples the grid to at most
                    // 1024 bits (`bitmap_bits`); bucket those, not chunks.
                    buckets: bucketize(bitmap, *bitmap_bits),
                };
                for label in PROGRESS_WINDOWS {
                    let _ = app.emit_to(label, KDX_EVENT, Envelope { gen, seq, event: &dto });
                }
            }
            Event::TransferComplete { id, .. } => {
                throttle.forget(id);
                emit_all(&app, gen, seq, &ev);
            }
            Event::Disconnected { reason: r } => {
                reason = Some(r.clone());
                break;
            }
            _ => emit_all(&app, gen, seq, &ev),
        }
    }

    // Clear the dead connection first so a window reacting to the event (and
    // calling get_session) already sees it gone.
    {
        let state = app.state::<AppState>();
        let mut conn = state.conn.lock().await;
        if conn.as_ref().map(|c| c.generation) == Some(gen) {
            conn.take();
        }
    }
    let reason = reason.unwrap_or_else(|| "connection lost".to_string());
    emit_disconnected(&app, gen, &app.state::<AppState>().seq, &reason);
}

/// Rate-limits progress events per transfer, always letting the first and
/// the final (`done >= total`) one through.
#[derive(Default)]
pub struct ProgressThrottle {
    last: HashMap<String, Instant>,
}

impl ProgressThrottle {
    pub fn admit(&mut self, id: &str, done: u32, total: u32, now: Instant) -> bool {
        let due = done >= total
            || self
                .last
                .get(id)
                .is_none_or(|t| now.duration_since(*t) >= PROGRESS_INTERVAL);
        if due {
            self.last.insert(id.to_string(), now);
        }
        due
    }

    pub fn forget(&mut self, id: &str) {
        self.last.remove(id);
    }
}

/// Downsample an LSB-first chunk bitmap of `total` chunks to at most
/// [`MAX_BUCKETS`] cells: 0 = none of the cell's chunks done, 1 = some,
/// 2 = all. Bits beyond the bitmap's length count as not done, and the work
/// is bounded by the bitmap's size, not by the (server-chosen) `total`.
pub fn bucketize(bitmap: &[u8], total: u32) -> Vec<u8> {
    let total = u64::from(total);
    if total == 0 {
        return Vec::new();
    }
    let cells = total.min(MAX_BUCKETS as u64);
    let have_bits = (bitmap.len() as u64) * 8;
    (0..cells)
        .map(|b| {
            let start = b * total / cells;
            let end = ((b + 1) * total / cells).max(start + 1);
            let done = count_ones(bitmap, start.min(have_bits), end.min(have_bits));
            if done == 0 {
                0
            } else if done == end - start {
                2
            } else {
                1
            }
        })
        .collect()
}

/// Set bits in `[start, end)` of an LSB-first bitmap (both within range).
fn count_ones(bitmap: &[u8], start: u64, end: u64) -> u64 {
    let mut n = 0u64;
    let mut i = start;
    while i < end {
        let byte = bitmap[(i / 8) as usize];
        if i.is_multiple_of(8) && end - i >= 8 {
            n += u64::from(byte.count_ones());
            i += 8;
        } else {
            n += u64::from((byte >> (i % 8)) & 1);
            i += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucketize_small_transfer_is_one_cell_per_chunk() {
        // chunks 0, 1 and 3 done of 5
        assert_eq!(bucketize(&[0b0000_1011], 5), vec![2, 2, 0, 2, 0]);
        assert_eq!(bucketize(&[], 0), Vec::<u8>::new());
    }

    #[test]
    fn bucketize_caps_cells_and_aggregates() {
        let total = 4096u32; // 4 chunks per cell
        let mut bitmap = vec![0u8; 512];
        bitmap[0] = 0b0000_1111; // cell 0 complete
        bitmap[1] = 0b0000_0001; // cell 2 partial
        let cells = bucketize(&bitmap, total);
        assert_eq!(cells.len(), MAX_BUCKETS);
        assert_eq!(&cells[..4], &[2, 0, 1, 0]);
        assert!(cells[4..].iter().all(|&c| c == 0));

        let full = vec![0xFFu8; 512];
        assert!(bucketize(&full, total).iter().all(|&c| c == 2));
    }

    #[test]
    fn bucketize_huge_total_with_tiny_bitmap_is_cheap_and_bounded() {
        // A hostile server announcing u32::MAX chunks must not make us walk
        // four billion bits per event or draw four billion cells.
        let start = Instant::now();
        let cells = bucketize(&[0xFF], u32::MAX);
        assert_eq!(cells.len(), MAX_BUCKETS);
        assert_eq!(cells[0], 1);
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn throttle_admits_first_final_and_spaced_events() {
        let mut t = ProgressThrottle::default();
        let t0 = Instant::now();
        assert!(t.admit("a", 1, 100, t0));
        assert!(!t.admit("a", 2, 100, t0 + Duration::from_millis(10)));
        assert!(t.admit("b", 1, 100, t0 + Duration::from_millis(10)), "per transfer");
        assert!(t.admit("a", 3, 100, t0 + PROGRESS_INTERVAL));
        assert!(t.admit("a", 100, 100, t0 + PROGRESS_INTERVAL), "final always passes");
        t.forget("a");
        assert!(t.admit("a", 1, 100, t0 + PROGRESS_INTERVAL));
    }

    #[test]
    fn envelope_flattens_event_with_generation() {
        let ev = Event::Chat {
            room: "lobby".into(),
            sender: "a".into(),
            timestamp: 1,
            flags: 0,
            text: "hi".into(),
        };
        let json = serde_json::to_value(Envelope {
            gen: 7,
            seq: 9,
            event: &ev,
        })
        .unwrap();
        assert_eq!(json["gen"], 7);
        assert_eq!(json["seq"], 9);
        assert_eq!(json["type"], "chat");
        assert_eq!(json["room"], "lobby");

        let dto = ProgressDto {
            id: "x".into(),
            direction: Direction::Download,
            done: 1,
            total: 2,
            buckets: vec![2, 0],
        };
        let json = serde_json::to_value(Envelope {
            gen: 1,
            seq: 2,
            event: &dto,
        })
        .unwrap();
        assert_eq!(json["type"], "transfer_progress");
        assert_eq!(json["direction"], "download");
        assert_eq!(json["buckets"][0], 2);
        assert!(json.get("bitmap").is_none());
    }
}

#[cfg(test)]
mod forward_tests {
    use std::sync::{Arc, Mutex};

    use tauri::test::{mock_builder, mock_context, noop_assets, MockRuntime};
    use tauri::{Listener, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

    use super::*;

    type Seen = Arc<Mutex<Vec<serde_json::Value>>>;

    fn window(app: &tauri::App<MockRuntime>, label: &str) -> (WebviewWindow<MockRuntime>, Seen) {
        let w = WebviewWindowBuilder::new(app, label, WebviewUrl::default())
            .build()
            .unwrap();
        let seen: Seen = Default::default();
        let s = seen.clone();
        w.listen(KDX_EVENT, move |e| {
            s.lock().unwrap().push(serde_json::from_str(e.payload()).unwrap());
        });
        (w, seen)
    }

    fn types(seen: &Seen) -> Vec<String> {
        seen.lock()
            .unwrap()
            .iter()
            .map(|v| v["type"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn tags_events_targets_progress_and_reports_a_dead_actor() {
        let app = mock_builder()
            .manage(AppState::default())
            .build(mock_context(noop_assets()))
            .unwrap();
        let (_m, main) = window(&app, "main");
        let (_c, chat) = window(&app, "chat");
        let (_t, transfers) = window(&app, "transfers");

        let (tx, rx) = mpsc::channel(8);
        tx.try_send(Event::ServerInfo { text: "hi".into() }).unwrap();
        tx.try_send(Event::TransferProgress {
            id: "t1".into(),
            direction: Direction::Download,
            done: 1,
            total: 50_000_000,
            bitmap: vec![0xFF],
            bitmap_bits: 1024,
        })
        .unwrap();
        // The actor dies without a Disconnected (e.g. it panicked): the
        // sender is simply dropped.
        drop(tx);
        tauri::async_runtime::block_on(forward(app.handle().clone(), 7, rx));

        // Progress goes only to the windows that draw it, downsampled.
        assert_eq!(types(&main), ["server_info", "transfer_progress", "disconnected"]);
        assert_eq!(types(&transfers), types(&main));
        assert_eq!(types(&chat), ["server_info", "disconnected"]);
        let progress = main.lock().unwrap()[1].clone();
        assert_eq!(progress["buckets"].as_array().unwrap().len(), MAX_BUCKETS);
        assert!(progress.get("bitmap").is_none());

        // Everything carries the generation and increasing sequence numbers;
        // the dead actor is reported instead of leaving the UI "online".
        let all = chat.lock().unwrap().clone();
        assert!(all.iter().all(|v| v["gen"] == 7));
        assert!(all[0]["seq"].as_u64() < all[1]["seq"].as_u64());
        assert_eq!(all[1]["reason"], "connection lost");
    }

    #[test]
    fn disconnected_ends_forwarding_once() {
        let app = mock_builder()
            .manage(AppState::default())
            .build(mock_context(noop_assets()))
            .unwrap();
        let (_m, main) = window(&app, "main");
        let (tx, rx) = mpsc::channel(8);
        tx.try_send(Event::Disconnected {
            reason: "connection closed by server".into(),
        })
        .unwrap();
        tx.try_send(Event::ServerInfo { text: "after".into() }).unwrap();
        tauri::async_runtime::block_on(forward(app.handle().clone(), 3, rx));
        let seen = main.lock().unwrap().clone();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert_eq!(seen[0]["type"], "disconnected");
        assert_eq!(seen[0]["reason"], "connection closed by server");
        drop(tx);
    }
}
