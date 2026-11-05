use std::sync::atomic::{AtomicU64, Ordering};

use kdx_client_core::ClientHandle;
use serde::Serialize;
use tauri::async_runtime::JoinHandle;
use tokio::sync::Mutex;

/// App-wide state: the one active client connection (if any), the
/// connection-generation counter, and the fingerprint awaiting a TOFU
/// decision.
#[derive(Default)]
pub struct AppState {
    pub conn: Mutex<Option<Conn>>,
    /// Last connection generation handed out. Every forwarded event carries
    /// its connection's generation so the webview can drop stragglers from a
    /// connection that has since been replaced.
    generation: AtomicU64,
    /// App-wide event sequence number (dedupe key for replayed events).
    pub seq: AtomicU64,
    /// The certificate the last `connect` refused as untrusted. `trust` may
    /// only pin exactly this (host, port, fingerprint), once.
    pub pending_trust: std::sync::Mutex<Option<PendingTrust>>,
}

impl AppState {
    /// Hand out the next connection generation (starts at 1, so 0 can mean
    /// "never connected" in the webview).
    pub fn next_generation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::SeqCst) + 1
    }
}

/// One live connection plus what the webview needs to hydrate a window that
/// opens after login (see `get_session`).
pub struct Conn {
    pub handle: ClientHandle,
    pub generation: u64,
    pub forwarder: JoinHandle<()>,
    pub host: String,
    pub port: u16,
    pub user: Option<SessionUser>,
}

#[derive(Clone, Serialize)]
pub struct SessionUser {
    pub username: String,
    pub class: u8,
}

/// An untrusted certificate the user may choose to pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingTrust {
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
    pub previous: Option<String>,
}
