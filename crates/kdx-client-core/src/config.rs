use std::path::PathBuf;
use std::time::Duration;

/// How the client decides whether to trust a server's TLS certificate.
#[derive(Debug, Clone, Default)]
pub enum TrustPolicy {
    /// Trust-on-first-use: pin the server's SPKI fingerprint on first
    /// contact, warn loudly if it ever changes. The KDX default.
    #[default]
    Tofu,
    /// Verify against the OS/webpki root store (for real CA-signed certs).
    System,
    /// Accept any certificate. Test-only; requires the `dangerous` feature.
    #[cfg(feature = "dangerous")]
    InsecureAcceptAny,
}

/// Default bound on TCP connect + TLS + KDX handshake.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Default bound on waiting for a request's reply.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Default keepalive Ping interval.
pub const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(30);
/// Default bound on writing one frame to the socket.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Default age after which an untouched partial download is swept.
pub const DEFAULT_STALE_PARTIAL_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Connection parameters.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub host: String,
    pub port: u16,
    pub trust: TrustPolicy,
    /// The client's own state directory (an app's private data directory;
    /// inside the container for a sandboxed macOS app). Holds
    /// `known_hosts.toml`, and under `transfers/` every partial download:
    /// its bytes (`<id>.kdxdata`) and resume sidecar (`<id>.kdxpart`). Only
    /// the verified file is ever written to a download's destination.
    pub data_dir: PathBuf,
    /// Bound on the whole connect: TCP connect, TLS handshake and the KDX
    /// version handshake. Default 15 s.
    pub connect_timeout: Duration,
    /// How long a `ClientHandle` call waits for the server's reply before
    /// failing with `ClientError::Timeout` (transfers are exempt: they are
    /// bounded by liveness instead). Also bounds waiting for a transfer to
    /// be accepted. Default 30 s.
    pub request_timeout: Duration,
    /// Keepalive Ping interval. If nothing at all arrives from the server
    /// for twice this long the connection is declared dead and closed.
    /// Default 30 s.
    pub keepalive: Duration,
    /// Bound on writing one frame (a server that stops reading can't wedge
    /// the client). Default 30 s.
    pub write_timeout: Duration,
    /// Partial downloads nothing has touched for this long are deleted from
    /// `data_dir/transfers/` when connecting (resuming them is then no
    /// longer possible), so abandoned downloads can't fill the disk.
    /// `None` keeps them forever. Default 7 days.
    pub stale_partial_age: Option<Duration>,
}

impl ClientConfig {
    pub fn new(host: impl Into<String>, port: u16, data_dir: impl Into<PathBuf>) -> Self {
        Self {
            host: host.into(),
            port,
            trust: TrustPolicy::default(),
            data_dir: data_dir.into(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            keepalive: DEFAULT_KEEPALIVE,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            stale_partial_age: Some(DEFAULT_STALE_PARTIAL_AGE),
        }
    }
}
