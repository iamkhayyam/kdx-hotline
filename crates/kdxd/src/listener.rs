use std::collections::HashMap;
use std::future::Future;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use kdx_server_core::auth::{AuthManager, RoleManager};
use kdx_server_core::chat::RoomManager;
use kdx_server_core::files::FileTree;
use kdx_server_core::history::HistoryLog;
use kdx_server_core::ip_rules::{IpRuleManager, Verdict};
use kdx_server_core::news::NewsManager;
use kdx_server_core::presence::unix_now;
use kdx_server_core::settings::ServerSettings;
use kdx_server_core::tracker::{ServerEntry, Tracker, DEFAULT_TTL};
use kdx_server_core::transfer::{TransferConfig, TransferManager};
use kdx_server_core::{Connection, Presence, ServerCtx};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig as TlsServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Instant};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::config::{Config, TlsConfig};

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("tls setup failed: {0}")]
    Tls(#[from] rustls::Error),
    #[error("cannot read pem file: {0}")]
    Pem(std::io::Error),
    #[error("no private key found in key pem")]
    NoKey,
    #[error("self-signed cert generation failed: {0}")]
    SelfSigned(#[from] rcgen::Error),
    #[error("storage error: {0}")]
    Storage(#[from] kdx_storage::StorageError),
    #[error("initialization failed: {0}")]
    Init(String),
    #[error("invalid config: {0}")]
    Config(String),
    #[error("refusing to use the cached dev key: {0}")]
    InsecureKey(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// ALPN protocol id the server offers. Clients that send ALPN must offer
/// this; clients that send none are still accepted.
pub const ALPN_PROTOCOL: &[u8] = b"kdx/1";

/// TCP keepalive on accepted sockets, so half-open peers (client vanished
/// without FIN/RST) are eventually noticed: first probe after 60 s idle,
/// then every 10 s, giving up after 6 unanswered probes.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(60);

/// Backoff after a failed `accept()` that isn't a per-connection error
/// (typically EMFILE/ENFILE when out of descriptors): 50 ms, doubling to 1 s.
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(50);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);
/// At most one accept-error / connection-refused log line per this period.
const ACCEPT_LOG_EVERY: Duration = Duration::from_secs(5);

/// Denied connections are coalesced into one `ip_denied` history row per
/// address per window (the first denial is recorded right away).
const DENY_LOG_WINDOW: Duration = Duration::from_secs(10 * 60);
/// Addresses tracked individually; denials from further addresses are
/// pooled into one "other addresses" counter.
const DENY_LOG_MAX_TRACKED: usize = 1024;
/// How often the deny-log writer looks for windows that have closed.
const DENY_LOG_POLL: Duration = Duration::from_secs(30);
/// Longest rule note copied into an `ip_denied` row.
const DENY_LOG_NOTE_LEN: usize = 200;

/// How often expired login sessions are swept from the `AuthManager`.
const SESSION_SWEEP_EVERY: Duration = Duration::from_secs(60);

/// A running server: its bound address, shared context, and the accept-loop
/// task handle.
pub struct Server {
    pub local_addr: SocketAddr,
    pub ctx: Arc<ServerCtx>,
    pub handle: tokio::task::JoinHandle<()>,
    limits: Arc<ConnLimits>,
}

impl Server {
    /// Connections currently open, at any stage (TLS handshake onwards).
    pub fn open_connections(&self) -> usize {
        self.limits.open()
    }

    /// Graceful stop: stop accepting, send every logged-in user a Disconnect
    /// carrying `reason`, then wait up to `grace` for connection tasks to
    /// finish. Returns how many connections were still open when it gave up
    /// (0 = fully drained). Also the right follow-up once the accept loop
    /// has stopped on its own after an `AdminShutdown`.
    pub async fn shutdown(mut self, reason: &str, grace: Duration) -> usize {
        // `notify_one` stores a permit, so the accept loop sees it even if
        // it is not parked on the notification right now.
        self.ctx.shutdown.notify_one();
        if !self.handle.is_finished() {
            let _ = timeout(Duration::from_secs(1), &mut self.handle).await;
        }
        self.handle.abort();
        self.ctx.presence.disconnect_all(reason).await;
        self.limits.drain(grace).await;
        // Land queued history rows (logouts, the shutdown itself) before
        // the process exits.
        let _ = timeout(Duration::from_secs(2), self.ctx.history.flush()).await;
        self.open_connections()
    }
}

/// Bind the listener and spawn the accept loop. Returns once bound, so
/// callers (including tests) know the server is reachable and on which port.
pub async fn serve(config: Config) -> Result<Server, ServeError> {
    config.check_limits().map_err(ServeError::Config)?;
    // Cache the dev cert next to the database so restarts keep the same
    // server identity (clients that pinned it stay trusted).
    let cert_cache = config
        .database
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    // The state dir (database, WAL, dev key) is private to the server.
    create_private_dir(&cert_cache)?;
    let tls_config = build_tls_config(config.tls.as_ref(), &cert_cache)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let pool = kdx_storage::connect(&config.database).await?;
    let tree = FileTree::load(pool.clone())
        .await
        .map_err(|e| ServeError::Init(e.to_string()))?;
    let transfers = TransferManager::new(
        pool.clone(),
        TransferConfig {
            files_root: config.files_root.clone(),
            max_upload_bytes_per_sec: config.max_upload_bytes_per_sec,
            max_download_bytes_per_sec: config.max_download_bytes_per_sec,
        },
    )
    .await
    .map_err(|e| ServeError::Init(e.to_string()))?;
    let ip_rules = IpRuleManager::load(pool.clone())
        .await
        .map_err(|e| ServeError::Init(e.to_string()))?;
    // Config gives the defaults; settings an admin saved earlier override them.
    let settings = ServerSettings::load(
        pool.clone(),
        config.server_name.clone(),
        config.server_description.clone(),
        config.max_users,
    )
    .await
    .map_err(|e| ServeError::Init(e.to_string()))?;
    let listener = TcpListener::bind(config.bind).await?;
    let local_addr = listener.local_addr()?;

    let ctx = Arc::new(ServerCtx {
        roles: RoleManager::new(pool.clone()),
        news: NewsManager::new(pool.clone()),
        history: HistoryLog::new(pool.clone()),
        ip_rules,
        auth: AuthManager::new(pool, Duration::from_secs(config.session_ttl_secs)),
        rooms: RoomManager::new(),
        tree,
        transfers,
        presence: Presence::spawn(),
        tracker: Tracker::spawn(DEFAULT_TTL),
        settings,
        bind_port: local_addr.port(),
        shutdown: Arc::new(Notify::new()),
    });
    info!(%local_addr, "kdxd listening");

    // Register this server in its own tracker directory and keep the entry
    // fresh (and its live user count / settings current) with a periodic
    // heartbeat — only under an operator-chosen public name: the bind
    // address is a wildcard or possibly an internal one.
    match &config.public_host {
        Some(host) => spawn_self_registration(&ctx, host.clone(), local_addr.port()),
        None => info!("public_host not set; not listing this server in its tracker directory"),
    }
    spawn_session_sweeper(&ctx);
    let denials = DenyLog::spawn_writer(&ctx);
    let limits = Arc::new(ConnLimits::new(
        config.max_connections,
        config.max_connections_per_ip,
    ));
    let handshake_timeout = Duration::from_secs(config.tls_handshake_timeout_secs);
    // Created before the accept task exists, so a shutdown notification
    // sent at any moment from here on is seen: `notified_owned()` catches
    // `notify_waiters` from creation on and consumes a `notify_one` permit.
    let stop = ctx.shutdown.clone().notified_owned();

    let accept_ctx = ctx.clone();
    let accept_limits = limits.clone();
    let handle = tokio::spawn(async move {
        tokio::pin!(stop);
        let mut backoff = AcceptBackoff::default();
        let mut refusal_log = LogThrottle::new(ACCEPT_LOG_EVERY);
        loop {
            tokio::select! {
                biased;
                // AdminShutdown notifies this to stop taking new connections.
                // Already-open connections close on their own as the
                // presence-wide Disconnect it also sent gets processed.
                _ = &mut stop => {
                    info!("shutdown requested; accept loop stopping");
                    break;
                }
                (tcp, peer) = accept_with_backoff(|| listener.accept(), &mut backoff) => {
                    // On a dual-stack `[::]` listener IPv4 peers arrive as
                    // `::ffff:a.b.c.d`; rules, caps and logs all need the
                    // plain IPv4 address or IPv4 rules never match.
                    let peer = canonical_peer(peer);
                    // Allow-Deny IP rules: match before TLS so a denied
                    // peer burns zero handshake work. `match_ip` is a
                    // scan of a small in-memory cache; the sockaddr's IP
                    // is what the rules apply to, not the port.
                    let verdict = accept_ctx.ip_rules.match_ip(peer.ip()).await;
                    if let Verdict::Deny { note } = verdict {
                        debug!(%peer, note = %note, "connection denied by IP rule");
                        // Only an in-memory count here: the history row is
                        // written (coalesced per address) by a background
                        // task, so a banned host's connect flood never makes
                        // the accept loop wait on the database.
                        denials.note(peer.ip(), &note);
                        // Close the socket immediately (drop it) — we do
                        // not want to send anything back, since even that
                        // hint would help someone probe for the ban.
                        drop(tcp);
                        continue;
                    }
                    let guard = match accept_limits.try_admit(peer.ip()) {
                        Ok(guard) => guard,
                        Err(refusal) => {
                            if let Some(suppressed) = refusal_log.allow(Instant::now()) {
                                warn!(%peer, limit = refusal.as_str(), suppressed, "connection refused");
                            }
                            drop(tcp);
                            continue;
                        }
                    };
                    set_keepalive(&tcp, peer);
                    let acceptor = acceptor.clone();
                    let conn_ctx = accept_ctx.clone();
                    tokio::spawn(async move {
                        // Holds this connection's global and per-address
                        // slots until the task ends, however it ends.
                        let _guard = guard;
                        let tls = match timeout(handshake_timeout, acceptor.accept(tcp)).await {
                            Ok(Ok(tls)) => tls,
                            Ok(Err(e)) => {
                                debug!(%peer, error = %e, "tls handshake failed");
                                return;
                            }
                            Err(_) => {
                                debug!(%peer, "tls handshake timed out");
                                return;
                            }
                        };
                        if let Err(e) =
                            Connection::new_with_peer(tls, conn_ctx, peer.to_string()).run().await
                        {
                            warn!(%peer, error = %e, "connection ended with error");
                        }
                    });
                }
            }
        }
    });

    Ok(Server {
        local_addr,
        ctx,
        handle,
        limits,
    })
}

/// Register this server in its own in-process tracker and keep the entry fresh
/// with a heartbeat every 30s (well within the 90s TTL), reading `settings`
/// and the live user count fresh each tick — so an admin's `ServerSettingsUpdate`
/// (name/description/max_users) shows up in the tracker directory within one
/// heartbeat, without restarting anything. `host` is the configured
/// `public_host`.
fn spawn_self_registration(ctx: &Arc<ServerCtx>, host: String, port: u16) {
    let ctx = ctx.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            let snap = ctx.settings.snapshot().await;
            let entry = ServerEntry {
                name: snap.name,
                host: host.clone(),
                port,
                users: ctx.presence.list().await.len() as u32,
                max_users: snap.max_users,
                description: snap.description,
            };
            ctx.tracker.heartbeat(entry).await;
        }
    });
}

/// Sweep expired login sessions out of the `AuthManager` periodically;
/// nothing else removes a session whose connection died before cleanup.
/// Holds only a weak reference, so the task ends with the server.
fn spawn_session_sweeper(ctx: &Arc<ServerCtx>) {
    let ctx = Arc::downgrade(ctx);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SESSION_SWEEP_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let Some(ctx) = ctx.upgrade() else { break };
            ctx.auth.sweep();
        }
    });
}

/// `peer` with an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) turned back
/// into plain IPv4.
fn canonical_peer(peer: SocketAddr) -> SocketAddr {
    SocketAddr::new(peer.ip().to_canonical(), peer.port())
}

/// Best-effort TCP keepalive on an accepted socket.
fn set_keepalive(tcp: &TcpStream, peer: SocketAddr) {
    let keepalive = socket2::TcpKeepalive::new().with_time(KEEPALIVE_IDLE);
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "windows",
    ))]
    let keepalive = keepalive
        .with_interval(Duration::from_secs(10))
        .with_retries(6);
    if let Err(e) = socket2::SockRef::from(tcp).set_tcp_keepalive(&keepalive) {
        debug!(%peer, error = %e, "could not enable TCP keepalive");
    }
}

/// Call `accept` until it yields a connection, sleeping between failures as
/// `backoff` says, so a persistent error (EMFILE once descriptors run out:
/// the pending connection stays queued and every retry fails at once) can't
/// turn the accept loop into a busy spin.
async fn accept_with_backoff<T, F, Fut>(mut accept: F, backoff: &mut AcceptBackoff) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    loop {
        match accept().await {
            Ok(conn) => {
                backoff.reset();
                return conn;
            }
            Err(e) => {
                let delay = backoff.on_error(&e, Instant::now());
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
}

/// Exponential backoff state for `accept()` failures.
struct AcceptBackoff {
    next: Duration,
    log: LogThrottle,
}

impl Default for AcceptBackoff {
    fn default() -> Self {
        Self {
            next: ACCEPT_BACKOFF_MIN,
            log: LogThrottle::new(ACCEPT_LOG_EVERY),
        }
    }
}

impl AcceptBackoff {
    /// How long to wait before calling `accept()` again after `err`. An
    /// error about one connection (reset or aborted before we got to it)
    /// says nothing about the listener, so it gets no delay — a remote peer
    /// must not be able to slow accepting down by triggering it.
    fn on_error(&mut self, err: &io::Error, now: Instant) -> Duration {
        if matches!(
            err.kind(),
            io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionReset
        ) {
            debug!(error = %err, "connection failed before it was accepted");
            return Duration::ZERO;
        }
        let delay = self.next;
        self.next = (self.next * 2).min(ACCEPT_BACKOFF_MAX);
        if let Some(suppressed) = self.log.allow(now) {
            error!(
                error = %err,
                retry_in_ms = delay.as_millis() as u64,
                suppressed,
                "accept failed"
            );
        }
        delay
    }

    fn reset(&mut self) {
        self.next = ACCEPT_BACKOFF_MIN;
    }
}

/// Lets through at most one log line per `every`, counting the rest.
struct LogThrottle {
    every: Duration,
    last: Option<Instant>,
    suppressed: u64,
}

impl LogThrottle {
    fn new(every: Duration) -> Self {
        Self {
            every,
            last: None,
            suppressed: 0,
        }
    }

    /// `Some(n)` when a line may be logged now (`n` = lines swallowed since
    /// the last one), `None` to stay quiet.
    fn allow(&mut self, now: Instant) -> Option<u64> {
        match self.last {
            Some(last) if now.saturating_duration_since(last) < self.every => {
                self.suppressed += 1;
                None
            }
            _ => {
                self.last = Some(now);
                Some(std::mem::take(&mut self.suppressed))
            }
        }
    }
}

/// Why a connection was turned away at accept time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    ServerFull,
    PerAddressLimit,
}

impl Refusal {
    fn as_str(self) -> &'static str {
        match self {
            Refusal::ServerFull => "max_connections",
            Refusal::PerAddressLimit => "max_connections_per_ip",
        }
    }
}

/// Global and per-address caps on open connections. A slot is taken before
/// the TLS handshake and held by a [`ConnGuard`] for the connection's life.
struct ConnLimits {
    slots: Arc<Semaphore>,
    max_total: u32,
    per_addr: Mutex<HashMap<IpAddr, usize>>,
    max_per_addr: usize,
}

/// The per-address key: the address itself for IPv4, its /64 for IPv6 (one
/// host typically holds a whole /64, so per-/128 counting caps nothing).
fn limit_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
    }
}

impl ConnLimits {
    fn new(max_total: usize, max_per_addr: usize) -> Self {
        // `Config::check_limits` keeps this far below u32::MAX.
        let max_total = u32::try_from(max_total).unwrap_or(u32::MAX);
        Self {
            slots: Arc::new(Semaphore::new(max_total as usize)),
            max_total,
            per_addr: Mutex::new(HashMap::new()),
            max_per_addr,
        }
    }

    fn try_admit(self: &Arc<Self>, ip: IpAddr) -> Result<ConnGuard, Refusal> {
        let permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Refusal::ServerFull)?;
        let key = limit_key(ip);
        let mut per_addr = self.per_addr.lock().unwrap_or_else(PoisonError::into_inner);
        let count = per_addr.entry(key).or_insert(0);
        if *count >= self.max_per_addr {
            return Err(Refusal::PerAddressLimit);
        }
        *count += 1;
        Ok(ConnGuard {
            limits: self.clone(),
            key,
            _permit: permit,
        })
    }

    fn open(&self) -> usize {
        self.max_total as usize - self.slots.available_permits()
    }

    /// Wait (up to `grace`) until every connection slot has been given back.
    async fn drain(&self, grace: Duration) -> bool {
        matches!(
            timeout(grace, self.slots.acquire_many(self.max_total)).await,
            Ok(Ok(_))
        )
    }
}

/// One open connection's claim on [`ConnLimits`]; released on drop.
struct ConnGuard {
    limits: Arc<ConnLimits>,
    key: IpAddr,
    _permit: OwnedSemaphorePermit,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut per_addr = self
            .limits
            .per_addr
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = per_addr.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                per_addr.remove(&self.key);
            }
        }
    }
}

/// Coalesces `ip_denied` history rows. The accept loop only bumps an
/// in-memory counter ([`DenyLog::note`]); a background task writes the rows:
/// the first denial from an address right away, then at most one row per
/// address per [`DENY_LOG_WINDOW`] carrying the count.
struct DenyLog {
    state: Mutex<DenyState>,
    wake: Notify,
}

#[derive(Default)]
struct DenyState {
    per_addr: HashMap<IpAddr, DenyEntry>,
    /// Denials from addresses beyond [`DENY_LOG_MAX_TRACKED`].
    overflow: u64,
    overflow_written: Option<Instant>,
}

struct DenyEntry {
    note: String,
    pending: u64,
    last_written: Option<Instant>,
}

impl DenyLog {
    fn new() -> Self {
        Self {
            state: Mutex::new(DenyState::default()),
            wake: Notify::new(),
        }
    }

    /// Start the writer task and return the handle the accept loop feeds.
    /// The task holds the server context weakly and ends with it.
    fn spawn_writer(ctx: &Arc<ServerCtx>) -> Arc<Self> {
        let log = Arc::new(Self::new());
        let writer = log.clone();
        let ctx: Weak<ServerCtx> = Arc::downgrade(ctx);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = writer.wake.notified() => {}
                    _ = tokio::time::sleep(DENY_LOG_POLL) => {}
                }
                let rows = writer.take_due(Instant::now());
                let Some(ctx) = ctx.upgrade() else { break };
                for detail in rows {
                    warn!(%detail, "connection(s) denied by IP rule");
                    ctx.history
                        .record_detached(unix_now(), None, "ip_denied", &detail);
                }
            }
        });
        log
    }

    /// Count one denied connection. Synchronous and O(1): fit for the
    /// accept path.
    fn note(&self, ip: IpAddr, note: &str) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = state.per_addr.get_mut(&ip) {
            entry.pending += 1;
            return;
        }
        if state.per_addr.len() >= DENY_LOG_MAX_TRACKED {
            state.overflow += 1;
            let first = state.overflow_written.is_none();
            drop(state);
            if first {
                self.wake.notify_one();
            }
            return;
        }
        let note = kdx_server_core::limits::truncate_utf8(note, DENY_LOG_NOTE_LEN).to_string();
        state.per_addr.insert(
            ip,
            DenyEntry {
                note,
                pending: 1,
                last_written: None,
            },
        );
        drop(state);
        self.wake.notify_one();
    }

    /// The history rows due at `now`, marking them written. An address
    /// quiet for a whole window is forgotten, so its next denial is again
    /// reported right away.
    fn take_due(&self, now: Instant) -> Vec<String> {
        let window = DENY_LOG_WINDOW.as_secs();
        let mut rows = Vec::new();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.per_addr.retain(|ip, entry| match entry.last_written {
            None => {
                rows.push(if entry.pending > 1 {
                    format!("peer={ip}, note={}, connections={}", entry.note, entry.pending)
                } else {
                    format!("peer={ip}, note={}", entry.note)
                });
                entry.pending = 0;
                entry.last_written = Some(now);
                true
            }
            Some(at) if now.saturating_duration_since(at) >= DENY_LOG_WINDOW => {
                if entry.pending == 0 {
                    return false;
                }
                rows.push(format!(
                    "peer={ip}, note={}, connections={} in the last {window}s",
                    entry.note, entry.pending
                ));
                entry.pending = 0;
                entry.last_written = Some(now);
                true
            }
            Some(_) => true,
        });
        let overflow_due = match state.overflow_written {
            None => true,
            Some(at) => now.saturating_duration_since(at) >= DENY_LOG_WINDOW,
        };
        if state.overflow > 0 && overflow_due {
            rows.push(format!(
                "peer=(other addresses), connections={}; too many denied addresses to list individually",
                state.overflow
            ));
            state.overflow = 0;
            state.overflow_written = Some(now);
        }
        rows
    }
}

fn build_tls_config(
    tls: Option<&TlsConfig>,
    cert_cache: &std::path::Path,
) -> Result<TlsServerConfig, ServeError> {
    let (certs, key) = match tls {
        Some(paths) => load_pem(paths)?,
        None => self_signed(cert_cache)?,
    };
    // An explicit provider (no reliance on a process-wide default) and
    // TLS 1.3 only, as the protocol spec promises.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = TlsServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
    Ok(config)
}

fn load_pem(
    paths: &TlsConfig,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ServeError> {
    let cert_file = std::fs::File::open(&paths.cert_pem).map_err(ServeError::Pem)?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
        .collect::<Result<_, _>>()
        .map_err(ServeError::Pem)?;
    let key_file = std::fs::File::open(&paths.key_pem).map_err(ServeError::Pem)?;
    warn_if_world_readable(&paths.key_pem, &key_file);
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))
        .map_err(ServeError::Pem)?
        .ok_or(ServeError::NoKey)?;
    Ok((certs, key))
}

/// Operator-supplied keys are only warned about (group-readable keys are a
/// common, deliberate setup, e.g. an `ssl-cert` group); world-readable is
/// never right.
#[cfg(unix)]
fn warn_if_world_readable(path: &Path, file: &std::fs::File) {
    use std::os::unix::fs::MetadataExt;
    if let Ok(meta) = file.metadata() {
        if meta.mode() & 0o007 != 0 {
            warn!(
                path = %path.display(),
                mode = format!("{:04o}", meta.mode() & 0o7777),
                "TLS private key is accessible to every local user; chmod o-rwx it"
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_world_readable(_path: &Path, _file: &std::fs::File) {}

const DEV_CERT_FILE: &str = "dev-cert.der";
const DEV_KEY_FILE: &str = "dev-key.der";

/// Load a cached self-signed dev cert from `cache_dir`, or generate one and
/// persist it there. Persisting keeps the server's identity stable across
/// restarts, so clients that pinned it (trust-on-first-use) stay trusted.
///
/// A cached key is only reused if it is a regular file owned by this user
/// and inaccessible to anyone else; otherwise someone else may know it (or
/// planted it), and serving it would let them impersonate the server, so
/// startup fails with instructions instead.
fn self_signed(
    cache_dir: &std::path::Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ServeError> {
    let cert_path = cache_dir.join(DEV_CERT_FILE);
    let key_path = cache_dir.join(DEV_KEY_FILE);

    match std::fs::symlink_metadata(&key_path) {
        Ok(meta) => {
            check_cached_key(&key_path, &meta)?;
            match (std::fs::read(&cert_path), std::fs::read(&key_path)) {
                (Ok(cert_bytes), Ok(key_bytes)) => match PrivateKeyDer::try_from(key_bytes) {
                    Ok(key) => {
                        info!(path = %cert_path.display(), "reusing cached dev certificate");
                        return Ok((vec![CertificateDer::from(cert_bytes)], key));
                    }
                    Err(_) => warn!("cached dev key is not a valid key; replacing it"),
                },
                _ => warn!("cached dev certificate is incomplete; replacing it"),
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(ServeError::Io(e)),
    }

    warn!("generating self-signed dev certificate (cached for future restarts)");
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = certified.cert.der().to_vec();
    let key_der = certified.key_pair.serialize_der();
    create_private_dir(cache_dir)?;
    // Key first: a crash in between leaves a key with no cert, which the
    // next start replaces — never a cert whose key is missing.
    write_private_file(&key_path, &key_der)?;
    write_private_file(&cert_path, &cert_der)?;

    let key = PrivateKeyDer::try_from(key_der).expect("rcgen emits valid pkcs8");
    Ok((vec![CertificateDer::from(cert_der)], key))
}

#[cfg(unix)]
fn check_cached_key(path: &Path, meta: &std::fs::Metadata) -> Result<(), ServeError> {
    use std::os::unix::fs::MetadataExt;
    let euid = crate::sys::effective_uid();
    let problem = if meta.file_type().is_symlink() {
        "is a symlink".to_string()
    } else if !meta.is_file() {
        "is not a regular file".to_string()
    } else if meta.uid() != euid {
        format!("is owned by uid {}, not by this process (uid {euid})", meta.uid())
    } else if meta.mode() & 0o077 != 0 {
        format!(
            "has mode {:04o}: other local users may have read it",
            meta.mode() & 0o7777
        )
    } else {
        return Ok(());
    };
    Err(ServeError::InsecureKey(format!(
        "{} {problem}. Delete {DEV_KEY_FILE} and {DEV_CERT_FILE} in that directory to \
         generate a new server identity (clients that pinned the old one will warn), or, \
         if you are sure the key was never exposed, make it a regular file owned by the \
         server user with mode 0600",
        path.display()
    )))
}

#[cfg(not(unix))]
fn check_cached_key(_path: &Path, _meta: &std::fs::Metadata) -> Result<(), ServeError> {
    Ok(())
}

/// Create `dir` (and missing parents) accessible to this user only. An
/// existing directory is left as it is.
fn create_private_dir(dir: &Path) -> io::Result<()> {
    if dir.as_os_str().is_empty() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Atomically replace `path` with `bytes`, mode 0600: write a fresh temp
/// file next to it (never following a symlink planted there), fsync, rename.
fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(".tmp");
    let tmp = dir.join(tmp_name);
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options.open(&tmp).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    });
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written?;
    // Make the rename itself durable (best-effort; not possible on Windows).
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn emfile() -> io::Error {
        io::Error::from_raw_os_error(24) // EMFILE on Linux and macOS
    }

    #[test]
    fn backoff_doubles_to_a_cap_and_resets() {
        let now = Instant::now();
        let mut backoff = AcceptBackoff::default();
        let delays: Vec<u64> = (0..7)
            .map(|_| backoff.on_error(&emfile(), now).as_millis() as u64)
            .collect();
        assert_eq!(delays, [50, 100, 200, 400, 800, 1000, 1000]);
        backoff.reset();
        assert_eq!(backoff.on_error(&emfile(), now), ACCEPT_BACKOFF_MIN);
    }

    #[test]
    fn per_connection_accept_errors_get_no_delay() {
        let now = Instant::now();
        let mut backoff = AcceptBackoff::default();
        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionRefused,
        ] {
            assert_eq!(backoff.on_error(&kind.into(), now), Duration::ZERO);
        }
        // ...and they don't advance the backoff either.
        assert_eq!(backoff.on_error(&emfile(), now), ACCEPT_BACKOFF_MIN);
    }

    #[tokio::test(start_paused = true)]
    async fn accept_sleeps_between_persistent_failures() {
        let start = Instant::now();
        let mut failures = 0;
        let mut backoff = AcceptBackoff::default();
        let got = accept_with_backoff(
            || {
                failures += 1;
                let result = if failures <= 5 { Err(emfile()) } else { Ok(failures) };
                async move { result }
            },
            &mut backoff,
        )
        .await;
        assert_eq!(got, 6);
        // 50 + 100 + 200 + 400 + 800 ms of (virtual) sleeping, not a spin.
        assert!(start.elapsed() >= Duration::from_millis(1550), "{:?}", start.elapsed());
        // Success resets the backoff.
        assert_eq!(backoff.next, ACCEPT_BACKOFF_MIN);
    }

    #[test]
    fn log_throttle_lets_one_line_through_per_period() {
        let t0 = Instant::now();
        let mut log = LogThrottle::new(Duration::from_secs(5));
        assert_eq!(log.allow(t0), Some(0));
        assert_eq!(log.allow(t0 + Duration::from_secs(1)), None);
        assert_eq!(log.allow(t0 + Duration::from_secs(4)), None);
        assert_eq!(log.allow(t0 + Duration::from_secs(5)), Some(2));
        assert_eq!(log.allow(t0 + Duration::from_secs(6)), None);
    }

    #[test]
    fn ipv4_mapped_peers_are_canonicalised() {
        let mapped: SocketAddr = "[::ffff:203.0.113.7]:4000".parse().unwrap();
        assert_eq!(canonical_peer(mapped), "203.0.113.7:4000".parse().unwrap());
        let v6: SocketAddr = "[2001:db8::1]:4000".parse().unwrap();
        assert_eq!(canonical_peer(v6), v6);
    }

    #[test]
    fn conn_limits_enforce_global_and_per_address_caps() {
        let limits = Arc::new(ConnLimits::new(3, 2));
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let a1 = limits.try_admit(a).unwrap();
        let a2 = limits.try_admit(a).unwrap();
        assert_eq!(limits.try_admit(a).err(), Some(Refusal::PerAddressLimit));
        let b1 = limits.try_admit(b).unwrap();
        assert_eq!(limits.open(), 3);
        assert_eq!(limits.try_admit(b).err(), Some(Refusal::ServerFull));
        drop(a1);
        assert_eq!(limits.open(), 2);
        let a3 = limits.try_admit(a).unwrap();
        drop((a2, a3, b1));
        assert_eq!(limits.open(), 0);
        assert!(limits.per_addr.lock().unwrap().is_empty());
    }

    #[test]
    fn ipv6_addresses_share_a_per_64_limit() {
        let limits = Arc::new(ConnLimits::new(10, 1));
        let _first = limits.try_admit("2001:db8:1:2::1".parse().unwrap()).unwrap();
        assert_eq!(
            limits.try_admit("2001:db8:1:2::ffff".parse().unwrap()).err(),
            Some(Refusal::PerAddressLimit)
        );
        limits.try_admit("2001:db8:1:3::1".parse().unwrap()).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn drain_waits_for_connections_up_to_the_grace_period() {
        let limits = Arc::new(ConnLimits::new(4, 4));
        assert!(limits.drain(Duration::from_millis(10)).await);
        let guard = limits.try_admit("192.0.2.1".parse().unwrap()).unwrap();
        assert!(!limits.drain(Duration::from_secs(5)).await);
        let releaser = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            drop(guard);
        });
        assert!(limits.drain(Duration::from_secs(5)).await);
        releaser.await.unwrap();
    }

    #[test]
    fn deny_log_writes_one_row_per_address_per_window() {
        let t0 = Instant::now();
        let log = DenyLog::new();
        let a: IpAddr = "198.51.100.7".parse().unwrap();
        let b: IpAddr = "198.51.100.8".parse().unwrap();
        for _ in 0..200 {
            log.note(a, "abuse");
        }
        log.note(b, "abuse");
        let mut rows = log.take_due(t0);
        rows.sort();
        assert_eq!(
            rows,
            [
                "peer=198.51.100.7, note=abuse, connections=200",
                "peer=198.51.100.8, note=abuse",
            ]
        );

        // More denials inside the window: counted, not written.
        for _ in 0..50 {
            log.note(a, "abuse");
        }
        assert!(log.take_due(t0 + Duration::from_secs(60)).is_empty());

        // Window over: one summary row for `a`; quiet `b` is forgotten.
        let rows = log.take_due(t0 + DENY_LOG_WINDOW);
        assert_eq!(rows, ["peer=198.51.100.7, note=abuse, connections=50 in the last 600s"]);
        assert!(!log.state.lock().unwrap().per_addr.contains_key(&b));

        // A forgotten address is reported right away again.
        log.note(b, "abuse");
        assert_eq!(
            log.take_due(t0 + DENY_LOG_WINDOW + Duration::from_secs(1)),
            ["peer=198.51.100.8, note=abuse"]
        );
    }

    #[test]
    fn deny_log_pools_addresses_beyond_the_tracking_cap() {
        let t0 = Instant::now();
        let log = DenyLog::new();
        for i in 0..(DENY_LOG_MAX_TRACKED as u32 + 500) {
            log.note(IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + i)), "x");
        }
        let rows = log.take_due(t0);
        assert_eq!(rows.len(), DENY_LOG_MAX_TRACKED + 1);
        assert!(rows.iter().any(|r| r.contains("other addresses") && r.contains("connections=500")));
        // The pooled counter is also rate-limited to once per window.
        log.note("192.0.2.200".parse().unwrap(), "x");
        assert!(log.take_due(t0 + Duration::from_secs(1)).is_empty());
    }
}
