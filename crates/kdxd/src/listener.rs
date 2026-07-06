use std::net::SocketAddr;
use std::sync::Arc;
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
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

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
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A running server: its bound address, shared context, and the accept-loop
/// task handle.
pub struct Server {
    pub local_addr: SocketAddr,
    pub ctx: Arc<ServerCtx>,
    pub handle: tokio::task::JoinHandle<()>,
}

/// Bind the listener and spawn the accept loop. Returns once bound, so
/// callers (including tests) know the server is reachable and on which port.
pub async fn serve(config: Config) -> Result<Server, ServeError> {
    // Cache the dev cert next to the database so restarts keep the same
    // server identity (clients that pinned it stay trusted).
    let cert_cache = config
        .database
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
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
        settings: ServerSettings::new(
            config.server_name.clone(),
            config.server_description.clone(),
            config.max_users,
        ),
        bind_port: local_addr.port(),
        shutdown: Arc::new(Notify::new()),
    });
    info!(%local_addr, "kdxd listening");

    // Register this server in its own tracker directory and keep the entry
    // fresh (and its live user count / settings current) with a periodic
    // heartbeat.
    spawn_self_registration(&ctx, local_addr);

    let accept_ctx = ctx.clone();
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                // AdminShutdown notifies this to stop taking new connections.
                // Already-open connections close on their own as the
                // presence-wide Disconnect it also sent gets processed.
                _ = accept_ctx.shutdown.notified() => {
                    info!("shutdown requested; accept loop stopping");
                    break;
                }
                accepted = listener.accept() => {
                    let (tcp, peer) = match accepted {
                        Ok(pair) => pair,
                        Err(e) => {
                            error!(error = %e, "accept failed");
                            continue;
                        }
                    };
                    // Allow-Deny IP rules: match before TLS so a denied
                    // peer burns zero handshake work. `match_ip` is a
                    // scan of a small in-memory cache; the sockaddr's IP
                    // is what the rules apply to, not the port.
                    let verdict = accept_ctx.ip_rules.match_ip(peer.ip()).await;
                    if let Verdict::Deny { note } = verdict {
                        warn!(%peer, note = %note, "connection denied by IP rule");
                        let _ = accept_ctx
                            .history
                            .record(
                                unix_now(),
                                None,
                                "ip_denied",
                                &format!("peer={}, note={}", peer.ip(), note),
                            )
                            .await;
                        // Close the socket immediately (drop it) — we do
                        // not want to send anything back, since even that
                        // hint would help someone probe for the ban.
                        drop(tcp);
                        continue;
                    }
                    let acceptor = acceptor.clone();
                    let conn_ctx = accept_ctx.clone();
                    tokio::spawn(async move {
                        let tls = match acceptor.accept(tcp).await {
                            Ok(tls) => tls,
                            Err(e) => {
                                warn!(%peer, error = %e, "tls handshake failed");
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
    })
}

/// Register this server in its own in-process tracker and keep the entry fresh
/// with a heartbeat every 30s (well within the 90s TTL), reading `settings`
/// and the live user count fresh each tick — so an admin's `ServerSettingsUpdate`
/// (name/description/max_users) shows up in the tracker directory within one
/// heartbeat, without restarting anything.
fn spawn_self_registration(ctx: &Arc<ServerCtx>, local_addr: SocketAddr) {
    let host = if local_addr.ip().is_unspecified() {
        "127.0.0.1".to_string()
    } else {
        local_addr.ip().to_string()
    };
    let port = local_addr.port();
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

fn build_tls_config(
    tls: Option<&TlsConfig>,
    cert_cache: &std::path::Path,
) -> Result<TlsServerConfig, ServeError> {
    let (certs, key) = match tls {
        Some(paths) => load_pem(paths)?,
        None => self_signed(cert_cache)?,
    };
    let config = TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
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
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))
        .map_err(ServeError::Pem)?
        .ok_or(ServeError::NoKey)?;
    Ok((certs, key))
}

/// Load a cached self-signed dev cert from `cache_dir`, or generate one and
/// persist it there. Persisting keeps the server's identity stable across
/// restarts, so clients that pinned it (trust-on-first-use) stay trusted.
fn self_signed(
    cache_dir: &std::path::Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ServeError> {
    let cert_path = cache_dir.join("dev-cert.der");
    let key_path = cache_dir.join("dev-key.der");

    if let (Ok(cert_bytes), Ok(key_bytes)) =
        (std::fs::read(&cert_path), std::fs::read(&key_path))
    {
        if let Ok(key) = PrivateKeyDer::try_from(key_bytes) {
            info!("reusing cached dev certificate");
            return Ok((vec![CertificateDer::from(cert_bytes)], key));
        }
    }

    warn!("generating self-signed dev certificate (cached for future restarts)");
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = certified.cert.der().to_vec();
    let key_der = certified.key_pair.serialize_der();
    let _ = std::fs::create_dir_all(cache_dir);
    let _ = std::fs::write(&cert_path, &cert_der);
    let _ = std::fs::write(&key_path, &key_der);

    let key = PrivateKeyDer::try_from(key_der).expect("rcgen emits valid pkcs8");
    Ok((vec![CertificateDer::from(cert_der)], key))
}
