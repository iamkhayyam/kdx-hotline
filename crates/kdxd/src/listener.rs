use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use kdx_server_core::auth::AuthManager;
use kdx_server_core::chat::RoomManager;
use kdx_server_core::files::FileTree;
use kdx_server_core::transfer::{TransferConfig, TransferManager};
use kdx_server_core::{Connection, ServerCtx};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig as TlsServerConfig;
use tokio::net::TcpListener;
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
    let ctx = Arc::new(ServerCtx {
        auth: AuthManager::new(pool, Duration::from_secs(config.session_ttl_secs)),
        rooms: RoomManager::new(),
        tree,
        transfers,
    });

    let listener = TcpListener::bind(config.bind).await?;
    let local_addr = listener.local_addr()?;
    info!(%local_addr, "kdxd listening");

    let accept_ctx = ctx.clone();
    let handle = tokio::spawn(async move {
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    error!(error = %e, "accept failed");
                    continue;
                }
            };
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
                if let Err(e) = Connection::new(tls, conn_ctx).run().await {
                    warn!(%peer, error = %e, "connection ended with error");
                }
            });
        }
    });

    Ok(Server {
        local_addr,
        ctx,
        handle,
    })
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
