use std::net::SocketAddr;
use std::sync::Arc;

use kdx_server_core::Connection;
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
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A running server: its bound address and the accept-loop task handle.
pub struct Server {
    pub local_addr: SocketAddr,
    pub handle: tokio::task::JoinHandle<()>,
}

/// Bind the listener and spawn the accept loop. Returns once bound, so
/// callers (including tests) know the server is reachable and on which port.
pub async fn serve(config: Config) -> Result<Server, ServeError> {
    let tls_config = build_tls_config(config.tls.as_ref())?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(config.bind).await?;
    let local_addr = listener.local_addr()?;
    info!(%local_addr, "kdxd listening");

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
            tokio::spawn(async move {
                let tls = match acceptor.accept(tcp).await {
                    Ok(tls) => tls,
                    Err(e) => {
                        warn!(%peer, error = %e, "tls handshake failed");
                        return;
                    }
                };
                if let Err(e) = Connection::new(tls).run().await {
                    warn!(%peer, error = %e, "connection ended with error");
                }
            });
        }
    });

    Ok(Server { local_addr, handle })
}

fn build_tls_config(tls: Option<&TlsConfig>) -> Result<TlsServerConfig, ServeError> {
    let (certs, key) = match tls {
        Some(paths) => load_pem(paths)?,
        None => {
            warn!("no TLS certs configured; generating self-signed dev certificate");
            self_signed()?
        }
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

fn self_signed() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ServeError> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::try_from(certified.key_pair.serialize_der())
        .expect("rcgen emits valid pkcs8");
    Ok((vec![cert], key))
}
