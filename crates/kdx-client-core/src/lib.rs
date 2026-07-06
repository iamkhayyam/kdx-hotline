//! KDX client library. A pure-async connection to a kdxd server with zero UI
//! dependencies, so it can be driven headlessly in tests and wrapped by a
//! thin Tauri shell for the desktop app.
//!
//! ```ignore
//! let (client, mut events) = kdx_client_core::connect(cfg).await?;
//! client.login("phraq", "s3cret").await?;
//! client.join("lobby").await?;
//! while let Some(event) = events.recv().await { /* ... */ }
//! ```

mod actor;
mod config;
mod error;
mod event;
mod handle;
mod tls;
mod transfer;

use std::sync::Arc;

use futures_util::SinkExt;
use kdx_protocol::messages::{HandshakeInit, HandshakeResp};
use kdx_protocol::{KdxCodec, KdxFrame, PacketFlags, PacketHeader, PacketType, PROTOCOL_VERSION};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_util::codec::Framed;

pub use config::{ClientConfig, TrustPolicy};
pub use error::ClientError;
pub use event::{
    AccountSummary, Direction, Event, NewsPost, NewsgroupInfo, PresenceUser, RoleInfo,
    TrackerServer,
};
pub use handle::{ClientHandle, Session};
// Re-exported so consumers (the Tauri app) can name the file-listing shape
// returned by list_files / create_folder / delete_path.
pub use kdx_protocol::messages::FileListResponse;
pub use tls::{spki_fingerprint, KnownHosts};

use actor::Actor;
use futures_util::StreamExt;

/// Depth of the command and event channels.
const CHANNEL_DEPTH: usize = 256;

/// Connect to a KDX server: TCP + TLS (per the trust policy) + KDX version
/// handshake. On success returns a handle and an event stream, and emits an
/// initial [`Event::Connected`].
pub async fn connect(
    config: ClientConfig,
) -> Result<(ClientHandle, mpsc::Receiver<Event>), ClientError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let known_hosts = KnownHosts::new(&config.data_dir);

    // Build the rustls verifier per policy; keep a slot to read the presented
    // fingerprint after the handshake (or after a TOFU rejection).
    let (tls_config, seen_slot) = build_tls_config(&provider, &config, &known_hosts)?;
    let connector = TlsConnector::from(Arc::new(tls_config));

    let server_name = rustls::pki_types::ServerName::try_from(config.host.clone())
        .map_err(|_| ClientError::InvalidServerName(config.host.clone()))?;
    let tcp = TcpStream::connect((config.host.as_str(), config.port)).await?;

    let tls = match connector.connect(server_name, tcp).await {
        Ok(tls) => tls,
        Err(e) => {
            // A TOFU rejection surfaces here; translate it using the observed
            // fingerprint and any previously pinned value.
            if let Some(seen) = seen_slot.and_then(|s| s.lock().unwrap().clone()) {
                let previous = known_hosts.get(&config.host, config.port);
                return Err(ClientError::UntrustedCertificate {
                    host: config.host.clone(),
                    fingerprint: seen,
                    previous,
                });
            }
            return Err(ClientError::Tls(e.to_string()));
        }
    };

    let fingerprint = known_hosts
        .get(&config.host, config.port)
        .unwrap_or_default();

    let mut framed = Framed::new(tls, KdxCodec::default());
    kdx_handshake(&mut framed).await?;

    let (cmd_tx, cmd_rx) = mpsc::channel(CHANNEL_DEPTH);
    let (event_tx, event_rx) = mpsc::channel(CHANNEL_DEPTH);

    let actor = Actor::new(framed, cmd_rx, event_tx.clone());
    tokio::spawn(actor.run());

    let _ = event_tx.send(Event::Connected { fingerprint }).await;
    Ok((ClientHandle { tx: cmd_tx }, event_rx))
}

/// Pin a server's fingerprint so a subsequent TOFU connect will trust it.
pub fn trust_server(
    data_dir: &std::path::Path,
    host: &str,
    port: u16,
    fingerprint: &str,
) -> Result<(), ClientError> {
    KnownHosts::new(data_dir).pin(host, port, fingerprint)
}

type SeenSlot = Option<Arc<std::sync::Mutex<Option<String>>>>;

fn build_tls_config(
    provider: &Arc<rustls::crypto::CryptoProvider>,
    config: &ClientConfig,
    known_hosts: &KnownHosts,
) -> Result<(rustls::ClientConfig, SeenSlot), ClientError> {
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| ClientError::Tls(e.to_string()))?;

    match &config.trust {
        TrustPolicy::Tofu => {
            let expected = known_hosts.get(&config.host, config.port);
            let verifier = tls::TofuVerifier::new(provider.clone(), expected);
            let slot = verifier.seen_slot();
            let cfg = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth();
            Ok((cfg, Some(slot)))
        }
        TrustPolicy::System => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots_or_empty());
            let cfg = builder.with_root_certificates(roots).with_no_client_auth();
            Ok((cfg, None))
        }
        #[cfg(feature = "dangerous")]
        TrustPolicy::InsecureAcceptAny => {
            let verifier = tls::AcceptAnyVerifier::new(provider.clone());
            let slot = verifier.seen_slot();
            let cfg = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth();
            Ok((cfg, Some(slot)))
        }
    }
}

/// System policy without the `webpki-roots` crate has no bundled roots; the
/// OS store would be wired here in a real deployment. For now it's empty,
/// which means System policy rejects everything unless roots are added — TOFU
/// is the working default for KDX.
fn webpki_roots_or_empty() -> Vec<rustls::pki_types::TrustAnchor<'static>> {
    Vec::new()
}

async fn kdx_handshake<S>(framed: &mut Framed<S, KdxCodec>) -> Result<(), ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let init = HandshakeInit {
        version: PROTOCOL_VERSION,
        features: 0,
    };
    let header = PacketHeader {
        version: PROTOCOL_VERSION,
        packet_type: PacketType::HandshakeInit,
        flags: PacketFlags::empty(),
        sequence: 0,
        length: init.encode().len() as u32,
    };
    framed
        .send(KdxFrame {
            header,
            payload: init.encode(),
        })
        .await?;

    let frame = framed
        .next()
        .await
        .ok_or(ClientError::Disconnected)??;
    if frame.header.packet_type != PacketType::HandshakeResp {
        return Err(ClientError::HandshakeRejected);
    }
    let resp = HandshakeResp::decode(&frame.payload)?;
    if resp.version != PROTOCOL_VERSION {
        return Err(ClientError::HandshakeRejected);
    }
    Ok(())
}
