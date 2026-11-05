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
mod local_name;
#[cfg(test)]
mod login_tests;
mod tls;
mod transfer;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use futures_util::SinkExt;
use kdx_protocol::messages::{HandshakeInit, HandshakeResp};
use kdx_protocol::{KdxCodec, KdxFrame, PacketFlags, PacketHeader, PacketType, PROTOCOL_VERSION};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_util::codec::Framed;
use tracing::warn;

pub use config::{
    ClientConfig, TrustPolicy, DEFAULT_CONNECT_TIMEOUT, DEFAULT_KEEPALIVE, DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_STALE_PARTIAL_AGE, DEFAULT_WRITE_TIMEOUT,
};
pub use error::ClientError;
pub use event::{
    AccountSummary, BanEntry, BanList, Direction, Event, FileSearchEntry, HistoryEntry, IpRule,
    NewsPost, NewsgroupInfo, PresenceUser, RoleInfo, ServerSettings, TrackerServer,
};
pub use handle::{ClientHandle, Session};
// Re-exported so consumers (the Tauri app) can name the file-listing shape
// returned by list_files / create_folder / delete_path.
pub use kdx_protocol::messages::{FileInfoResponse, FileListResponse};
pub use local_name::safe_local_file_name;
pub use tls::{spki_fingerprint, KnownHosts};
pub use transfer::TRANSFERS_DIR;

use actor::{Actor, ActorOptions};
use futures_util::StreamExt;

/// Depth of the command and event channels.
const CHANNEL_DEPTH: usize = 256;

/// ALPN protocol id offered during the TLS handshake (servers that don't
/// speak ALPN simply ignore it).
const KDX_ALPN: &[u8] = b"kdx/1";

/// Connect to a KDX server: TCP + TLS (per the trust policy) + KDX version
/// handshake, all within `config.connect_timeout`. On success returns a
/// handle and an event stream, and emits an initial [`Event::Connected`]
/// carrying the SPKI fingerprint of the certificate actually verified.
///
/// Fails with `ClientError::UntrustedCertificate` only when the TOFU check
/// itself refused the server's key (`previous` is the pin it was compared
/// with); any other handshake failure is `ClientError::Tls`. A
/// `known_hosts.toml` that can't be read is `ClientError::KnownHosts`.
///
/// Partial downloads in `config.data_dir` that nothing has touched for
/// `config.stale_partial_age` are deleted first.
pub async fn connect(
    config: ClientConfig,
) -> Result<(ClientHandle, mpsc::Receiver<Event>), ClientError> {
    let transfers_dir = config.data_dir.join(transfer::TRANSFERS_DIR);
    if let Some(max_age) = config.stale_partial_age {
        // Before any download of this connection can start, so a resume
        // never races the sweep. A failure only means nothing was swept.
        let dir = transfers_dir.clone();
        let swept = tokio::task::spawn_blocking(move || {
            transfer::sweep_stale_partials(&dir, max_age, std::time::SystemTime::now())
        })
        .await;
        match swept {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => tracing::info!("removed {n} stale partial download(s)"),
            Ok(Err(e)) => warn!("could not sweep stale partial downloads: {e}"),
            Err(e) => warn!("could not sweep stale partial downloads: {e}"),
        }
    }

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let known_hosts = KnownHosts::new(&config.data_dir);

    // Build the rustls verifier per policy; keep a slot to read what the
    // verifier saw and decided.
    let (tls_config, outcome_slot, expected) = build_tls_config(&provider, &config, &known_hosts)?;
    let connector = TlsConnector::from(Arc::new(tls_config));

    let server_name = rustls::pki_types::ServerName::try_from(config.host.clone())
        .map_err(|_| ClientError::InvalidServerName(config.host.clone()))?;
    let deadline = Instant::now() + bounded(config.connect_timeout, Duration::ZERO);
    let tcp = within(
        deadline,
        "connect",
        TcpStream::connect((config.host.as_str(), config.port)),
    )
    .await??;

    let tls = match within(deadline, "TLS handshake", connector.connect(server_name, tcp)).await? {
        Ok(tls) => tls,
        Err(e) => {
            // Only the verifier's own refusal is a trust decision; anything
            // else (a reset, a bad signature, a protocol error) is plain TLS
            // failure and must not be reported as "the key changed".
            if let Some(outcome) = outcome_slot.as_ref().map(tls::read_outcome) {
                if let (true, Some(seen)) = (outcome.rejected, outcome.seen) {
                    return Err(ClientError::UntrustedCertificate {
                        host: config.host.clone(),
                        fingerprint: seen,
                        previous: expected,
                    });
                }
            }
            return Err(ClientError::Tls(e.to_string()));
        }
    };

    // The fingerprint of the certificate this session actually verified.
    let fingerprint = match outcome_slot.as_ref().map(tls::read_outcome) {
        Some(outcome) => {
            let seen = outcome.seen.unwrap_or_default();
            if outcome.legacy_match {
                // Upgrade a whole-certificate pin to the SPKI form.
                if let Err(e) = known_hosts.pin(&config.host, config.port, &seen) {
                    warn!("could not migrate the pinned fingerprint: {e}");
                }
            }
            seen
        }
        None => tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(spki_fingerprint)
            .unwrap_or_default(),
    };

    // Login proofs are bound to this TLS session, so a server can't relay
    // our login to another server (see kdx_crypto::scram).
    let channel_binding = tls
        .get_ref()
        .1
        .export_keying_material(
            [0u8; kdx_crypto::CHANNEL_BINDING_LEN],
            kdx_crypto::TLS_EXPORTER_LABEL,
            None,
        )
        .map_err(|e| ClientError::Tls(e.to_string()))?;

    let mut framed = Framed::new(tls, KdxCodec::default());
    within(deadline, "KDX handshake", kdx_handshake(&mut framed)).await??;

    let (cmd_tx, cmd_rx) = mpsc::channel(CHANNEL_DEPTH);
    let (event_tx, event_rx) = mpsc::channel(CHANNEL_DEPTH);

    let _ = event_tx.send(Event::Connected { fingerprint }).await;
    let options = ActorOptions {
        keepalive: bounded(config.keepalive, Duration::from_secs(1)),
        request_timeout: bounded(config.request_timeout, Duration::ZERO),
        write_timeout: bounded(config.write_timeout, Duration::ZERO),
        server_id: format!("{}:{}", config.host, config.port),
        transfers_dir: Some(transfers_dir),
        ..ActorOptions::default()
    };
    let actor = Actor::new(framed, cmd_rx, event_tx.clone())
        .with_options(options)
        .with_channel_binding(channel_binding);
    let handle = actor.spawn(cmd_tx);
    Ok((handle, event_rx))
}

/// Keep a configured duration within `[min, 1 day]` so deadline arithmetic
/// can't overflow (and a zero keepalive can't spin).
fn bounded(d: Duration, min: Duration) -> Duration {
    d.clamp(min, Duration::from_secs(24 * 60 * 60))
}

/// Run `future` unless `deadline` passes first.
async fn within<F: Future>(
    deadline: Instant,
    what: &str,
    future: F,
) -> Result<F::Output, ClientError> {
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| ClientError::Timeout(format!("{what} timed out")))
}

/// Pin a server's fingerprint so a subsequent TOFU connect will trust it.
/// `host` must be a valid DNS name or IP address and `fingerprint` a
/// `sha256:<base64>` value as reported by `ClientError::UntrustedCertificate`.
pub fn trust_server(
    data_dir: &std::path::Path,
    host: &str,
    port: u16,
    fingerprint: &str,
) -> Result<(), ClientError> {
    KnownHosts::new(data_dir).pin(host, port, fingerprint)
}

type BuiltTls = (rustls::ClientConfig, Option<tls::OutcomeSlot>, Option<String>);

fn build_tls_config(
    provider: &Arc<rustls::crypto::CryptoProvider>,
    config: &ClientConfig,
    known_hosts: &KnownHosts,
) -> Result<BuiltTls, ClientError> {
    // TLS 1.3 only.
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ClientError::Tls(e.to_string()))?;

    let (mut cfg, slot, expected) = match &config.trust {
        TrustPolicy::Tofu => {
            // An unreadable pin file refuses the connect (never "unpinned").
            let expected = known_hosts.get(&config.host, config.port)?;
            let verifier = tls::TofuVerifier::new(provider.clone(), expected.clone());
            let slot = verifier.outcome_slot();
            let cfg = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth();
            (cfg, Some(slot), expected)
        }
        TrustPolicy::System => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots_or_empty());
            let cfg = builder.with_root_certificates(roots).with_no_client_auth();
            (cfg, None, None)
        }
        #[cfg(feature = "dangerous")]
        TrustPolicy::InsecureAcceptAny => {
            let verifier = tls::AcceptAnyVerifier::new(provider.clone());
            let slot = verifier.outcome_slot();
            let cfg = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth();
            (cfg, Some(slot), None)
        }
    };
    cfg.alpn_protocols = vec![KDX_ALPN.to_vec()];
    Ok((cfg, slot, expected))
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
