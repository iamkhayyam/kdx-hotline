//! C1 TOFU behavior: first contact with an unpinned server is refused with
//! the observed fingerprint; after pinning, connecting succeeds; a server
//! that presents a different key is refused with `previous: Some(_)`. Only
//! the verifier's own refusal is reported as an untrusted certificate, and
//! every connect step is bounded by `connect_timeout`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::TestServer;
use kdx_client_core::{
    connect, spki_fingerprint, trust_server, ClientConfig, ClientError, Event, TrustPolicy,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::TcpListener;

fn tofu_config(port: u16, data_dir: &std::path::Path) -> ClientConfig {
    let mut cfg = ClientConfig::new("127.0.0.1", port, data_dir);
    cfg.trust = TrustPolicy::Tofu;
    cfg
}

/// A syntactically valid fingerprint that matches no real key.
const BOGUS_PIN: &str = "sha256:Qk9HVVNQUkVWSU9VU0tFWUJPR1VTUFJFVklPVVNLRVk=";

#[tokio::test]
async fn first_contact_is_refused_then_pins_then_succeeds() {
    let ts = TestServer::start().await;
    ts.seed_account("phraq", "pw", 1).await;
    let data_dir = tempfile::tempdir().unwrap();

    // First contact: unknown cert, refused with a fingerprint to pin.
    let err = connect(tofu_config(ts.port(), data_dir.path()))
        .await
        .unwrap_err();
    let fingerprint = match err {
        ClientError::UntrustedCertificate {
            fingerprint,
            previous,
            ..
        } => {
            assert!(previous.is_none(), "first contact should have no previous key");
            assert!(fingerprint.starts_with("sha256:"));
            fingerprint
        }
        other => panic!("expected UntrustedCertificate, got {other:?}"),
    };

    // Pin it, then connect succeeds and login works.
    trust_server(data_dir.path(), "127.0.0.1", ts.port(), &fingerprint).unwrap();
    let (client, mut events) = connect(tofu_config(ts.port(), data_dir.path()))
        .await
        .expect("connect should succeed after pinning");
    // Connected reports the fingerprint of the certificate just verified.
    match events.recv().await.unwrap() {
        Event::Connected { fingerprint: seen } => assert_eq!(seen, fingerprint),
        other => panic!("expected Connected, got {other:?}"),
    }
    assert_eq!(client.login("phraq", "pw").await.unwrap().class, 1);

    ts.stop();
}

#[tokio::test]
async fn changed_key_is_flagged_as_previous() {
    let data_dir = tempfile::tempdir().unwrap();

    // Pin a bogus fingerprint for this host:port, simulating a prior trust of
    // a different key.
    let ts = TestServer::start().await;
    ts.seed_account("phraq", "pw", 1).await;
    trust_server(data_dir.path(), "127.0.0.1", ts.port(), BOGUS_PIN).unwrap();

    let err = connect(tofu_config(ts.port(), data_dir.path()))
        .await
        .unwrap_err();
    match err {
        ClientError::UntrustedCertificate { previous, .. } => {
            assert_eq!(previous.as_deref(), Some(BOGUS_PIN));
        }
        other => panic!("expected UntrustedCertificate with previous, got {other:?}"),
    }

    ts.stop();
}

#[tokio::test]
async fn corrupt_known_hosts_refuses_to_connect() {
    let ts = TestServer::start().await;
    let data_dir = tempfile::tempdir().unwrap();
    std::fs::write(data_dir.path().join("known_hosts.toml"), b"\xFF\xFE garbage\n").unwrap();
    // Not a quiet first-contact prompt: the pin store itself is broken.
    let err = connect(tofu_config(ts.port(), data_dir.path()))
        .await
        .unwrap_err();
    assert!(matches!(err, ClientError::KnownHosts(_)), "{err:?}");
    ts.stop();
}

/// Serves one fixed certified key, whatever the client asks for.
#[derive(Debug)]
struct FixedCert(Arc<CertifiedKey>);

impl ResolvesServerCert for FixedCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// A rogue TLS server presenting a certificate for `cert_key` but signing
/// the handshake with `sign_key`. After the TLS handshake it holds the
/// connection open without ever speaking KDX. Returns its port and the
/// SPKI fingerprint of the certificate it presents.
async fn rogue_tls_server(cert_key: &rcgen::KeyPair, sign_key: &rcgen::KeyPair) -> (u16, String) {
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(cert_key)
        .unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(sign_key.serialize_der()));
    let signer = provider.key_provider.load_private_key(key_der).unwrap();
    let certified = Arc::new(CertifiedKey::new(vec![cert.der().clone()], signer));
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FixedCert(certified)));
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(stream) = acceptor.accept(tcp).await {
                    // Never answer the KDX handshake.
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    drop(stream);
                }
            });
        }
    });
    (port, spki_fingerprint(cert.der()))
}

#[tokio::test]
async fn failure_after_the_pin_matched_is_a_tls_error_not_a_changed_key() {
    // The certificate carries the pinned key, but the server can't prove it
    // holds that key (a middlebox replaying the real, public certificate).
    let real = rcgen::KeyPair::generate().unwrap();
    let impostor = rcgen::KeyPair::generate().unwrap();
    let (port, fingerprint) = rogue_tls_server(&real, &impostor).await;
    let data_dir = tempfile::tempdir().unwrap();
    trust_server(data_dir.path(), "127.0.0.1", port, &fingerprint).unwrap();

    let err = connect(tofu_config(port, data_dir.path())).await.unwrap_err();
    assert!(matches!(err, ClientError::Tls(_)), "{err:?}");
}

#[tokio::test]
async fn silent_server_after_tls_times_out_the_connect() {
    let key = rcgen::KeyPair::generate().unwrap();
    let (port, fingerprint) = rogue_tls_server(&key, &key).await;
    let data_dir = tempfile::tempdir().unwrap();
    trust_server(data_dir.path(), "127.0.0.1", port, &fingerprint).unwrap();

    let mut cfg = tofu_config(port, data_dir.path());
    cfg.connect_timeout = Duration::from_millis(500);
    let started = std::time::Instant::now();
    let err = connect(cfg).await.unwrap_err();
    assert!(matches!(err, ClientError::Timeout(_)), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn silent_tcp_listener_times_out_the_tls_handshake() {
    // Accepts TCP and never says anything.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = listener.accept().await {
            held.push(tcp);
        }
    });
    let data_dir = tempfile::tempdir().unwrap();
    let mut cfg = tofu_config(port, data_dir.path());
    cfg.connect_timeout = Duration::from_millis(500);
    let err = connect(cfg).await.unwrap_err();
    assert!(matches!(err, ClientError::Timeout(_)), "{err:?}");
}
