//! C1 TOFU behavior: first contact with an unpinned server is refused with
//! the observed fingerprint; after pinning, connecting succeeds; a server
//! that presents a different key is refused with `previous: Some(_)`.

mod common;

use common::TestServer;
use kdx_client_core::{connect, trust_server, ClientConfig, ClientError, TrustPolicy};

fn tofu_config(port: u16, data_dir: &std::path::Path) -> ClientConfig {
    ClientConfig {
        host: "127.0.0.1".into(),
        port,
        trust: TrustPolicy::Tofu,
        data_dir: data_dir.to_path_buf(),
    }
}

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
    let (client, _events) = connect(tofu_config(ts.port(), data_dir.path()))
        .await
        .expect("connect should succeed after pinning");
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
    trust_server(data_dir.path(), "127.0.0.1", ts.port(), "sha256:BOGUSPREVIOUSKEY=").unwrap();

    let err = connect(tofu_config(ts.port(), data_dir.path()))
        .await
        .unwrap_err();
    match err {
        ClientError::UntrustedCertificate { previous, .. } => {
            assert_eq!(previous.as_deref(), Some("sha256:BOGUSPREVIOUSKEY="));
        }
        other => panic!("expected UntrustedCertificate with previous, got {other:?}"),
    }

    ts.stop();
}
