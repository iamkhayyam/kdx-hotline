//! Shared harness: spin an in-process kdxd on an ephemeral port and seed
//! accounts, so client-core tests drive the real server through the public
//! `ClientHandle` API.
//!
//! Not every test binary uses every helper here; each compiles `common`
//! independently, so unused-method warnings per binary are expected.
#![allow(dead_code)]

use std::path::PathBuf;

use kdx_client_core::{connect, trust_server, ClientConfig, ClientError, ClientHandle, Event};
use kdx_storage::accounts;
use kdxd::{serve, Config, Server};
use tokio::sync::mpsc::Receiver;

pub struct TestServer {
    pub server: Server,
    // Held to keep the server's data dir alive for the test's lifetime.
    #[allow(dead_code)]
    pub dir: tempfile::TempDir,
    pub db_path: PathBuf,
}

impl TestServer {
    pub async fn start() -> Self {
        Self::start_with_download_throttle(0).await
    }

    /// Start with a per-transfer download throttle (bytes/sec; 0 = unlimited),
    /// so tests can interrupt a slow download deterministically.
    pub async fn start_with_download_throttle(download_bps: u64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("kdx.db");
        let config = Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            database: db_path.clone(),
            files_root: dir.path().join("files"),
            max_download_bytes_per_sec: download_bps,
            ..Config::default()
        };
        let server = serve(config).await.unwrap();
        Self {
            server,
            dir,
            db_path,
        }
    }

    pub async fn seed_account(&self, username: &str, password: &str, class: i64) {
        let pool = kdx_storage::connect(&self.db_path).await.unwrap();
        let phc = kdx_crypto::hash_password(password).unwrap();
        accounts::create(&pool, username, &phc, class).await.unwrap();
    }

    pub fn port(&self) -> u16 {
        self.server.local_addr.port()
    }

    /// Connect via the real TOFU path: first contact is refused with a
    /// fingerprint, which we pin and retry. Exercises the shipping trust
    /// logic instead of a test-only accept-any policy. The returned TempDir
    /// holds `known_hosts.toml` and must outlive the client.
    pub async fn connect_client(&self) -> (ClientHandle, Receiver<Event>, tempfile::TempDir) {
        let data_dir = tempfile::tempdir().unwrap();
        let cfg = ClientConfig::new("127.0.0.1", self.port(), data_dir.path());

        match connect(cfg.clone()).await {
            Err(ClientError::UntrustedCertificate { fingerprint, .. }) => {
                trust_server(data_dir.path(), "127.0.0.1", self.port(), &fingerprint).unwrap();
            }
            Err(e) => panic!("unexpected first-contact error: {e}"),
            Ok(_) => panic!("first contact should be untrusted"),
        }
        let (client, events) = connect(cfg).await.expect("connect after pinning");
        (client, events, data_dir)
    }

    pub fn stop(self) {
        self.server.handle.abort();
    }
}
