//! Daemon hardening: connection caps and timeouts, TLS policy, the cached
//! dev identity, IP-rule matching on dual-stack listeners, denied-peer
//! floods, graceful shutdown, tracker self-registration and `kdxd useradd`.

#[allow(dead_code)]
mod common;

use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use common::{connect_tls, test_config};
use kdx_server_core::ip_rules::Action;
use kdxd::listener::ServeError;
use kdxd::{serve, Config, Server};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::{timeout, Instant};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

// ---------------------------------------------------------------- helpers

#[derive(Debug)]
struct AcceptAnyCert(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config(
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn: &[&[u8]],
) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

fn tls13() -> Arc<rustls::ClientConfig> {
    client_config(&[&rustls::version::TLS13], &[])
}

async fn tls_connect(
    addr: SocketAddr,
    config: Arc<rustls::ClientConfig>,
) -> std::io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    let connect = TlsConnector::from(config).connect(ServerName::try_from("localhost").unwrap(), tcp);
    timeout(Duration::from_secs(5), connect)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "tls connect timed out"))?
}

async fn peer_cert(addr: SocketAddr) -> Vec<u8> {
    let tls = tls_connect(addr, tls13()).await.unwrap();
    tls.get_ref().1.peer_certificates().unwrap()[0].as_ref().to_vec()
}

/// A TCP connection from a specific loopback source address (127.0.0.x;
/// Linux routes all of 127/8 to lo). `None` if the platform can't.
async fn connect_from(src: &str, addr: SocketAddr) -> Option<TcpStream> {
    let socket = TcpSocket::new_v4().ok()?;
    socket.bind(SocketAddr::new(src.parse().unwrap(), 0)).ok()?;
    socket.connect(addr).await.ok()
}

/// Assert the server closes `stream` (EOF or reset) within `within`,
/// without sending anything.
async fn assert_closed(stream: &mut TcpStream, within: Duration) {
    let mut buf = [0u8; 64];
    match timeout(within, stream.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("server sent {n} bytes instead of closing"),
        Err(_) => panic!("connection still open after {within:?}"),
    }
}

async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn start(config: Config) -> Server {
    serve(config).await.unwrap_or_else(|e| panic!("serve failed: {e}"))
}

async fn serve_err(config: Config) -> ServeError {
    match serve(config).await {
        Ok(server) => {
            server.handle.abort();
            panic!("serve unexpectedly succeeded")
        }
        Err(e) => e,
    }
}

async fn deny(server: &Server, cidr: &str) {
    server
        .ctx
        .ip_rules
        .create(0, Action::Deny, cidr, "ops test", "test", 0)
        .await
        .unwrap();
}

// ------------------------------------------------- caps and timeouts (DOS-1)

#[tokio::test]
async fn silent_tcp_client_is_dropped_after_tls_handshake_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(Config {
        tls_handshake_timeout_secs: 1,
        ..test_config(&dir)
    })
    .await;

    let mut raw = TcpStream::connect(server.local_addr).await.unwrap();
    let started = Instant::now();
    assert_closed(&mut raw, Duration::from_secs(5)).await;
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(800), "closed too early: {waited:?}");
    wait_until("slot release", || server.open_connections() == 0).await;

    server.handle.abort();
}

#[tokio::test]
async fn per_address_connection_cap() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(Config {
        max_connections_per_ip: 2,
        ..test_config(&dir)
    })
    .await;
    let addr = server.local_addr;

    let first = TcpStream::connect(addr).await.unwrap();
    let _second = TcpStream::connect(addr).await.unwrap();
    wait_until("two open connections", || server.open_connections() == 2).await;

    // Over the cap: closed straight away, not parked in the TLS handshake.
    let mut third = TcpStream::connect(addr).await.unwrap();
    assert_closed(&mut third, Duration::from_secs(2)).await;
    assert_eq!(server.open_connections(), 2);

    // Closing one frees its slot for a real client.
    drop(first);
    wait_until("slot release", || server.open_connections() == 1).await;
    let _client = connect_tls(addr).await;
    assert_eq!(server.open_connections(), 2);

    server.handle.abort();
}

#[tokio::test]
async fn global_connection_cap() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(Config {
        max_connections: 2,
        max_connections_per_ip: 2,
        ..test_config(&dir)
    })
    .await;
    let addr = server.local_addr;

    let Some(_a) = connect_from("127.0.0.2", addr).await else {
        eprintln!("skipping: cannot connect from 127.0.0.2 on this platform");
        server.handle.abort();
        return;
    };
    let _b = connect_from("127.0.0.3", addr).await.unwrap();
    wait_until("two open connections", || server.open_connections() == 2).await;

    // A third address with no connections of its own is still turned away.
    let mut c = connect_from("127.0.0.4", addr).await.unwrap();
    assert_closed(&mut c, Duration::from_secs(2)).await;

    server.handle.abort();
}

// ------------------------------------------------------- TLS policy (OPS-10)

#[tokio::test]
async fn tls13_only_and_kdx_alpn() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(test_config(&dir)).await;
    let addr = server.local_addr;

    // A client that only speaks TLS 1.2 is refused.
    let tls12 = client_config(&[&rustls::version::TLS12], &[]);
    assert!(tls_connect(addr, tls12).await.is_err());

    // A client offering both negotiates 1.3, and kdx/1 when it offers ALPN.
    let both = client_config(&[&rustls::version::TLS13, &rustls::version::TLS12], &[b"kdx/1"]);
    let tls = tls_connect(addr, both).await.unwrap();
    assert_eq!(tls.get_ref().1.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"kdx/1"[..]));

    // ALPN is optional for clients...
    let plain = connect_tls(addr).await;
    let conn = plain.get_ref().get_ref().1;
    assert_eq!(conn.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
    assert_eq!(conn.alpn_protocol(), None);

    // ...but a client asking for some other protocol is refused.
    let h2 = client_config(&[&rustls::version::TLS13], &[b"h2"]);
    assert!(tls_connect(addr, h2).await.is_err());

    server.handle.abort();
}

// ------------------------------------------------ dev TLS identity (OPS-1)

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[cfg(unix)]
#[tokio::test]
async fn dev_key_is_private_and_identity_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let config = || Config {
        database: state.join("kdx.db"),
        ..test_config(&dir)
    };

    let server = start(config()).await;
    assert_eq!(mode(&state), 0o700, "state dir must be private");
    assert_eq!(mode(&state.join("dev-key.der")), 0o600, "dev key must be private");
    let first = peer_cert(server.local_addr).await;
    server.handle.abort();

    let server = start(config()).await;
    assert_eq!(peer_cert(server.local_addr).await, first, "identity changed on restart");
    let leftovers: Vec<_> = std::fs::read_dir(&state)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|n| n.to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");
    server.handle.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn insecure_cached_dev_key_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    start(test_config(&dir)).await.handle.abort();
    let key = dir.path().join("dev-key.der");
    let set_mode = |m: u32| std::fs::set_permissions(&key, std::fs::Permissions::from_mode(m)).unwrap();

    // Readable by group/others: someone else may hold the key.
    set_mode(0o644);
    let err = serve_err(test_config(&dir)).await;
    assert!(matches!(err, ServeError::InsecureKey(_)), "{err}");

    // A symlink (possibly planted) is never followed.
    set_mode(0o600);
    let elsewhere = dir.path().join("elsewhere.der");
    std::fs::rename(&key, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &key).unwrap();
    let err = serve_err(test_config(&dir)).await;
    assert!(matches!(err, ServeError::InsecureKey(_)), "{err}");
    std::fs::remove_file(&key).unwrap();
    std::fs::rename(&elsewhere, &key).unwrap();

    // Owned by another user (only arrangeable as root).
    if kdxd::sys::effective_uid() == 0 {
        std::os::unix::fs::chown(&key, Some(1), None).unwrap();
        let err = serve_err(test_config(&dir)).await;
        assert!(matches!(err, ServeError::InsecureKey(_)), "{err}");
        std::os::unix::fs::chown(&key, Some(0), None).unwrap();
    }

    // A private key owned by us is reused as before.
    start(test_config(&dir)).await.handle.abort();
}

// ---------------------------------------- IP rules on dual stack (OPS-3)

#[tokio::test]
async fn ipv4_rules_match_ipv4_peers_on_a_dual_stack_listener() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        bind: "[::]:0".parse().unwrap(),
        ..test_config(&dir)
    };
    let server = match serve(config).await {
        Ok(server) => server,
        Err(e) => {
            eprintln!("skipping: cannot bind [::] ({e})");
            return;
        }
    };
    let v4 = SocketAddr::from(([127, 0, 0, 1], server.local_addr.port()));
    if let Err(e) = TcpStream::connect(v4).await {
        eprintln!("skipping: listener is IPv6-only ({e})");
        server.handle.abort();
        return;
    }

    // The peer shows up as ::ffff:127.0.0.1; the IPv4 rule must still match.
    deny(&server, "127.0.0.1/32").await;
    assert!(
        tls_connect(v4, tls13()).await.is_err(),
        "IPv4 deny rule bypassed via an IPv4-mapped address"
    );

    // Without the rule the same client gets in.
    for rule in server.ctx.ip_rules.list().await.unwrap() {
        server.ctx.ip_rules.delete(&rule.id).await.unwrap();
    }
    tls_connect(v4, tls13()).await.unwrap();

    server.handle.abort();
}

// -------------------------------------------- denied-peer floods (DOS-5)

#[tokio::test]
async fn denied_flood_does_not_stall_the_accept_loop() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(test_config(&dir)).await;
    let addr = server.local_addr;
    deny(&server, "127.0.0.2/32").await;
    if connect_from("127.0.0.2", addr).await.is_none() {
        eprintln!("skipping: cannot connect from 127.0.0.2 on this platform");
        server.handle.abort();
        return;
    }

    // Hold the database's write lock, so any history write the accept loop
    // waited on would block (for the 5 s busy timeout, every time).
    let pool = kdx_storage::connect(&dir.path().join("kdx.db")).await.unwrap();
    let mut lock = pool.acquire().await.unwrap();
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *lock).await.unwrap();

    for _ in 0..50 {
        drop(connect_from("127.0.0.2", addr).await.unwrap());
    }
    let started = Instant::now();
    let _client = timeout(Duration::from_secs(2), connect_tls(addr))
        .await
        .expect("allowed client stalled behind denied connections");
    assert!(started.elapsed() < Duration::from_secs(2));

    sqlx::query("ROLLBACK").execute(&mut *lock).await.unwrap();
    server.handle.abort();
}

#[tokio::test]
async fn denied_flood_is_coalesced_in_history() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(test_config(&dir)).await;
    let addr = server.local_addr;
    deny(&server, "127.0.0.2/32").await;

    for _ in 0..200 {
        let Some(conn) = connect_from("127.0.0.2", addr).await else {
            eprintln!("skipping: cannot connect from 127.0.0.2 on this platform");
            server.handle.abort();
            return;
        };
        drop(conn);
    }

    let denied_rows = || async {
        server.ctx.history.flush().await;
        server
            .ctx
            .history
            .recent(10_000)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.action == "ip_denied")
            .collect::<Vec<_>>()
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while denied_rows().await.is_empty() {
        assert!(Instant::now() < deadline, "no ip_denied row was recorded");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let rows = denied_rows().await;
    assert_eq!(rows.len(), 1, "200 denials must coalesce into one row: {rows:?}");
    assert!(rows[0].detail.contains("peer=127.0.0.2"), "{rows:?}");

    server.handle.abort();
}

// ------------------------------------------------------ shutdown (DOS-12)

#[tokio::test]
async fn shutdown_notification_before_the_accept_loop_runs_is_not_lost() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(test_config(&dir)).await;
    // What AdminShutdown does, fired before the accept task was ever polled.
    server.ctx.shutdown.notify_waiters();
    timeout(Duration::from_secs(2), server.handle)
        .await
        .expect("accept loop missed the shutdown notification")
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let server = start(test_config(&dir)).await;
    server.ctx.shutdown.notify_one();
    timeout(Duration::from_secs(2), server.handle)
        .await
        .expect("accept loop missed the shutdown notification")
        .unwrap();
}

#[tokio::test]
async fn shutdown_stops_accepting_and_drains_connections() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(test_config(&dir)).await;
    let addr = server.local_addr;
    let raw = TcpStream::connect(addr).await.unwrap();
    wait_until("open connection", || server.open_connections() == 1).await;

    let shutdown = tokio::spawn(server.shutdown("bye", Duration::from_secs(5)));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!shutdown.is_finished(), "shutdown must wait for the open connection");

    drop(raw);
    let still_open = timeout(Duration::from_secs(2), shutdown)
        .await
        .expect("shutdown did not finish once the connection closed")
        .unwrap();
    assert_eq!(still_open, 0);
    assert!(TcpStream::connect(addr).await.is_err(), "listener still accepting");
}

#[tokio::test]
async fn shutdown_gives_up_after_the_grace_period() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(test_config(&dir)).await;
    let _raw = TcpStream::connect(server.local_addr).await.unwrap();
    wait_until("open connection", || server.open_connections() == 1).await;
    let still_open = timeout(
        Duration::from_secs(3),
        server.shutdown("bye", Duration::from_millis(300)),
    )
    .await
    .expect("shutdown ignored its grace period");
    assert_eq!(still_open, 1);
}

// ------------------------------------------------- tracker entry (OPS-12)

#[tokio::test]
async fn tracker_lists_the_server_only_under_public_host() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(Config {
        public_host: Some("kdx.example.net".into()),
        ..test_config(&dir)
    })
    .await;
    let deadline = Instant::now() + Duration::from_secs(5);
    let entries = loop {
        let entries = server.ctx.tracker.query(None).await;
        if !entries.is_empty() {
            break entries;
        }
        assert!(Instant::now() < deadline, "server never registered");
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].host, "kdx.example.net");
    assert_eq!(entries[0].port, server.local_addr.port());
    server.handle.abort();

    // No public_host: nothing is advertised (in particular not 127.0.0.1).
    let dir = tempfile::tempdir().unwrap();
    let server = start(test_config(&dir)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(server.ctx.tracker.query(None).await.is_empty());
    server.handle.abort();
}

// ------------------------------------------------------ useradd (OPS-7)

fn kdxd(cwd: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kdxd"))
        .args(args)
        .current_dir(cwd)
        .env("RUST_LOG", "warn")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[tokio::test]
async fn useradd_reads_password_from_stdin_into_the_configs_database() {
    let cfg_dir = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let cfg = cfg_dir.path().join("kdxd.toml");
    std::fs::write(&cfg, "database = \"kdx.db\"\n").unwrap();
    let cfg = cfg.to_str().unwrap();

    let out = kdxd(
        cwd.path(),
        &["useradd", "bob", "--password-stdin", "power", cfg, "--allow-root"],
        "correct horse\n",
    );
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert!(!text(&out.stderr).contains("warning"), "{}", text(&out.stderr));

    // The relative database path resolved next to the config file, not in
    // the working directory, and the absolute path is reported.
    let db = std::path::absolute(cfg_dir.path().join("kdx.db")).unwrap();
    assert!(text(&out.stdout).contains(&db.display().to_string()), "{}", text(&out.stdout));
    assert!(!cwd.path().join("kdx.db").exists());

    let pool = kdx_storage::connect(&db).await.unwrap();
    let bob = kdx_storage::accounts::by_username(&pool, "bob")
        .await
        .unwrap()
        .expect("account created");
    assert_eq!(bob.base_class, 2);
    // The trailing newline is not part of the password.
    assert!(kdx_crypto::verify_password("correct horse", &bob.password_phc).unwrap());

    // Creating the same account again fails cleanly.
    let again = kdxd(
        cwd.path(),
        &["useradd", "bob", "--password-stdin", "user", cfg, "--allow-root"],
        "other\n",
    );
    assert!(!again.status.success());
}

#[test]
fn useradd_rejects_empty_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("kdxd.toml");
    std::fs::write(&cfg, "").unwrap();
    let cfg = cfg.to_str().unwrap();

    let empty_password = kdxd(
        dir.path(),
        &["useradd", "bob", "--password-stdin", "user", cfg, "--allow-root"],
        "\n",
    );
    assert!(!empty_password.status.success());
    assert!(text(&empty_password.stderr).contains("password"), "{}", text(&empty_password.stderr));

    let blank_user = kdxd(
        dir.path(),
        &["useradd", " ", "--password-stdin", "user", cfg, "--allow-root"],
        "pw\n",
    );
    assert!(!blank_user.status.success());

    let legacy_empty = kdxd(dir.path(), &["useradd", "bob", "", "user", cfg, "--allow-root"], "");
    assert!(!legacy_empty.status.success());
    assert!(!dir.path().join("kdx.db").exists(), "nothing should have been created");
}

#[test]
fn useradd_positional_password_still_works_but_warns() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("kdxd.toml");
    std::fs::write(&cfg, "").unwrap();
    let out = kdxd(
        dir.path(),
        &["useradd", "carol", "s3cret", "guest", cfg.to_str().unwrap(), "--allow-root"],
        "",
    );
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    assert!(text(&out.stderr).contains("warning"), "{}", text(&out.stderr));
}

#[cfg(unix)]
#[test]
fn kdxd_refuses_to_run_as_root_without_allow_root() {
    if kdxd::sys::effective_uid() != 0 {
        eprintln!("skipping: not running as root");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let out = kdxd(dir.path(), &["useradd", "bob", "--password-stdin"], "pw\n");
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("refusing to run as root"), "{}", text(&out.stderr));
    assert!(!dir.path().join("kdx.db").exists());

    let cfg = dir.path().join("kdxd.toml");
    // Invalid (port 0), so a missing guard fails fast instead of serving.
    std::fs::write(&cfg, "bind = \"127.0.0.1:0\"\n").unwrap();
    let out = kdxd(dir.path(), &[cfg.to_str().unwrap()], "");
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("refusing to run as root"), "{}", text(&out.stderr));
}

// ------------------------------------------------ service files (OPS-8)

#[test]
fn launchd_job_runs_unprivileged_with_enough_descriptors() {
    let plist = include_str!("../net.kdx.hotline.server.plist");
    assert!(plist.contains("<key>UserName</key>\n  <string>_kdx</string>"));
    assert!(plist.contains("<key>GroupName</key>"));
    assert!(plist.contains("<key>Umask</key>"));
    assert!(plist.contains("<key>SoftResourceLimits</key>"));
    assert!(plist.contains("<key>NumberOfFiles</key>"));
}

#[test]
fn systemd_unit_is_sandboxed_and_owner_only() {
    let unit = include_str!("../kdxd.service");
    for directive in [
        "User=kdx",
        "StateDirectory=kdx",
        "StateDirectoryMode=0700",
        "UMask=0077",
        "NoNewPrivileges=true",
        "CapabilityBoundingSet=\n",
        "PrivateDevices=true",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        "SystemCallFilter=@system-service",
        "MemoryDenyWriteExecute=true",
        "LockPersonality=true",
        "ProtectKernelTunables=true",
        "ProtectKernelModules=true",
    ] {
        assert!(unit.contains(directive), "kdxd.service lacks {directive:?}");
    }
}
