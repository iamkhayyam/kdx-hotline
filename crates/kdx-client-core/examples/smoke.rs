//! End-to-end smoke test against a real, separately-running kdxd.
//!
//!   cargo run -p kdxd -- useradd phraq s3cret power smoke.toml
//!   cargo run -p kdxd -- smoke.toml &
//!   cargo run -p kdx-client-core --example smoke -- 127.0.0.1 10700 phraq s3cret
//!
//! Connects (accepting the TOFU cert on first contact), logs in, joins the
//! lobby, sends a message, and lists the root directory — printing each step.

use std::time::Duration;

use kdx_client_core::{connect, ClientConfig, ClientError, Event};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let host = args.first().cloned().unwrap_or_else(|| "127.0.0.1".into());
    let port: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(10700);
    let user = args.get(2).cloned().unwrap_or_else(|| "phraq".into());
    let pass = args.get(3).cloned().unwrap_or_else(|| "s3cret".into());
    let data_dir = std::env::temp_dir().join("kdx-smoke");
    std::fs::create_dir_all(&data_dir)?;

    let cfg = ClientConfig::new(host.clone(), port, &data_dir);

    // First contact: pin the TOFU fingerprint, then reconnect.
    let (client, mut events) = match connect(cfg.clone()).await {
        Ok(pair) => pair,
        Err(ClientError::UntrustedCertificate { fingerprint, .. }) => {
            println!("[tofu] pinning {fingerprint}");
            kdx_client_core::trust_server(&data_dir, &host, port, &fingerprint)?;
            connect(cfg).await?
        }
        Err(e) => return Err(e.into()),
    };
    println!("[connected] {host}:{port}");

    let session = client.login(&user, &pass).await?;
    println!("[login] ok, class {}", session.class);

    client.join("lobby").await?;
    client.send_chat("lobby", 0, "hello from the smoke test").await?;
    println!("[chat] joined lobby and sent a message");

    let listing = client.list_files("/").await?;
    println!("[files] / has {} entries", listing.entries.len());

    // Drain a couple of events to show the push stream is live.
    for _ in 0..3 {
        match tokio::time::timeout(Duration::from_millis(500), events.recv()).await {
            Ok(Some(ev @ Event::UserList { .. })) => println!("[event] {ev:?}"),
            Ok(Some(_)) => {}
            _ => break,
        }
    }

    client.disconnect().await;
    println!("[done] smoke test passed");
    Ok(())
}
