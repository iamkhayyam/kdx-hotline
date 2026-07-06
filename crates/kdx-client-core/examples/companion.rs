//! A companion bot for testing the live experience: connects, logs in, joins
//! the lobby, then periodically chats and echoes what it hears. Runs until
//! killed. Useful so a human logging in via the GUI sees company.
//!
//!   cargo run -p kdx-client-core --example companion -- 127.0.0.1 10700 phraq hunter2

use std::time::Duration;

use kdx_client_core::{connect, ClientConfig, ClientError, Event};

const LINES: &[&str] = &[
    "anyone got the 1620 linux build?",
    "/me sips coffee",
    "the tracker's been flaky today",
    "welcome to the underground",
    "drop it in /incoming when you're done",
    "sirrus and cumulus, reporting in",
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let host = args.first().cloned().unwrap_or_else(|| "127.0.0.1".into());
    let port: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(10700);
    let user = args.get(2).cloned().unwrap_or_else(|| "phraq".into());
    let pass = args.get(3).cloned().unwrap_or_else(|| "hunter2".into());

    let data_dir = std::env::temp_dir().join("kdx-companion");
    std::fs::create_dir_all(&data_dir)?;
    let cfg = ClientConfig::new(host.clone(), port, &data_dir);

    let (client, mut events) = match connect(cfg.clone()).await {
        Ok(p) => p,
        Err(ClientError::UntrustedCertificate { fingerprint, .. }) => {
            kdx_client_core::trust_server(&data_dir, &host, port, &fingerprint)?;
            connect(cfg).await?
        }
        Err(e) => return Err(e.into()),
    };
    client.login(&user, &pass).await?;
    client.join("lobby").await?;
    println!("[companion] {user} online in #lobby");

    // Print what other people say.
    tokio::spawn(async move {
        while let Some(ev) = events.recv().await {
            if let Event::Chat { sender, text, .. } = ev {
                if sender != user && !sender.is_empty() {
                    println!("[heard] <{sender}> {text}");
                }
            }
        }
    });

    let mut i = 0usize;
    loop {
        tokio::time::sleep(Duration::from_secs(18)).await;
        let line = LINES[i % LINES.len()];
        i += 1;
        let flags = if line.starts_with("/me ") { 1 } else { 0 };
        let text = line.strip_prefix("/me ").unwrap_or(line);
        if client.send_chat("lobby", flags, text).await.is_err() {
            eprintln!("[companion] disconnected");
            break;
        }
    }
    Ok(())
}
