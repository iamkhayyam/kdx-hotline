//! kdxd — the KDX server daemon.

use std::path::PathBuf;

use kdxd::{serve, Config};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = match std::env::args().nth(1) {
        Some(path) => Config::load(&PathBuf::from(path))?,
        None => {
            info!("no config file given; using defaults (0.0.0.0:10700, self-signed TLS)");
            Config::default()
        }
    };

    let server = serve(config).await?;
    info!(addr = %server.local_addr, "kdxd running; ctrl-c to stop");

    tokio::signal::ctrl_c().await?;
    info!("shutting down");
    server.handle.abort();
    Ok(())
}
