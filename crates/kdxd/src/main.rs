//! kdxd — the KDX server daemon.
//!
//! Usage:
//!   kdxd [CONFIG.toml]                       run the server
//!   kdxd useradd USER PASS [CLASS] [CONFIG]  create an account, then exit
//!
//! CLASS is one of guest|user|power|admin (default: user).

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

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("useradd") => useradd(args.collect()).await,
        maybe_config => run(maybe_config.map(PathBuf::from)).await,
    }
}

async fn run(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let config = match config_path {
        Some(path) => Config::load(&path)?,
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

async fn useradd(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let username = args.first().ok_or("usage: kdxd useradd USER PASS [CLASS] [CONFIG]")?;
    let password = args.get(1).ok_or("usage: kdxd useradd USER PASS [CLASS] [CONFIG]")?;
    let class = match args.get(2).map(String::as_str) {
        None | Some("user") => 1,
        Some("guest") => 0,
        Some("power") => 2,
        Some("admin") => 3,
        Some(other) => return Err(format!("unknown class '{other}'").into()),
    };
    let config = match args.get(3) {
        Some(path) => Config::load(&PathBuf::from(path))?,
        None => Config::default(),
    };

    let pool = kdx_storage::connect(&config.database).await?;
    let phc = kdx_crypto::hash_password(password)?;
    kdx_storage::accounts::create(&pool, username, &phc, class).await?;
    println!("created account '{username}' (class {class}) in {}", config.database.display());
    Ok(())
}
