//! kdxd — the KDX server daemon.
//!
//! Usage:
//!   kdxd [--allow-root] [CONFIG.toml]                                   run the server
//!   kdxd useradd USER [--prompt | --password-stdin] [CLASS] [CONFIG]   create an account, then exit
//!
//! CLASS is one of guest|user|power|admin (default: user). See
//! `kdxd::cli::USAGE` for the full text.

use std::path::PathBuf;
use std::time::Duration;

use kdx_server_core::auth::AuthManager;
use kdxd::cli::{self, PasswordSource, RunArgs, UseraddArgs};
use kdxd::{serve, sys, Config};
use tracing::{info, warn};

/// How long a graceful stop waits for open connections to close.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match real_main().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kdxd: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    // Everything kdxd creates (database, uploads, dev key) is private.
    #[cfg(unix)]
    sys::restrict_umask();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", cli::USAGE);
        return Ok(());
    }
    match args.first().map(String::as_str) {
        Some("useradd") => match cli::parse_useradd(&args[1..]) {
            Ok(parsed) => useradd(parsed).await,
            Err(e) => Err(format!("{e}\n\n{}", cli::USAGE).into()),
        },
        _ => match cli::parse_run(&args) {
            Ok(parsed) => run(parsed).await,
            Err(e) => Err(format!("{e}\n\n{}", cli::USAGE).into()),
        },
    }
}

fn refuse_root(allow_root: bool) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    sys::check_not_root(sys::effective_uid(), allow_root)?;
    #[cfg(not(unix))]
    let _ = allow_root;
    Ok(())
}

fn load_config(path: Option<&PathBuf>) -> Result<Config, Box<dyn std::error::Error>> {
    Ok(match path {
        Some(path) => Config::load(path)?,
        None => Config::default(),
    })
}

async fn run(args: RunArgs) -> Result<(), Box<dyn std::error::Error>> {
    refuse_root(args.allow_root)?;
    if args.config.is_none() {
        info!("no config file given; using defaults (0.0.0.0:10700, self-signed TLS)");
    }
    let config = load_config(args.config.as_ref())?;
    info!(
        database = %std::path::absolute(&config.database)?.display(),
        files_root = %std::path::absolute(&config.files_root)?.display(),
        "starting"
    );

    let mut server = serve(config).await?;
    info!(addr = %server.local_addr, "kdxd running; ctrl-c to stop");

    tokio::select! {
        result = stop_signal() => {
            result?;
            info!("shutting down");
        }
        _ = &mut server.handle => {
            // The accept loop stopped on its own — an admin's AdminShutdown,
            // which already told every user. Let their connections close.
            info!("server shut down remotely; exiting");
        }
    }
    tokio::select! {
        still_open = server.shutdown("server shutting down", SHUTDOWN_GRACE) => {
            if still_open > 0 {
                warn!(still_open, "connections still open after the grace period; exiting anyway");
            }
        }
        _ = stop_signal() => warn!("second stop signal; exiting now"),
    }
    Ok(())
}

/// Ctrl-C, or SIGTERM (what systemd and launchd send on stop).
async fn stop_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = term.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

async fn useradd(args: UseraddArgs) -> Result<(), Box<dyn std::error::Error>> {
    refuse_root(args.allow_root)?;
    cli::validate_username(&args.username)?;
    let config = load_config(args.config.as_ref())?;

    let password = match args.password {
        PasswordSource::Argv(password) => {
            eprintln!(
                "warning: a password on the command line is visible to other local users \
                 (ps, /proc) and saved in your shell history; prefer the prompt \
                 (`kdxd useradd USER`) or --password-stdin"
            );
            password
        }
        PasswordSource::Stdin => sys::read_password_line(&mut std::io::stdin().lock())?,
        PasswordSource::Prompt => {
            let first = sys::prompt_password("Password: ")?;
            cli::validate_password(&first)?;
            let again = sys::prompt_password("Retype password: ")?;
            if first != again {
                return Err("passwords do not match".into());
            }
            first
        }
    };
    cli::validate_password(&password)?;

    let database = std::path::absolute(&config.database)?;
    let pool = kdx_storage::connect(&database).await?;
    let auth = AuthManager::new(pool, Duration::from_secs(config.session_ttl_secs));
    auth.create_account(&args.username, &password, args.class, 0, 0)
        .await?;
    println!(
        "created account '{}' (class {}) in {}",
        args.username,
        args.class,
        database.display()
    );
    Ok(())
}
