use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

/// kdxd configuration, loaded from a TOML file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to bind. KDX's traditional port is 10700.
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    /// TLS certificate/key PEM paths. When absent, a self-signed dev
    /// certificate is generated at startup (fine for local testing, useless
    /// for clients that verify — supply real certs in production).
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// SQLite database path (created if missing).
    #[serde(default = "default_database")]
    pub database: PathBuf,
    /// Idle session lifetime in seconds before reauthentication is required.
    #[serde(default = "default_session_ttl_secs")]
    pub session_ttl_secs: u64,
    /// Directory where served file bytes are stored (created if missing).
    #[serde(default = "default_files_root")]
    pub files_root: PathBuf,
    /// Per-transfer upload throttle in bytes/sec. 0 = unlimited.
    #[serde(default)]
    pub max_upload_bytes_per_sec: u64,
    /// Per-transfer download throttle in bytes/sec. 0 = unlimited.
    #[serde(default)]
    pub max_download_bytes_per_sec: u64,
}

fn default_files_root() -> PathBuf {
    PathBuf::from("files")
}

fn default_database() -> PathBuf {
    PathBuf::from("kdx.db")
}

fn default_session_ttl_secs() -> u64 {
    30 * 60
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert_pem: PathBuf,
    pub key_pem: PathBuf,
}

fn default_bind() -> SocketAddr {
    "0.0.0.0:10700".parse().expect("valid default bind address")
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            tls: None,
            database: default_database(),
            session_ttl_secs: default_session_ttl_secs(),
            files_root: default_files_root(),
            max_upload_bytes_per_sec: 0,
            max_download_bytes_per_sec: 0,
        }
    }
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Read(path.to_owned(), e))?;
        toml::from_str(&raw).map_err(|e| ConfigError::Parse(path.to_owned(), e))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config {0}: {1}")]
    Read(PathBuf, std::io::Error),
    #[error("cannot parse config {0}: {1}")]
    Parse(PathBuf, toml::de::Error),
}
