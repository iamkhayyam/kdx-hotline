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
