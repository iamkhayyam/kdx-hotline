use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use kdx_server_core::limits::{MAX_SERVER_DESCRIPTION_LEN, MAX_SERVER_NAME_LEN};
use serde::Deserialize;

/// kdxd configuration, loaded from a TOML file.
///
/// Relative paths in a config file (`database`, `files_root`, `[tls]`) are
/// resolved against the directory that contains the file, so the server and
/// `kdxd useradd` agree on them whatever the working directory is.
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
    /// Display name this server advertises to the tracker directory.
    #[serde(default = "default_server_name")]
    pub server_name: String,
    /// One-line description shown in the tracker directory.
    #[serde(default)]
    pub server_description: String,
    /// Advertised capacity (for the tracker directory's "users/max" figure).
    #[serde(default = "default_max_users")]
    pub max_users: u32,
    /// Seconds a new TCP connection gets to finish the TLS handshake before
    /// it is dropped.
    #[serde(default = "default_tls_handshake_timeout_secs")]
    pub tls_handshake_timeout_secs: u64,
    /// Cap on concurrently open connections (any stage, pre- or post-login).
    /// Connections over the cap are closed as soon as they are accepted.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Cap on concurrently open connections from one peer address (one IPv4
    /// address, or one IPv6 /64).
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,
    /// Public hostname (or address) clients should use to reach this
    /// server. The server lists itself in its own tracker directory only
    /// when this is set; otherwise nothing is advertised.
    #[serde(default)]
    pub public_host: Option<String>,
}

fn default_server_name() -> String {
    "KDX Server".to_string()
}

fn default_max_users() -> u32 {
    256
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

fn default_tls_handshake_timeout_secs() -> u64 {
    10
}

fn default_max_connections() -> usize {
    1024
}

fn default_max_connections_per_ip() -> usize {
    8
}

/// Upper bound for `session_ttl_secs` (30 days). Larger values overflow
/// `Instant + Duration` at login.
pub const MAX_SESSION_TTL_SECS: u64 = 30 * 24 * 60 * 60;
/// Upper bound for `tls_handshake_timeout_secs`.
pub const MAX_TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 300;
/// Upper bound for `max_connections`.
pub const MAX_MAX_CONNECTIONS: usize = 1_000_000;
/// Longest accepted `public_host` (a DNS name is at most 253 bytes).
pub const MAX_PUBLIC_HOST_LEN: usize = 253;

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
            server_name: default_server_name(),
            server_description: String::new(),
            max_users: default_max_users(),
            tls_handshake_timeout_secs: default_tls_handshake_timeout_secs(),
            max_connections: default_max_connections(),
            max_connections_per_ip: default_max_connections_per_ip(),
            public_host: None,
        }
    }
}

impl Config {
    /// Read, parse and validate a config file, resolving its relative paths
    /// against the file's own directory.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Read(path.to_owned(), e))?;
        let mut config: Config =
            toml::from_str(&raw).map_err(|e| ConfigError::Parse(path.to_owned(), e))?;
        let absolute =
            std::path::absolute(path).map_err(|e| ConfigError::Read(path.to_owned(), e))?;
        if let Some(base) = absolute.parent() {
            config.resolve_relative_paths(base);
        }
        config
            .validate()
            .map_err(|e| ConfigError::Invalid(path.to_owned(), e))?;
        Ok(config)
    }

    /// Make every relative path in the config relative to `base`.
    pub fn resolve_relative_paths(&mut self, base: &Path) {
        let fix = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        };
        fix(&mut self.database);
        fix(&mut self.files_root);
        if let Some(tls) = self.tls.as_mut() {
            fix(&mut tls.cert_pem);
            fix(&mut tls.key_pem);
        }
    }

    /// Full validation, as applied to a config file: everything
    /// [`Config::check_limits`] checks, plus `bind` must name a real port
    /// (port 0 would silently listen on a random one).
    pub fn validate(&self) -> Result<(), String> {
        if self.bind.port() == 0 {
            return Err(format!(
                "bind = \"{}\": port 0 picks a random port; name the port to listen on",
                self.bind
            ));
        }
        self.check_limits()
    }

    /// The checks `serve()` itself enforces: values that would otherwise
    /// panic, wrap, or break the wire protocol. Unlike [`Config::validate`]
    /// this allows port 0, which in-process tests use for an ephemeral port.
    pub fn check_limits(&self) -> Result<(), String> {
        if !(1..=MAX_SESSION_TTL_SECS).contains(&self.session_ttl_secs) {
            return Err(format!(
                "session_ttl_secs = {} is out of range (1..={MAX_SESSION_TTL_SECS})",
                self.session_ttl_secs
            ));
        }
        if self.server_name.trim().is_empty() || self.server_name.len() > MAX_SERVER_NAME_LEN {
            return Err(format!(
                "server_name must be 1..={MAX_SERVER_NAME_LEN} bytes and not blank"
            ));
        }
        if self.server_description.len() > MAX_SERVER_DESCRIPTION_LEN {
            return Err(format!(
                "server_description is {} bytes (max {MAX_SERVER_DESCRIPTION_LEN})",
                self.server_description.len()
            ));
        }
        if !(1..=MAX_TLS_HANDSHAKE_TIMEOUT_SECS).contains(&self.tls_handshake_timeout_secs) {
            return Err(format!(
                "tls_handshake_timeout_secs = {} is out of range (1..={MAX_TLS_HANDSHAKE_TIMEOUT_SECS})",
                self.tls_handshake_timeout_secs
            ));
        }
        if !(1..=MAX_MAX_CONNECTIONS).contains(&self.max_connections) {
            return Err(format!(
                "max_connections = {} is out of range (1..={MAX_MAX_CONNECTIONS})",
                self.max_connections
            ));
        }
        if !(1..=self.max_connections).contains(&self.max_connections_per_ip) {
            return Err(format!(
                "max_connections_per_ip = {} is out of range (1..=max_connections)",
                self.max_connections_per_ip
            ));
        }
        if let Some(host) = &self.public_host {
            if host.is_empty()
                || host.len() > MAX_PUBLIC_HOST_LEN
                || host.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                return Err(format!(
                    "public_host must be a host name or address (1..={MAX_PUBLIC_HOST_LEN} bytes, no spaces)"
                ));
            }
        }
        if self.database.as_os_str().is_empty() {
            return Err("database must not be empty".into());
        }
        if self.files_root.as_os_str().is_empty() {
            return Err("files_root must not be empty".into());
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config {0}: {1}")]
    Read(PathBuf, std::io::Error),
    #[error("cannot parse config {0}: {1}")]
    Parse(PathBuf, toml::de::Error),
    #[error("invalid config {0}: {1}")]
    Invalid(PathBuf, String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_str(toml: &str) -> (Result<Config, ConfigError>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kdxd.toml");
        std::fs::write(&path, toml).unwrap();
        (Config::load(&path), dir)
    }

    fn invalid(toml: &str) -> String {
        match load_str(toml).0 {
            Err(ConfigError::Invalid(_, msg)) => msg,
            other => panic!("expected Invalid for {toml:?}, got {other:?}"),
        }
    }

    #[test]
    fn empty_file_is_the_valid_default() {
        let (config, dir) = load_str("");
        let config = config.unwrap();
        assert_eq!(config.bind, default_bind());
        assert_eq!(config.tls_handshake_timeout_secs, 10);
        assert_eq!(config.max_connections, 1024);
        assert_eq!(config.max_connections_per_ip, 8);
        assert!(config.public_host.is_none());
        // Relative defaults land next to the config file, not in the cwd.
        let base = std::path::absolute(dir.path()).unwrap();
        assert_eq!(config.database, base.join("kdx.db"));
        assert_eq!(config.files_root, base.join("files"));
    }

    #[test]
    fn shipped_example_config_loads() {
        let (config, _dir) = load_str(include_str!("../kdxd.example.toml"));
        config.unwrap();
    }

    #[test]
    fn relative_paths_resolve_against_config_dir() {
        let (config, dir) = load_str(
            "database = \"state/kdx.db\"\nfiles_root = \"/srv/kdx/files\"\n\
             [tls]\ncert_pem = \"cert.pem\"\nkey_pem = \"/etc/kdx/key.pem\"\n",
        );
        let config = config.unwrap();
        let base = std::path::absolute(dir.path()).unwrap();
        assert_eq!(config.database, base.join("state/kdx.db"));
        assert_eq!(config.files_root, PathBuf::from("/srv/kdx/files"));
        let tls = config.tls.unwrap();
        assert_eq!(tls.cert_pem, base.join("cert.pem"));
        assert_eq!(tls.key_pem, PathBuf::from("/etc/kdx/key.pem"));
    }

    #[test]
    fn port_zero_rejected_in_files_but_allowed_programmatically() {
        assert!(invalid("bind = \"0.0.0.0:0\"").contains("port 0"));
        let config = Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            ..Config::default()
        };
        assert!(config.validate().is_err());
        config.check_limits().unwrap();
    }

    #[test]
    fn huge_session_ttl_rejected() {
        // TOML's largest integer: used to panic `Instant + Duration` at login.
        assert!(invalid("session_ttl_secs = 9223372036854775807").contains("session_ttl_secs"));
        assert!(invalid("session_ttl_secs = 0").contains("session_ttl_secs"));
        let (ok, _dir) = load_str(&format!("session_ttl_secs = {MAX_SESSION_TTL_SECS}"));
        ok.unwrap();
    }

    #[test]
    fn server_name_and_description_bounds() {
        assert!(invalid("server_name = \"\"").contains("server_name"));
        assert!(invalid("server_name = \"   \"").contains("server_name"));
        let long_name = "n".repeat(MAX_SERVER_NAME_LEN + 1);
        assert!(invalid(&format!("server_name = \"{long_name}\"")).contains("server_name"));
        let (ok, _dir) = load_str(&format!("server_name = \"{}\"", "n".repeat(MAX_SERVER_NAME_LEN)));
        ok.unwrap();

        let long_desc = "d".repeat(MAX_SERVER_DESCRIPTION_LEN + 1);
        assert!(invalid(&format!("server_description = \"{long_desc}\""))
            .contains("server_description"));
        let big = "d".repeat(20_000);
        assert!(invalid(&format!("server_description = \"{big}\"")).contains("server_description"));
    }

    #[test]
    fn connection_limit_bounds() {
        assert!(invalid("max_connections = 0").contains("max_connections"));
        assert!(invalid("max_connections = 100000000").contains("max_connections"));
        assert!(invalid("max_connections_per_ip = 0").contains("max_connections_per_ip"));
        assert!(invalid("max_connections = 4\nmax_connections_per_ip = 5")
            .contains("max_connections_per_ip"));
        assert!(invalid("tls_handshake_timeout_secs = 0").contains("tls_handshake_timeout_secs"));
        assert!(invalid("tls_handshake_timeout_secs = 100000").contains("tls_handshake_timeout_secs"));
        let (ok, _dir) = load_str("max_connections = 4\nmax_connections_per_ip = 4");
        ok.unwrap();
    }

    #[test]
    fn public_host_validation() {
        assert!(invalid("public_host = \"\"").contains("public_host"));
        assert!(invalid("public_host = \"kdx example.net\"").contains("public_host"));
        let (ok, _dir) = load_str("public_host = \"kdx.example.net\"");
        assert_eq!(ok.unwrap().public_host.as_deref(), Some("kdx.example.net"));
    }

    #[test]
    fn unknown_fields_still_rejected() {
        assert!(matches!(load_str("bogus = 1").0, Err(ConfigError::Parse(..))));
    }
}
