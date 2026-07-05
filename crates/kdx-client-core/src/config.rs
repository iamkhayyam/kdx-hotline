use std::path::PathBuf;

/// How the client decides whether to trust a server's TLS certificate.
#[derive(Debug, Clone, Default)]
pub enum TrustPolicy {
    /// Trust-on-first-use: pin the server's SPKI fingerprint on first
    /// contact, warn loudly if it ever changes. The KDX default.
    #[default]
    Tofu,
    /// Verify against the OS/webpki root store (for real CA-signed certs).
    System,
    /// Accept any certificate. Test-only; requires the `dangerous` feature.
    #[cfg(feature = "dangerous")]
    InsecureAcceptAny,
}

/// Connection parameters.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub host: String,
    pub port: u16,
    pub trust: TrustPolicy,
    /// Where `known_hosts.toml` and transfer resume sidecars live.
    pub data_dir: PathBuf,
}

impl ClientConfig {
    pub fn new(host: impl Into<String>, port: u16, data_dir: impl Into<PathBuf>) -> Self {
        Self {
            host: host.into(),
            port,
            trust: TrustPolicy::default(),
            data_dir: data_dir.into(),
        }
    }
}
