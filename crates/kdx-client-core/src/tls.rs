//! TLS trust policy. The default is trust-on-first-use (TOFU), SSH-style:
//! on first contact we pin the SHA-256 of the server's SubjectPublicKeyInfo
//! (SPKI) per `host:port` in a `known_hosts.toml` file; on later connects we
//! require the same key and warn loudly if it changed.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};

use crate::error::ClientError;

/// The fingerprint format we store and compare: `sha256:<base64>`.
pub fn spki_fingerprint(cert: &CertificateDer<'_>) -> String {
    // The DER cert contains the SPKI; hashing the whole cert is simpler than
    // parsing out the SPKI and, for TOFU pinning, equally sound as long as we
    // are consistent. We hash the leaf certificate DER.
    let digest = Sha256::digest(cert.as_ref());
    format!("sha256:{}", base64::engine::general_purpose::STANDARD.encode(digest))
}

/// Persistent map of `host:port` → pinned fingerprint.
pub struct KnownHosts {
    path: PathBuf,
}

impl KnownHosts {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("known_hosts.toml"),
        }
    }

    fn read_all(&self) -> Vec<(String, String)> {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        // Minimal `"key" = "value"` parsing — no toml dep in this crate.
        text.lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    return None;
                }
                let (k, v) = line.split_once('=')?;
                Some((
                    k.trim().trim_matches('"').to_string(),
                    v.trim().trim_matches('"').to_string(),
                ))
            })
            .collect()
    }

    pub fn get(&self, host: &str, port: u16) -> Option<String> {
        let key = format!("{host}:{port}");
        self.read_all()
            .into_iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v)
    }

    /// Pin (or replace) the fingerprint for a host.
    pub fn pin(&self, host: &str, port: u16, fingerprint: &str) -> Result<(), ClientError> {
        let key = format!("{host}:{port}");
        let mut entries = self.read_all();
        entries.retain(|(k, _)| *k != key);
        entries.push((key, fingerprint.to_string()));
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body: String = entries
            .iter()
            .map(|(k, v)| format!("\"{k}\" = \"{v}\"\n"))
            .collect();
        std::fs::write(&self.path, body)?;
        Ok(())
    }
}

/// rustls verifier implementing TOFU. Because the verifier callback is
/// synchronous and cannot prompt, it records the fingerprint it saw into a
/// side-slot and fails the handshake on an unknown/changed key; `connect()`
/// reads the slot to build a `ClientError::UntrustedCertificate`.
#[derive(Debug)]
pub struct TofuVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
    expected: Option<String>,
    /// Fingerprint of the cert actually presented (filled during verify).
    seen: Arc<Mutex<Option<String>>>,
}

impl TofuVerifier {
    pub fn new(provider: Arc<rustls::crypto::CryptoProvider>, expected: Option<String>) -> Self {
        Self {
            provider,
            expected,
            seen: Arc::new(Mutex::new(None)),
        }
    }

    /// Shared handle to read what fingerprint the handshake presented.
    pub fn seen_slot(&self) -> Arc<Mutex<Option<String>>> {
        self.seen.clone()
    }
}

impl ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fingerprint = spki_fingerprint(end_entity);
        *self.seen.lock().unwrap() = Some(fingerprint.clone());
        match &self.expected {
            Some(expected) if *expected == fingerprint => Ok(ServerCertVerified::assertion()),
            _ => Err(rustls::Error::General("untrusted certificate (TOFU)".into())),
        }
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
            &self.provider.signature_verification_algorithms,
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
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Test-only verifier that accepts any certificate but still records the
/// fingerprint it saw (so tests can assert on it).
#[cfg(feature = "dangerous")]
#[derive(Debug)]
pub struct AcceptAnyVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
    seen: Arc<Mutex<Option<String>>>,
}

#[cfg(feature = "dangerous")]
impl AcceptAnyVerifier {
    pub fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self {
            provider,
            seen: Arc::new(Mutex::new(None)),
        }
    }
    pub fn seen_slot(&self) -> Arc<Mutex<Option<String>>> {
        self.seen.clone()
    }
}

#[cfg(feature = "dangerous")]
impl ServerCertVerifier for AcceptAnyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _i: &[CertificateDer<'_>],
        _n: &ServerName<'_>,
        _o: &[u8],
        _t: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.seen.lock().unwrap() = Some(spki_fingerprint(end_entity));
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_hosts_pin_and_get() {
        let dir = tempfile::tempdir().unwrap();
        let kh = KnownHosts::new(dir.path());
        assert!(kh.get("host", 10700).is_none());
        kh.pin("host", 10700, "sha256:abc").unwrap();
        assert_eq!(kh.get("host", 10700).as_deref(), Some("sha256:abc"));
        // Re-pinning replaces.
        kh.pin("host", 10700, "sha256:def").unwrap();
        assert_eq!(kh.get("host", 10700).as_deref(), Some("sha256:def"));
        // Other hosts unaffected.
        kh.pin("other", 10700, "sha256:xyz").unwrap();
        assert_eq!(kh.get("host", 10700).as_deref(), Some("sha256:def"));
        assert_eq!(kh.get("other", 10700).as_deref(), Some("sha256:xyz"));
    }
}
