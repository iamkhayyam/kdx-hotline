//! TLS trust policy. The default is trust-on-first-use (TOFU), SSH-style:
//! on first contact we pin the SHA-256 of the server's SubjectPublicKeyInfo
//! (SPKI) per `host:port` in a `known_hosts.toml` file; on later connects we
//! require the same key and warn loudly if it changed. Pinning the key (not
//! the whole certificate) means a certificate re-issued with the same key
//! (e.g. `certbot --reuse-key`) is still trusted.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use base64::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};

use crate::error::ClientError;
use crate::transfer::write_atomic;

/// The fingerprint format we store and compare: `sha256:<base64>` of the
/// DER-encoded SubjectPublicKeyInfo of the server's leaf certificate. Falls
/// back to hashing the whole certificate only if it cannot be parsed (such a
/// certificate can't complete a handshake anyway).
pub fn spki_fingerprint(cert: &CertificateDer<'_>) -> String {
    try_spki_fingerprint(cert).unwrap_or_else(|| legacy_cert_fingerprint(cert))
}

/// The SPKI fingerprint, or `None` if the certificate's DER can't be walked.
pub fn try_spki_fingerprint(cert: &CertificateDer<'_>) -> Option<String> {
    extract_spki(cert.as_ref()).map(fingerprint_of)
}

/// The pre-SPKI pin format (SHA-256 of the whole leaf certificate DER).
/// Still accepted on read so existing pins keep working; they are migrated
/// to the SPKI form on the next successful connect.
pub(crate) fn legacy_cert_fingerprint(cert: &CertificateDer<'_>) -> String {
    fingerprint_of(cert.as_ref())
}

fn fingerprint_of(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", base64::engine::general_purpose::STANDARD.encode(digest))
}

/// One DER element split off a buffer: (tag, whole TLV, content, rest).
type Tlv<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

/// Split one DER TLV off the front of `input`.
fn der_tlv(input: &[u8]) -> Option<Tlv<'_>> {
    let (&tag, after_tag) = input.split_first()?;
    if tag & 0x1F == 0x1F {
        return None; // multi-byte tags never appear in the fields we walk
    }
    let (&first, after_len) = after_tag.split_first()?;
    let (len, header_len) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 || after_len.len() < n {
            return None; // indefinite or absurd length
        }
        let len = after_len[..n]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | b as usize);
        (len, 2 + n)
    };
    let end = header_len.checked_add(len)?;
    if input.len() < end {
        return None;
    }
    Some((tag, &input[..end], &input[header_len..end], &input[end..]))
}

/// Walk `Certificate → tbsCertificate` to its `subjectPublicKeyInfo` and
/// return that field's full DER encoding.
fn extract_spki(cert: &[u8]) -> Option<&[u8]> {
    const SEQUENCE: u8 = 0x30;
    let (tag, _, cert_body, _) = der_tlv(cert)?;
    if tag != SEQUENCE {
        return None;
    }
    let (tag, _, tbs, _) = der_tlv(cert_body)?;
    if tag != SEQUENCE {
        return None;
    }
    let mut rest = tbs;
    // Optional `[0] EXPLICIT version`.
    let (tag, _, _, after) = der_tlv(rest)?;
    if tag == 0xA0 {
        rest = after;
    }
    // serialNumber INTEGER, signature, issuer, validity, subject.
    for want in [0x02, SEQUENCE, SEQUENCE, SEQUENCE, SEQUENCE] {
        let (tag, _, _, after) = der_tlv(rest)?;
        if tag != want {
            return None;
        }
        rest = after;
    }
    let (tag, spki, _, _) = der_tlv(rest)?;
    (tag == SEQUENCE).then_some(spki)
}

/// Is `s` a well-formed `sha256:<base64 of 32 bytes>` fingerprint?
pub fn is_valid_fingerprint(s: &str) -> bool {
    let Some(b64) = s.strip_prefix("sha256:") else {
        return false;
    };
    b64.len() == 44
        && base64::engine::general_purpose::STANDARD
            .decode(b64)
            .is_ok_and(|d| d.len() == 32)
}

/// A stored `host:port` key: a port, a non-empty host, and none of the
/// characters that would break the quoting or smuggle extra lines.
fn is_safe_key(key: &str) -> bool {
    let Some((host, port)) = key.rsplit_once(':') else {
        return false;
    };
    !host.is_empty()
        && port.parse::<u16>().is_ok()
        && !key
            .chars()
            .any(|c| c == '"' || c == '\\' || c.is_whitespace() || c.is_control())
}

/// Largest known_hosts file we'll read (far beyond any real pin set).
const MAX_KNOWN_HOSTS_BYTES: u64 = 4 * 1024 * 1024;

/// Serializes read-modify-write of the pin file within this process.
static PIN_LOCK: Mutex<()> = Mutex::new(());

fn lock_pins() -> MutexGuard<'static, ()> {
    PIN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Persistent map of `host:port` → pinned fingerprint.
///
/// The file is parsed strictly: an unreadable file (other than "not found"),
/// invalid UTF-8, or any malformed line is an error rather than "no pins",
/// so corruption can never silently downgrade a changed-key warning into a
/// first-contact prompt, and `pin` never rewrites a file it couldn't read.
/// Writes are atomic (temp file + fsync + rename).
pub struct KnownHosts {
    path: PathBuf,
}

impl KnownHosts {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("known_hosts.toml"),
        }
    }

    fn corrupt(&self, why: impl std::fmt::Display) -> ClientError {
        ClientError::KnownHosts(format!("{}: {why}", self.path.display()))
    }

    fn read_all(&self) -> Result<Vec<(String, String)>, ClientError> {
        use std::io::Read;
        let file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(self.corrupt(e)),
        };
        let mut bytes = Vec::new();
        file.take(MAX_KNOWN_HOSTS_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| self.corrupt(e))?;
        if bytes.len() as u64 > MAX_KNOWN_HOSTS_BYTES {
            return Err(self.corrupt("file is too large"));
        }
        let text = String::from_utf8(bytes).map_err(|_| self.corrupt("not valid UTF-8"))?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);

        let mut entries: Vec<(String, String)> = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = parse_entry(line)
                .ok_or_else(|| self.corrupt(format!("line {} is malformed", n + 1)))?;
            if entries.iter().any(|(k, _)| *k == key) {
                return Err(self.corrupt(format!("line {}: duplicate entry for {key}", n + 1)));
            }
            entries.push((key, value));
        }
        Ok(entries)
    }

    /// The pinned fingerprint for `host:port`, if any. Errors if the pin
    /// file exists but can't be read or parsed — callers must then refuse
    /// to connect rather than treat the host as new.
    pub fn get(&self, host: &str, port: u16) -> Result<Option<String>, ClientError> {
        let key = format!("{host}:{port}");
        Ok(self
            .read_all()?
            .into_iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v))
    }

    /// Pin (or replace) the fingerprint for a host. `host` must be a valid
    /// DNS name or IP address and `fingerprint` a `sha256:<base64>` value.
    pub fn pin(&self, host: &str, port: u16, fingerprint: &str) -> Result<(), ClientError> {
        if ServerName::try_from(host.to_string()).is_err() {
            return Err(ClientError::InvalidServerName(host.to_string()));
        }
        let key = format!("{host}:{port}");
        if !is_safe_key(&key) {
            return Err(ClientError::InvalidServerName(host.to_string()));
        }
        if !is_valid_fingerprint(fingerprint) {
            return Err(ClientError::InvalidInput("malformed fingerprint".into()));
        }
        let _guard = lock_pins();
        let mut entries = self.read_all()?;
        entries.retain(|(k, _)| *k != key);
        entries.push((key, fingerprint.to_string()));
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body: String = entries
            .iter()
            .map(|(k, v)| format!("\"{k}\" = \"{v}\"\n"))
            .collect();
        write_atomic(&self.path, body.as_bytes())?;
        Ok(())
    }
}

/// Parse one `"host:port" = "sha256:..."` line, validating both sides.
fn parse_entry(line: &str) -> Option<(String, String)> {
    let rest = line.strip_prefix('"')?;
    let (key, rest) = rest.split_once('"')?;
    let rest = rest.trim_start().strip_prefix('=')?.trim_start();
    let value = rest.strip_prefix('"')?.strip_suffix('"')?;
    (is_safe_key(key) && is_valid_fingerprint(value))
        .then(|| (key.to_string(), value.to_string()))
}

/// What the verifier observed during one handshake. `connect()` reads it to
/// tell a genuine TOFU refusal apart from any other TLS failure.
#[derive(Debug, Default, Clone)]
pub struct TofuOutcome {
    /// SPKI fingerprint of the certificate the server presented.
    pub seen: Option<String>,
    /// The verifier itself refused the certificate (unknown/changed key).
    pub rejected: bool,
    /// The pin matched only in the legacy whole-certificate form; the
    /// caller should re-pin with `seen`.
    pub legacy_match: bool,
}

pub type OutcomeSlot = Arc<Mutex<TofuOutcome>>;

fn lock_outcome(slot: &OutcomeSlot) -> MutexGuard<'_, TofuOutcome> {
    slot.lock().unwrap_or_else(|e| e.into_inner())
}

/// Snapshot the verifier's outcome.
pub fn read_outcome(slot: &OutcomeSlot) -> TofuOutcome {
    lock_outcome(slot).clone()
}

/// rustls verifier implementing TOFU. Because the verifier callback is
/// synchronous and cannot prompt, it records what it saw into a side-slot
/// and fails the handshake on an unknown/changed key; `connect()` reads the
/// slot to build a `ClientError::UntrustedCertificate`.
#[derive(Debug)]
pub struct TofuVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
    expected: Option<String>,
    outcome: OutcomeSlot,
}

impl TofuVerifier {
    pub fn new(provider: Arc<rustls::crypto::CryptoProvider>, expected: Option<String>) -> Self {
        Self {
            provider,
            expected,
            outcome: Arc::new(Mutex::new(TofuOutcome::default())),
        }
    }

    /// Shared handle to read what the handshake presented.
    pub fn outcome_slot(&self) -> OutcomeSlot {
        self.outcome.clone()
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
        let Some(fingerprint) = try_spki_fingerprint(end_entity) else {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        };
        let mut outcome = lock_outcome(&self.outcome);
        outcome.seen = Some(fingerprint.clone());
        match &self.expected {
            Some(expected) if *expected == fingerprint => Ok(ServerCertVerified::assertion()),
            Some(expected) if *expected == legacy_cert_fingerprint(end_entity) => {
                outcome.legacy_match = true;
                Ok(ServerCertVerified::assertion())
            }
            _ => {
                outcome.rejected = true;
                Err(rustls::Error::General("untrusted certificate (TOFU)".into()))
            }
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
    outcome: OutcomeSlot,
}

#[cfg(feature = "dangerous")]
impl AcceptAnyVerifier {
    pub fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self {
            provider,
            outcome: Arc::new(Mutex::new(TofuOutcome::default())),
        }
    }
    pub fn outcome_slot(&self) -> OutcomeSlot {
        self.outcome.clone()
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
        lock_outcome(&self.outcome).seen = Some(spki_fingerprint(end_entity));
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

    fn fp(byte: u8) -> String {
        fingerprint_of(&[byte])
    }

    #[test]
    fn known_hosts_pin_and_get() {
        let dir = tempfile::tempdir().unwrap();
        let kh = KnownHosts::new(dir.path());
        assert!(kh.get("host", 10700).unwrap().is_none());
        kh.pin("host", 10700, &fp(1)).unwrap();
        assert_eq!(kh.get("host", 10700).unwrap(), Some(fp(1)));
        // Re-pinning replaces.
        kh.pin("host", 10700, &fp(2)).unwrap();
        assert_eq!(kh.get("host", 10700).unwrap(), Some(fp(2)));
        // Other hosts unaffected.
        kh.pin("other", 10700, &fp(3)).unwrap();
        assert_eq!(kh.get("host", 10700).unwrap(), Some(fp(2)));
        assert_eq!(kh.get("other", 10700).unwrap(), Some(fp(3)));
        // IPv6 literals work as keys.
        kh.pin("::1", 10700, &fp(4)).unwrap();
        assert_eq!(kh.get("::1", 10700).unwrap(), Some(fp(4)));
    }

    #[test]
    fn corrupt_known_hosts_is_an_error_not_an_empty_list() {
        let dir = tempfile::tempdir().unwrap();
        let kh = KnownHosts::new(dir.path());
        kh.pin("a.example", 10700, &fp(1)).unwrap();
        let path = dir.path().join("known_hosts.toml");

        // A non-UTF-8 byte: lookups fail loudly, and pinning another host
        // refuses to rewrite (and so wipe) the file.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend_from_slice(b"\"b.example:1\" = \"\xFF\"\n");
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(kh.get("a.example", 10700), Err(ClientError::KnownHosts(_))));
        assert!(kh.pin("b.example", 10700, &fp(2)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "file left untouched");

        // A malformed (but UTF-8) line is also an error.
        std::fs::write(&path, format!("\"a.example:10700\" = \"{}\"\ngarbage\n", fp(1))).unwrap();
        assert!(kh.get("a.example", 10700).is_err());

        // A leading BOM is tolerated.
        std::fs::write(&path, format!("\u{feff}\"a.example:10700\" = \"{}\"\n", fp(1))).unwrap();
        assert_eq!(kh.get("a.example", 10700).unwrap(), Some(fp(1)));
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_known_hosts_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        // A directory where the file should be: EISDIR, not NotFound.
        std::fs::create_dir(dir.path().join("known_hosts.toml")).unwrap();
        let kh = KnownHosts::new(dir.path());
        assert!(kh.get("a.example", 10700).is_err());
    }

    #[test]
    fn pin_validates_host_and_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let kh = KnownHosts::new(dir.path());
        assert!(kh.pin("h\"\nx", 10700, &fp(1)).is_err());
        assert!(kh.pin("bad host", 10700, &fp(1)).is_err());
        assert!(kh.pin("host", 10700, "sha256:abc").is_err());
        assert!(kh.pin("host", 10700, "sha256:BOGUS\"\n\"x:1\" = \"y").is_err());
        assert!(!dir.path().join("known_hosts.toml").exists());
    }

    #[test]
    fn spki_fingerprint_is_stable_across_certs_with_the_same_key() {
        let key = rcgen::KeyPair::generate().unwrap();
        let a = rcgen::CertificateParams::new(vec!["a.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let b = rcgen::CertificateParams::new(vec!["b.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let other_key = rcgen::KeyPair::generate().unwrap();
        let c = rcgen::CertificateParams::new(vec!["a.example".into()])
            .unwrap()
            .self_signed(&other_key)
            .unwrap();

        let (a, b, c) = (a.der().clone(), b.der().clone(), c.der().clone());
        assert_ne!(a.as_ref(), b.as_ref(), "distinct certificates");
        let fa = try_spki_fingerprint(&a).expect("parseable");
        assert_eq!(fa, try_spki_fingerprint(&b).unwrap());
        assert_ne!(fa, try_spki_fingerprint(&c).unwrap());
        assert!(is_valid_fingerprint(&fa));
        // It really is the SPKI hash, not the whole certificate's.
        assert_ne!(fa, legacy_cert_fingerprint(&a));
        assert_eq!(fa, fingerprint_of(&key.public_key_der()));
    }

    #[test]
    fn verifier_accepts_legacy_pins_and_flags_only_its_own_rejections() {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["a.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let der = cert.der().clone();
        let name = ServerName::try_from("a.example").unwrap();
        let now = UnixTime::now();

        let legacy = TofuVerifier::new(provider.clone(), Some(legacy_cert_fingerprint(&der)));
        assert!(legacy.verify_server_cert(&der, &[], &name, &[], now).is_ok());
        let out = read_outcome(&legacy.outcome_slot());
        assert!(out.legacy_match && !out.rejected);
        assert_eq!(out.seen, try_spki_fingerprint(&der));

        let changed = TofuVerifier::new(provider.clone(), Some(fp(9)));
        assert!(changed.verify_server_cert(&der, &[], &name, &[], now).is_err());
        assert!(read_outcome(&changed.outcome_slot()).rejected);

        let garbage = CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x01]);
        let v = TofuVerifier::new(provider, None);
        assert!(v.verify_server_cert(&garbage, &[], &name, &[], now).is_err());
        assert!(
            !read_outcome(&v.outcome_slot()).rejected,
            "parse failure is not a TOFU refusal"
        );
    }
}
