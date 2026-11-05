//! Shared test-client plumbing: a TLS client that trusts the server's
//! per-run self-signed dev certificate, plus frame/handshake/login helpers.
//!
//! Each test binary compiles `common` separately and not all use every
//! helper, so unused-function warnings per binary are expected.
#![allow(dead_code)]

use std::sync::Arc;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use kdx_protocol::messages::{
    AuthChallenge, AuthRequest, AuthResponse, AuthResult, HandshakeInit, HandshakeResp,
};
use kdx_protocol::{KdxCodec, KdxFrame, PacketFlags, PacketHeader, PacketType, PROTOCOL_VERSION};
use kdxd::Config;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::codec::Framed;

pub type TlsClient = Framed<tokio_rustls::client::TlsStream<TcpStream>, KdxCodec>;

/// Accept any server certificate — the dev server generates a fresh
/// self-signed cert per run. Test-only trust policy.
#[derive(Debug)]
struct TrustAnything(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for TrustAnything {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
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
            &self.0.signature_verification_algorithms,
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
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn test_config(dir: &tempfile::TempDir) -> Config {
    Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        database: dir.path().join("kdx.db"),
        files_root: dir.path().join("files"),
        ..Config::default()
    }
}

pub async fn connect_tls(addr: std::net::SocketAddr) -> TlsClient {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls_config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAnything(provider)))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    Framed::new(tls, KdxCodec::default())
}

pub fn frame(packet_type: PacketType, sequence: u32, payload: Bytes) -> KdxFrame {
    KdxFrame {
        header: PacketHeader {
            version: PROTOCOL_VERSION,
            packet_type,
            flags: PacketFlags::empty(),
            sequence,
            length: payload.len() as u32,
        },
        payload,
    }
}

/// Complete the KDX version handshake; asserts the server accepts.
pub async fn kdx_handshake(client: &mut TlsClient, seq: &mut u32) {
    let init = HandshakeInit {
        version: PROTOCOL_VERSION,
        features: 0,
    };
    client
        .send(frame(PacketType::HandshakeInit, bump(seq), init.encode()))
        .await
        .unwrap();
    let resp_frame = client.next().await.unwrap().unwrap();
    assert_eq!(resp_frame.header.packet_type, PacketType::HandshakeResp);
    let resp = HandshakeResp::decode(&resp_frame.payload).unwrap();
    assert_eq!(resp.version, PROTOCOL_VERSION);
}

pub fn bump(seq: &mut u32) -> u32 {
    let s = *seq;
    *seq += 1;
    s
}

/// This connection's TLS exporter value — what the server binds login
/// proofs to (it reads the same value from its end of the session).
pub fn channel_binding(client: &TlsClient) -> [u8; kdx_crypto::CHANNEL_BINDING_LEN] {
    client
        .get_ref()
        .get_ref()
        .1
        .export_keying_material(
            [0u8; kdx_crypto::CHANNEL_BINDING_LEN],
            kdx_crypto::TLS_EXPORTER_LABEL,
            None,
        )
        .unwrap()
}

/// Send `AuthRequest` and return the server's `AuthChallenge`.
pub async fn request_challenge(
    client: &mut TlsClient,
    seq: &mut u32,
    username: &str,
) -> AuthChallenge {
    client
        .send(frame(
            PacketType::AuthRequest,
            bump(seq),
            AuthRequest {
                username: username.into(),
            }
            .encode(),
        ))
        .await
        .unwrap();
    let challenge_frame = client.next().await.unwrap().unwrap();
    assert_eq!(
        challenge_frame.header.packet_type,
        PacketType::AuthChallenge
    );
    AuthChallenge::decode(&challenge_frame.payload).unwrap()
}

/// Compute the client proof for `challenge`, bound to `binding`.
pub fn prove(
    username: &str,
    password: &str,
    challenge: &AuthChallenge,
    binding: &[u8; kdx_crypto::CHANNEL_BINDING_LEN],
) -> kdx_crypto::ClientProof {
    kdx_crypto::client_proof(
        password,
        &kdx_crypto::AuthContext {
            username,
            challenge: &challenge.challenge,
            salt: &challenge.salt,
            params: kdx_crypto::KdfParams {
                m_cost: challenge.m_cost,
                t_cost: challenge.t_cost,
                p_cost: challenge.p_cost,
            },
            channel_binding: binding,
        },
    )
    .unwrap()
}

/// Send `proof` as the `AuthResponse` and return the `AuthResult`.
pub async fn send_proof(client: &mut TlsClient, seq: &mut u32, proof: [u8; 32]) -> AuthResult {
    client
        .send(frame(
            PacketType::AuthResponse,
            bump(seq),
            AuthResponse { response: proof }.encode(),
        ))
        .await
        .unwrap();
    let result_frame = client.next().await.unwrap().unwrap();
    assert_eq!(result_frame.header.packet_type, PacketType::AuthResult);
    AuthResult::decode(&result_frame.payload).unwrap()
}

/// One full login round (channel-bound proof); returns the `AuthResult`.
/// A successful result's server signature is verified.
pub async fn login_result(
    client: &mut TlsClient,
    seq: &mut u32,
    username: &str,
    password: &str,
) -> AuthResult {
    let challenge = request_challenge(client, seq, username).await;
    let binding = channel_binding(client);
    let proof = prove(username, password, &challenge, &binding);
    let result = send_proof(client, seq, proof.proof).await;
    if result.success {
        assert!(
            proof.verify_server_signature(&result.server_signature),
            "server signature did not verify"
        );
    }
    result
}

/// Log in and assert success.
pub async fn login(client: &mut TlsClient, seq: &mut u32, username: &str, password: &str) {
    let result = login_result(client, seq, username, password).await;
    assert!(result.success, "{}", result.message);
}
