//! M2 exit criterion: a real TLS client completes the TLS + KDX version
//! handshake against an in-process kdxd and exchanges Ping/Pong.

use std::sync::Arc;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use kdx_protocol::messages::{HandshakeInit, HandshakeResp};
use kdx_protocol::{KdxCodec, KdxFrame, PacketFlags, PacketHeader, PacketType, PROTOCOL_VERSION};
use kdxd::{serve, Config};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::codec::Framed;

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

async fn connect_tls(
    addr: std::net::SocketAddr,
) -> Framed<tokio_rustls::client::TlsStream<TcpStream>, KdxCodec> {
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

fn frame(packet_type: PacketType, sequence: u32, payload: Bytes) -> KdxFrame {
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

#[tokio::test]
async fn tls_handshake_then_ping_pong() {
    let config = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        tls: None, // self-signed dev cert
    };
    let server = serve(config).await.unwrap();

    let mut client = connect_tls(server.local_addr).await;

    // KDX handshake
    let init = HandshakeInit {
        version: PROTOCOL_VERSION,
        features: 0,
    };
    client
        .send(frame(PacketType::HandshakeInit, 0, init.encode()))
        .await
        .unwrap();
    let resp_frame = client.next().await.unwrap().unwrap();
    assert_eq!(resp_frame.header.packet_type, PacketType::HandshakeResp);
    let resp = HandshakeResp::decode(&resp_frame.payload).unwrap();
    assert_eq!(resp.version, PROTOCOL_VERSION);

    // Ping/Pong with payload echo
    client
        .send(frame(PacketType::Ping, 1, Bytes::from_static(b"kdx lives")))
        .await
        .unwrap();
    let pong = client.next().await.unwrap().unwrap();
    assert_eq!(pong.header.packet_type, PacketType::Pong);
    assert_eq!(&pong.payload[..], b"kdx lives");

    // Clean disconnect
    client
        .send(frame(PacketType::Disconnect, 2, Bytes::new()))
        .await
        .unwrap();

    server.handle.abort();
}

#[tokio::test]
async fn plaintext_client_is_rejected() {
    let config = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        tls: None,
    };
    let server = serve(config).await.unwrap();

    // Speak raw KDX without TLS: the server's TLS accept must fail and the
    // connection must die rather than answer.
    let tcp = TcpStream::connect(server.local_addr).await.unwrap();
    let mut client = Framed::new(tcp, KdxCodec::default());
    let init = HandshakeInit {
        version: PROTOCOL_VERSION,
        features: 0,
    };
    client
        .send(frame(PacketType::HandshakeInit, 0, init.encode()))
        .await
        .unwrap();

    // Either immediate EOF or a framing error (TLS alert bytes) — anything
    // but a valid HandshakeResp.
    match client.next().await {
        None => {}
        Some(Err(_)) => {}
        Some(Ok(f)) => panic!("server answered a plaintext client: {f:?}"),
    }

    server.handle.abort();
}
