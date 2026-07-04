//! M2 exit criterion: a real TLS client completes the TLS + KDX version
//! handshake against an in-process kdxd and exchanges Ping/Pong.

mod common;

use bytes::Bytes;
use common::{bump, connect_tls, frame, kdx_handshake, test_config};
use futures_util::{SinkExt, StreamExt};
use kdx_protocol::messages::HandshakeInit;
use kdx_protocol::{KdxCodec, PacketType, PROTOCOL_VERSION};
use kdxd::serve;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

#[tokio::test]
async fn tls_handshake_then_ping_pong() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();

    let mut client = connect_tls(server.local_addr).await;
    let mut seq = 0;
    kdx_handshake(&mut client, &mut seq).await;

    // Ping/Pong with payload echo (works pre-auth: keepalive at the login
    // prompt is allowed).
    client
        .send(frame(
            PacketType::Ping,
            bump(&mut seq),
            Bytes::from_static(b"kdx lives"),
        ))
        .await
        .unwrap();
    let pong = client.next().await.unwrap().unwrap();
    assert_eq!(pong.header.packet_type, PacketType::Pong);
    assert_eq!(&pong.payload[..], b"kdx lives");

    // Clean disconnect
    client
        .send(frame(PacketType::Disconnect, bump(&mut seq), Bytes::new()))
        .await
        .unwrap();

    server.handle.abort();
}

#[tokio::test]
async fn plaintext_client_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();

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
