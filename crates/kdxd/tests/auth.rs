//! M3 exit criterion: challenge-response login against a seeded SQLite
//! account yields a session with the correct effective privileges; wrong
//! passwords are rejected.

mod common;

use common::{bump, connect_tls, frame, kdx_handshake, test_config, TlsClient};
use futures_util::{SinkExt, StreamExt};
use kdx_crypto::{client_response, hash_password, KdfParams};
use kdx_protocol::messages::{AuthChallenge, AuthRequest, AuthResponse, AuthResult};
use kdx_protocol::PacketType;
use kdx_server_core::auth::Privileges;
use kdx_storage::accounts;
use kdxd::serve;

async fn login(client: &mut TlsClient, seq: &mut u32, username: &str, password: &str) -> AuthResult {
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
    assert_eq!(challenge_frame.header.packet_type, PacketType::AuthChallenge);
    let challenge = AuthChallenge::decode(&challenge_frame.payload).unwrap();

    let response = client_response(
        password,
        &challenge.salt,
        &KdfParams {
            m_cost: challenge.m_cost,
            t_cost: challenge.t_cost,
            p_cost: challenge.p_cost,
        },
        &challenge.challenge,
    )
    .unwrap();
    client
        .send(frame(
            PacketType::AuthResponse,
            bump(seq),
            AuthResponse { response }.encode(),
        ))
        .await
        .unwrap();

    let result_frame = client.next().await.unwrap().unwrap();
    assert_eq!(result_frame.header.packet_type, PacketType::AuthResult);
    AuthResult::decode(&result_frame.payload).unwrap()
}

#[tokio::test]
async fn full_login_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();

    // Seed an account with overrides: PowerUser granted USER_KICK, revoked
    // FILE_DELETE.
    let pool = kdx_storage::connect(&dir.path().join("kdx.db")).await.unwrap();
    let phc = hash_password("correct horse").unwrap();
    accounts::create(&pool, "phraq", &phc, 2).await.unwrap();
    accounts::set_overrides(
        &pool,
        "phraq",
        Privileges::USER_KICK.bits() as i64,
        Privileges::FILE_DELETE.bits() as i64,
    )
    .await
    .unwrap();

    let mut client = connect_tls(server.local_addr).await;
    let mut seq = 0;
    kdx_handshake(&mut client, &mut seq).await;

    let result = login(&mut client, &mut seq, "phraq", "correct horse").await;
    assert!(result.success, "login failed: {}", result.message);
    assert_eq!(result.class, 2);
    assert_ne!(result.session_id, [0u8; 16]);

    // The server-side session reflects base class + overrides.
    let session_id = uuid::Uuid::from_bytes(result.session_id);
    let session = server.ctx.auth.validate(session_id).unwrap();
    assert!(session.privileges.contains(Privileges::USER_KICK));
    assert!(!session.privileges.contains(Privileges::FILE_DELETE));
    assert!(session.privileges.contains(Privileges::CHAT_CREATE_ROOM));

    server.handle.abort();
}

#[tokio::test]
async fn wrong_password_rejected_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();

    let pool = kdx_storage::connect(&dir.path().join("kdx.db")).await.unwrap();
    let phc = hash_password("correct horse").unwrap();
    accounts::create(&pool, "phraq", &phc, 1).await.unwrap();

    let mut client = connect_tls(server.local_addr).await;
    let mut seq = 0;
    kdx_handshake(&mut client, &mut seq).await;

    let result = login(&mut client, &mut seq, "phraq", "battery staple").await;
    assert!(!result.success);
    assert_eq!(result.session_id, [0u8; 16]);

    server.handle.abort();
}
