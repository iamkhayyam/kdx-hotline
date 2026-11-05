//! M3 exit criterion: challenge-response login against a seeded SQLite
//! account yields a session with the correct effective privileges; wrong
//! passwords are rejected. Protocol v2: the proof is SCRAM-style and bound
//! to the TLS channel, so a relayed proof or a stolen database is not enough
//! to log in.

mod common;

use common::{
    channel_binding, connect_tls, kdx_handshake, login_result, prove, request_challenge,
    send_proof, test_config, TlsClient,
};
use kdx_crypto::{
    hash_password, password_change_proof, AuthContext, KdfParams, PasswordChangeContext,
    StoredCredential,
};
use kdx_protocol::messages::{
    AuthResult, Credential, PasswordChangeBegin, PasswordChangeChallenge, PasswordChangeProof,
    PasswordChangeResult,
};
use kdx_protocol::PacketType;
use kdx_server_core::auth::Privileges;
use kdx_storage::accounts;
use kdxd::serve;
use sha2::{Digest, Sha256};

/// A protocol-v1 row for password "legacy pass" (Argon2id defaults,
/// 16-byte salt), as the old server stored it.
const LEGACY_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$a2R4bGVnYWN5c2FsdDE2IQ$1MaVnJW11DoDj6dBG8Pyjl8ME3i+BpQLmf5+5xVimQU";

async fn handshaken(addr: std::net::SocketAddr) -> (TlsClient, u32) {
    let mut client = connect_tls(addr).await;
    let mut seq = 0;
    kdx_handshake(&mut client, &mut seq).await;
    (client, seq)
}

/// Send a bare `AuthRequest` and return the `AuthResult` the server answers
/// it with directly (throttled / invalid username), asserting there was no
/// challenge round.
async fn refused_at_request(client: &mut TlsClient, seq: &mut u32, username: &str) -> AuthResult {
    use futures_util::{SinkExt, StreamExt};
    client
        .send(common::frame(
            PacketType::AuthRequest,
            common::bump(seq),
            kdx_protocol::messages::AuthRequest {
                username: username.into(),
            }
            .encode(),
        ))
        .await
        .unwrap();
    let frame = client.next().await.unwrap().unwrap();
    assert_eq!(frame.header.packet_type, PacketType::AuthResult);
    AuthResult::decode(&frame.payload).unwrap()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let inner = Sha256::new()
        .chain_update(block.map(|b| b ^ 0x36))
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(block.map(|b| b ^ 0x5c))
        .chain_update(inner)
        .finalize()
        .into()
}

/// A DB-only attacker's attempt: (stolen record, AuthMessage, challenge) →
/// proof.
type Forgery = fn(&StoredCredential, &[u8], &[u8; 32]) -> [u8; 32];

fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

#[tokio::test]
async fn full_login_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();

    // Seed an account with overrides (one INSERT): PowerUser granted
    // USER_KICK, revoked FILE_DELETE.
    let pool = kdx_storage::connect(&dir.path().join("kdx.db"))
        .await
        .unwrap();
    let credential = hash_password("correct horse").unwrap();
    accounts::create(
        &pool,
        "phraq",
        &credential,
        2,
        Privileges::USER_KICK.bits() as i64,
        Privileges::FILE_DELETE.bits() as i64,
    )
    .await
    .unwrap();

    let (mut client, mut seq) = handshaken(server.local_addr).await;
    // `login_result` also checks the server signature.
    let result = login_result(&mut client, &mut seq, "phraq", "correct horse").await;
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

    let pool = kdx_storage::connect(&dir.path().join("kdx.db"))
        .await
        .unwrap();
    let credential = hash_password("correct horse").unwrap();
    accounts::create(&pool, "phraq", &credential, 1, 0, 0)
        .await
        .unwrap();

    let (mut client, mut seq) = handshaken(server.local_addr).await;
    let result = login_result(&mut client, &mut seq, "phraq", "battery staple").await;
    assert!(!result.success);
    assert_eq!(result.session_id, [0u8; 16]);
    assert_eq!(result.server_signature, [0u8; 32]);

    server.handle.abort();
}

/// AUTH-2 / CLIENT-2: a malicious server M that relays a victim's login to
/// server T sits on two TLS sessions (victim↔M, M↔T). The victim's proof is
/// bound to the victim↔M session, so T — checking against M↔T — rejects it.
/// Simulated here with two sessions to the same server: the challenge comes
/// from session A, the proof is computed with session B's exporter.
#[tokio::test]
async fn relayed_proof_from_another_tls_session_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();
    let pool = kdx_storage::connect(&dir.path().join("kdx.db"))
        .await
        .unwrap();
    let credential = hash_password("correct horse").unwrap();
    accounts::create(&pool, "phraq", &credential, 3, 0, 0)
        .await
        .unwrap();

    let (mut relay_to_target, mut seq_a) = handshaken(server.local_addr).await;
    let (victim_side, _seq_b) = handshaken(server.local_addr).await;
    let binding_a = channel_binding(&relay_to_target);
    let binding_b = channel_binding(&victim_side);
    assert_ne!(
        binding_a, binding_b,
        "each TLS session has its own exporter value"
    );

    // The relay forwards T's challenge; the victim (correct password!)
    // answers it on its own session.
    let challenge = request_challenge(&mut relay_to_target, &mut seq_a, "phraq").await;
    let victim_proof = prove("phraq", "correct horse", &challenge, &binding_b);
    let result = send_proof(&mut relay_to_target, &mut seq_a, victim_proof.proof).await;
    assert!(!result.success, "relayed login was accepted");
    assert_eq!(result.message, "invalid credentials");

    // Sanity: the same password bound to the right session works.
    let ok = login_result(&mut relay_to_target, &mut seq_a, "phraq", "correct horse").await;
    assert!(ok.success, "{}", ok.message);

    server.handle.abort();
}

/// AUTH-3: everything the server stores (salt, params, StoredKey,
/// ServerKey) is not enough to produce a valid proof.
#[tokio::test]
async fn database_contents_alone_cannot_log_in() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();
    let pool = kdx_storage::connect(&dir.path().join("kdx.db"))
        .await
        .unwrap();
    let credential = hash_password("correct horse").unwrap();
    accounts::create(&pool, "sysop", &credential, 3, 0, 0)
        .await
        .unwrap();

    // The attacker's copy of the row.
    let row = accounts::by_username(&pool, "sysop")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.password_phc, "", "no password-equivalent hash at rest");
    let stolen = StoredCredential::decode(row.credential.as_deref().unwrap()).unwrap();

    let (mut client, mut seq) = handshaken(server.local_addr).await;
    let binding = channel_binding(&client);
    let forgeries: [Forgery; 3] = [
        // Use StoredKey as if it were ClientKey.
        |c, am, _| xor(&c.stored_key, &hmac_sha256(&c.stored_key, am)),
        // Use ServerKey as if it were ClientKey.
        |c, am, _| xor(&c.server_key, &hmac_sha256(&c.stored_key, am)),
        // The protocol-v1 answer, SHA-256(challenge || stored verifier).
        |c, _, challenge| {
            Sha256::new()
                .chain_update(challenge)
                .chain_update(c.stored_key)
                .finalize()
                .into()
        },
    ];
    for forge in forgeries {
        let challenge = request_challenge(&mut client, &mut seq, "sysop").await;
        let auth_message = AuthContext {
            username: "sysop",
            challenge: &challenge.challenge,
            salt: &challenge.salt,
            params: KdfParams {
                m_cost: challenge.m_cost,
                t_cost: challenge.t_cost,
                p_cost: challenge.p_cost,
            },
            channel_binding: &binding,
        }
        .auth_message();
        let proof = forge(&stolen, &auth_message, &challenge.challenge);
        let result = send_proof(&mut client, &mut seq, proof).await;
        assert!(!result.success, "forged proof accepted");
    }

    server.handle.abort();
}

/// A database written by protocol v1 (Argon2 PHC only) is converted when
/// the server starts: the password-equivalent hash is wiped and the user
/// logs in with the unchanged password.
#[tokio::test]
async fn legacy_database_is_converted_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let pool = kdx_storage::connect(&dir.path().join("kdx.db"))
        .await
        .unwrap();
    accounts::create_legacy(&pool, "oldtimer", LEGACY_PHC, 1)
        .await
        .unwrap();

    let server = serve(test_config(&dir)).await.unwrap();
    let row = accounts::by_username(&pool, "oldtimer")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.password_phc, "");
    assert!(row.credential.is_some());

    let (mut client, mut seq) = handshaken(server.local_addr).await;
    let result = login_result(&mut client, &mut seq, "oldtimer", "legacy pass").await;
    assert!(result.success, "{}", result.message);

    server.handle.abort();
}

/// AUTH-7: failures from one address are counted server-wide (not just per
/// connection), lead to a refusal even for the right password, and are
/// audited with the source address.
#[tokio::test]
async fn repeated_failures_from_one_address_are_throttled() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();
    let pool = kdx_storage::connect(&dir.path().join("kdx.db"))
        .await
        .unwrap();
    let credential = hash_password("correct horse").unwrap();
    accounts::create(&pool, "phraq", &credential, 1, 0, 0)
        .await
        .unwrap();
    let localhost: std::net::IpAddr = "127.0.0.1".parse().unwrap();

    // One connection's worth of wrong guesses (bogus proofs, no Argon2).
    let (mut client, mut seq) = handshaken(server.local_addr).await;
    for _ in 0..3 {
        request_challenge(&mut client, &mut seq, "phraq").await;
        assert!(!send_proof(&mut client, &mut seq, [0u8; 32]).await.success);
    }
    assert_eq!(
        server.ctx.login_limiter.failure_count(localhost, "phraq"),
        3
    );

    // More connections would keep adding; add them directly so the test
    // doesn't race the (short) first backoff.
    for _ in 0..9 {
        server.ctx.login_limiter.record_failure(localhost, "phraq");
    }
    let (mut client, mut seq) = handshaken(server.local_addr).await;
    let refused = refused_at_request(&mut client, &mut seq, "phraq").await;
    assert!(!refused.success);
    assert!(
        refused.message.contains("too many failed login attempts"),
        "{}",
        refused.message
    );

    // The failures were audited (through the detached history writer) with
    // the peer address. The writer merges identical events that land in one
    // batch into a single row whose detail ends in " (xN)" — and these three
    // are identical (same actor, same connection's peer) — so count events,
    // not rows: how many rows they became depends on batching timing.
    fn events_in(detail: &str) -> usize {
        detail
            .rsplit_once(" (x")
            .and_then(|(_, tail)| tail.strip_suffix(')'))
            .and_then(|n| n.parse().ok())
            .unwrap_or(1)
    }
    let mut failed = Vec::new();
    let mut events = 0;
    for _ in 0..200 {
        let history = server.ctx.history.recent(50).await.unwrap();
        failed = history
            .into_iter()
            .filter(|e| e.action == "login_failed")
            .collect();
        events = failed.iter().map(|e| events_in(&e.detail)).sum::<usize>();
        if events >= 3 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(events, 3, "{failed:?}");
    assert!(
        failed.iter().all(|e| e.detail.contains("127.0.0.1")),
        "{failed:?}"
    );

    server.handle.abort();
}

/// AUTH-8 / PROTO-5: an oversized username is refused before any DB work
/// and never reaches the audit log at full length.
#[tokio::test]
async fn oversized_username_is_refused_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();

    let (mut client, mut seq) = handshaken(server.local_addr).await;
    let huge = "x".repeat(16_000);
    let refused = refused_at_request(&mut client, &mut seq, &huge).await;
    assert!(!refused.success);

    // Give the detached audit write a moment, then check its size.
    for _ in 0..200 {
        if !server.ctx.history.recent(10).await.unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let history = server.ctx.history.recent(10).await.unwrap();
    assert!(!history.is_empty());
    assert!(history
        .iter()
        .all(|e| e.actor.as_deref().map_or(0, str::len) <= 64));

    server.handle.abort();
}

/// Read the next frame that isn't an unsolicited push (presence, greeting).
async fn next_reply(client: &mut TlsClient) -> kdx_protocol::KdxFrame {
    use futures_util::StreamExt;
    loop {
        let frame = client.next().await.unwrap().unwrap();
        if !matches!(
            frame.header.packet_type,
            PacketType::PresenceChange | PacketType::Info
        ) {
            return frame;
        }
    }
}

fn wire(credential: &StoredCredential) -> Credential {
    Credential {
        m_cost: credential.params.m_cost,
        t_cost: credential.params.t_cost,
        p_cost: credential.params.p_cost,
        salt: credential.salt.clone(),
        stored_key: credential.stored_key,
        server_key: credential.server_key,
    }
}

/// Self-service password change over real TLS: the change proof is bound to
/// this session's exporter (a proof made for another session fails, as a
/// wrong password), the server proves itself with the old ServerKey, and
/// afterwards only the new password logs in. Neither password is sent.
#[tokio::test]
async fn password_change_over_tls_is_channel_bound() {
    use futures_util::SinkExt;

    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();
    let pool = kdx_storage::connect(&dir.path().join("kdx.db"))
        .await
        .unwrap();
    let credential = hash_password("correct horse").unwrap();
    accounts::create(&pool, "phraq", &credential, 1, 0, 0)
        .await
        .unwrap();

    let (mut client, mut seq) = handshaken(server.local_addr).await;
    common::login(&mut client, &mut seq, "phraq", "correct horse").await;
    let binding = channel_binding(&client);
    let (other, _) = handshaken(server.local_addr).await;
    let foreign_binding = channel_binding(&other);
    let new = StoredCredential::derive("battery staple").unwrap();
    let localhost: std::net::IpAddr = "127.0.0.1".parse().unwrap();

    for (binding, should_succeed) in [(foreign_binding, false), (binding, true)] {
        client
            .send(common::frame(
                PacketType::PasswordChangeBegin,
                common::bump(&mut seq),
                PasswordChangeBegin.encode(),
            ))
            .await
            .unwrap();
        let frame = next_reply(&mut client).await;
        assert_eq!(frame.header.packet_type, PacketType::PasswordChangeChallenge);
        let challenge = PasswordChangeChallenge::decode(&frame.payload).unwrap();
        let proof = password_change_proof(
            "correct horse",
            &PasswordChangeContext {
                current: AuthContext {
                    username: "phraq",
                    challenge: &challenge.challenge,
                    salt: &challenge.salt,
                    params: KdfParams {
                        m_cost: challenge.m_cost,
                        t_cost: challenge.t_cost,
                        p_cost: challenge.p_cost,
                    },
                    channel_binding: &binding,
                },
                new_credential: &new,
            },
        )
        .unwrap();
        client
            .send(common::frame(
                PacketType::PasswordChangeProof,
                common::bump(&mut seq),
                PasswordChangeProof {
                    proof: proof.proof,
                    credential: wire(&new),
                }
                .encode(),
            ))
            .await
            .unwrap();
        let frame = next_reply(&mut client).await;
        assert_eq!(frame.header.packet_type, PacketType::PasswordChangeResult);
        let result = PasswordChangeResult::decode(&frame.payload).unwrap();
        assert_eq!(result.success, should_succeed, "{}", result.message);
        if should_succeed {
            assert!(proof.verify_server_signature(&result.server_signature));
        } else {
            // A proof for another TLS session is a wrong password.
            assert_eq!(server.ctx.login_limiter.failure_count(localhost, "phraq"), 1);
        }
    }
    // The success cleared the (address, account) pair again.
    assert_eq!(server.ctx.login_limiter.failure_count(localhost, "phraq"), 0);

    // Stored exactly as the client derived it; only the new password works.
    let row = accounts::by_username(&pool, "phraq").await.unwrap().unwrap();
    assert_eq!(row.credential, Some(new.encode()));
    let (mut again, mut seq) = handshaken(server.local_addr).await;
    assert!(!login_result(&mut again, &mut seq, "phraq", "correct horse").await.success);
    assert!(login_result(&mut again, &mut seq, "phraq", "battery staple").await.success);

    server.handle.abort();
}
