//! Login-path tests against a scripted (possibly hostile) server over an
//! in-memory duplex, driving the real actor through `ClientHandle::login`.

use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use kdx_crypto::{KdfParams, StoredCredential};
use kdx_protocol::messages::{AuthChallenge, AuthRequest, AuthResponse, AuthResult};
use kdx_protocol::{KdxCodec, KdxFrame, PacketFlags, PacketHeader, PacketType, PROTOCOL_VERSION};
use tokio::io::DuplexStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::codec::Framed;

use crate::actor::Actor;
use crate::error::ClientError;
use crate::event::Event;
use crate::handle::{ClientHandle, Command, Password, Session};

const BINDING: [u8; 32] = [0x5A; 32];

type ServerSide = Framed<DuplexStream, KdxCodec>;

struct Harness {
    client: ClientHandle,
    events: mpsc::Receiver<Event>,
    server: ServerSide,
    seq: u32,
}

fn harness() -> Harness {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let (event_tx, event_rx) = mpsc::channel(64);
    let actor = Actor::new(
        Framed::new(client_io, KdxCodec::default()),
        cmd_rx,
        event_tx,
    )
    .with_channel_binding(BINDING);
    Harness {
        client: actor.spawn(cmd_tx),
        events: event_rx,
        server: Framed::new(server_io, KdxCodec::default()),
        seq: 0,
    }
}

impl Harness {
    async fn send(&mut self, packet_type: PacketType, payload: Bytes) {
        let header = PacketHeader {
            version: PROTOCOL_VERSION,
            packet_type,
            flags: PacketFlags::empty(),
            sequence: self.seq,
            length: payload.len() as u32,
        };
        self.seq += 1;
        self.server
            .send(KdxFrame { header, payload })
            .await
            .unwrap();
    }

    async fn expect(&mut self, packet_type: PacketType) -> KdxFrame {
        loop {
            let frame = self.server.next().await.unwrap().unwrap();
            // The actor may send keepalive Pings; skip them.
            if frame.header.packet_type == PacketType::Ping {
                continue;
            }
            assert_eq!(frame.header.packet_type, packet_type);
            return frame;
        }
    }

    async fn send_challenge(&mut self, challenge: &AuthChallenge) {
        self.send(PacketType::AuthChallenge, challenge.encode())
            .await;
    }

    async fn send_result(&mut self, success: bool, message: &str, server_signature: [u8; 32]) {
        let result = AuthResult {
            success,
            session_id: if success { [9u8; 16] } else { [0u8; 16] },
            class: if success { 2 } else { 0 },
            message: message.into(),
            server_signature,
        };
        self.send(PacketType::AuthResult, result.encode()).await;
    }
}

fn start_login(client: &ClientHandle, password: &str) -> JoinHandle<Result<Session, ClientError>> {
    let client = client.clone();
    let password = password.to_owned();
    tokio::spawn(async move { client.login("phraq", &password).await })
}

async fn finish(login: JoinHandle<Result<Session, ClientError>>) -> Result<Session, ClientError> {
    tokio::time::timeout(Duration::from_secs(30), login)
        .await
        .expect("login hung")
        .unwrap()
}

fn challenge_for(credential: &StoredCredential) -> AuthChallenge {
    AuthChallenge {
        challenge: [3u8; 32],
        salt: credential.salt.clone(),
        m_cost: credential.params.m_cost,
        t_cost: credential.params.t_cost,
        p_cost: credential.params.p_cost,
    }
}

/// An honest server: verifies the proof against the account's stored
/// credential and the shared channel binding, and signs the result.
#[tokio::test]
async fn login_succeeds_against_an_honest_server() {
    let credential = StoredCredential::derive("s3cret").unwrap();
    let mut h = harness();
    let login = start_login(&h.client, "s3cret");

    let request = h.expect(PacketType::AuthRequest).await;
    assert_eq!(
        AuthRequest::decode(&request.payload).unwrap().username,
        "phraq"
    );
    let challenge = challenge_for(&credential);
    h.send_challenge(&challenge).await;
    let response = h.expect(PacketType::AuthResponse).await;
    let proof = AuthResponse::decode(&response.payload).unwrap().response;
    let signature = credential
        .verify_proof("phraq", &challenge.challenge, &BINDING, &proof)
        .expect("client proof verifies with the shared binding");
    h.send_result(true, "welcome", signature).await;

    let session = finish(login).await.unwrap();
    assert_eq!(session.class, 2);
}

/// P-3: a second login on a logged-in connection is refused locally. It
/// used to send another AuthRequest (which the server has no answer for)
/// and leave the actor "mid-login" for good, so keepalives stopped and the
/// idle watchdog killed the session.
#[tokio::test]
async fn a_second_login_is_refused_and_keepalives_continue() {
    let credential = StoredCredential::derive("s3cret").unwrap();
    let mut h = harness();
    let login = start_login(&h.client, "s3cret");
    h.expect(PacketType::AuthRequest).await;
    let challenge = challenge_for(&credential);
    h.send_challenge(&challenge).await;
    let response = h.expect(PacketType::AuthResponse).await;
    let proof = AuthResponse::decode(&response.payload).unwrap().response;
    let signature = credential
        .verify_proof("phraq", &challenge.challenge, &BINDING, &proof)
        .unwrap();
    h.send_result(true, "welcome", signature).await;
    finish(login).await.unwrap();

    // Argon2 above ran on the blocking pool in real time; from here on the
    // clock is paused so the keepalive interval passes instantly.
    tokio::time::pause();
    let again = tokio::time::timeout(Duration::from_secs(1), h.client.login("phraq", "s3cret"))
        .await
        .expect("refused at once, not after a timeout");
    assert!(matches!(again, Err(ClientError::InvalidInput(_))), "{again:?}");
    // Nothing was sent for it, and the session keeps pinging.
    let next = h.server.next().await.unwrap().unwrap();
    assert_eq!(next.header.packet_type, PacketType::Ping);
}

/// CLIENT-2 / AUTH-2: a server that can't produce the ServerSignature (a
/// phishing server that "accepts" anything, or a relay) is not trusted, and
/// the connection is dropped.
#[tokio::test]
async fn success_without_valid_server_signature_is_rejected() {
    let credential = StoredCredential::derive("s3cret").unwrap();
    let mut h = harness();
    let login = start_login(&h.client, "s3cret");

    h.expect(PacketType::AuthRequest).await;
    h.send_challenge(&challenge_for(&credential)).await;
    h.expect(PacketType::AuthResponse).await;
    h.send_result(true, "welcome", [0u8; 32]).await;

    assert!(matches!(
        finish(login).await,
        Err(ClientError::AuthFailed(_))
    ));
    // The actor hangs up on an impostor: a Disconnected event (or the
    // event channel closing because the actor is gone).
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = h.events.recv().await {
            if matches!(event, Event::Disconnected { .. }) {
                return;
            }
        }
    })
    .await
    .expect("actor should disconnect from an impostor");
}

/// A success that arrives before we've sent any proof is never valid.
#[tokio::test]
async fn success_before_any_proof_is_rejected() {
    let mut h = harness();
    let login = start_login(&h.client, "s3cret");
    h.expect(PacketType::AuthRequest).await;
    h.send_result(true, "welcome", [7u8; 32]).await;
    assert!(matches!(
        finish(login).await,
        Err(ClientError::AuthFailed(_))
    ));
}

/// Refusals may come straight back for the AuthRequest (throttled, full).
#[tokio::test]
async fn refusal_without_challenge_fails_cleanly() {
    let mut h = harness();
    let login = start_login(&h.client, "s3cret");
    h.expect(PacketType::AuthRequest).await;
    h.send_result(false, "server is full", [0u8; 32]).await;
    match finish(login).await {
        Err(ClientError::AuthFailed(message)) => assert_eq!(message, "server is full"),
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

/// CLIENT-1 / AUTH-4 / PROTO-4: server-chosen Argon2 parameters are bounded
/// before any work, so a hostile server can neither abort (huge memory) nor
/// hang (huge time) the client, nor make the proof cheap to crack.
#[tokio::test]
async fn hostile_kdf_parameters_fail_fast() {
    let ok = KdfParams::DEFAULT;
    let cases = [
        (
            KdfParams {
                m_cost: u32::MAX,
                ..ok
            },
            16,
        ),
        (
            KdfParams {
                m_cost: 8,
                t_cost: u32::MAX,
                ..ok
            },
            16,
        ),
        (
            KdfParams {
                m_cost: 8,
                t_cost: 1,
                ..ok
            },
            16,
        ),
        (ok, 4),
    ];
    for (params, salt_len) in cases {
        let mut h = harness();
        let login = start_login(&h.client, "s3cret");
        h.expect(PacketType::AuthRequest).await;
        h.send_challenge(&AuthChallenge {
            challenge: [1u8; 32],
            salt: vec![2u8; salt_len],
            m_cost: params.m_cost,
            t_cost: params.t_cost,
            p_cost: params.p_cost,
        })
        .await;
        let outcome = tokio::time::timeout(Duration::from_secs(2), login)
            .await
            .expect("login must fail fast")
            .unwrap();
        match outcome {
            Err(ClientError::AuthFailed(message)) => {
                assert!(message.contains("KDF"), "{message}")
            }
            other => panic!("{params:?}/{salt_len}: expected AuthFailed, got {other:?}"),
        }
    }
}

/// AUTH-11 / CLIENT-15: the password never shows up in `Debug` output.
#[test]
fn login_command_debug_redacts_the_password() {
    let (reply, _rx) = oneshot::channel();
    let command = Command::Login {
        username: "phraq".into(),
        password: Password::new("hunter2"),
        reply,
    };
    let shown = format!("{command:?}");
    assert!(shown.contains("phraq"));
    assert!(!shown.contains("hunter2"), "{shown}");
}
