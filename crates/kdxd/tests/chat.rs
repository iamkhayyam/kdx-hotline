//! M4 exit criterion: two authenticated clients join a room, exchange a
//! message with correct sender/timestamp, /me action flag survives, and a
//! spammer gets flood-throttled.

mod common;

use common::{bump, connect_tls, frame, kdx_handshake, test_config, TlsClient};
use futures_util::{SinkExt, StreamExt};
use kdx_crypto::{client_response, hash_password, KdfParams};
use kdx_protocol::messages::{
    AuthChallenge, AuthRequest, AuthResponse, AuthResult, ChatEvent, ChatJoin, ChatSend,
    ChatUserList, CHAT_ACTION, CHAT_SYSTEM,
};
use kdx_protocol::{KdxFrame, PacketType};
use kdx_storage::accounts;
use kdxd::serve;

async fn login(client: &mut TlsClient, seq: &mut u32, username: &str, password: &str) {
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
    let result = AuthResult::decode(&result_frame.payload).unwrap();
    assert!(result.success, "{}", result.message);
}

async fn next_frame(client: &mut TlsClient) -> KdxFrame {
    tokio::time::timeout(std::time::Duration::from_secs(5), client.next())
        .await
        .expect("timed out waiting for frame")
        .unwrap()
        .unwrap()
}

/// Read frames until one matches `packet_type`, returning it. Panics after a
/// few frames — tests should know roughly what's in flight.
async fn wait_for(client: &mut TlsClient, packet_type: PacketType) -> KdxFrame {
    for _ in 0..10 {
        let frame = next_frame(client).await;
        if frame.header.packet_type == packet_type {
            return frame;
        }
    }
    panic!("did not receive {packet_type:?} within 10 frames");
}

/// Read frames until a non-system chat message arrives (skipping join/leave
/// notices and other packet types).
async fn wait_for_user_chat(client: &mut TlsClient) -> ChatEvent {
    for _ in 0..10 {
        let frame = next_frame(client).await;
        if frame.header.packet_type == PacketType::ChatMessage {
            let event = ChatEvent::decode(&frame.payload).unwrap();
            if event.flags & CHAT_SYSTEM == 0 {
                return event;
            }
        }
    }
    panic!("did not receive a user chat message within 10 frames");
}

#[tokio::test]
async fn two_clients_chat_in_lobby() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();
    let pool = kdx_storage::connect(&dir.path().join("kdx.db")).await.unwrap();
    for name in ["alice", "bob"] {
        let phc = hash_password("pw").unwrap();
        accounts::create(&pool, name, &phc, 1).await.unwrap();
    }

    let mut alice = connect_tls(server.local_addr).await;
    let mut bob = connect_tls(server.local_addr).await;
    let (mut aseq, mut bseq) = (0u32, 0u32);
    kdx_handshake(&mut alice, &mut aseq).await;
    kdx_handshake(&mut bob, &mut bseq).await;
    login(&mut alice, &mut aseq, "alice", "pw").await;
    login(&mut bob, &mut bseq, "bob", "pw").await;

    let join = ChatJoin {
        room: "lobby".into(),
    };
    alice
        .send(frame(PacketType::ChatJoin, bump(&mut aseq), join.encode()))
        .await
        .unwrap();
    // Alice sees her own join: user list + system notice.
    let list_frame = wait_for(&mut alice, PacketType::ChatUserList).await;
    let list = ChatUserList::decode(&list_frame.payload).unwrap();
    assert_eq!(list.users, vec!["alice".to_string()]);

    bob.send(frame(PacketType::ChatJoin, bump(&mut bseq), join.encode()))
        .await
        .unwrap();
    let list_frame = wait_for(&mut bob, PacketType::ChatUserList).await;
    let list = ChatUserList::decode(&list_frame.payload).unwrap();
    assert_eq!(list.users.len(), 2);

    // Drain alice's queue (own join notice, user-list updates) up to bob's
    // join notice, then send a message.
    let notice = loop {
        let frame = wait_for(&mut alice, PacketType::ChatMessage).await;
        let event = ChatEvent::decode(&frame.payload).unwrap();
        if event.text == "bob joined" {
            break event;
        }
    };
    assert!(notice.flags & CHAT_SYSTEM != 0);

    let send = ChatSend {
        room: "lobby".into(),
        flags: 0,
        text: "welcome to the underground".into(),
    };
    alice
        .send(frame(PacketType::ChatMessage, bump(&mut aseq), send.encode()))
        .await
        .unwrap();

    // Bob receives it with sender and a sane server timestamp.
    let event = wait_for_user_chat(&mut bob).await;
    assert_eq!(event.sender, "alice");
    assert_eq!(event.text, "welcome to the underground");
    assert!(event.timestamp > 1_700_000_000, "timestamp not set");

    // Action message (/me) keeps its flag.
    let action = ChatSend {
        room: "lobby".into(),
        flags: CHAT_ACTION,
        text: "waves".into(),
    };
    alice
        .send(frame(PacketType::ChatMessage, bump(&mut aseq), action.encode()))
        .await
        .unwrap();
    let action_event = wait_for_user_chat(&mut bob).await;
    assert!(action_event.flags & CHAT_ACTION != 0);
    assert_eq!(action_event.sender, "alice");

    server.handle.abort();
}

#[tokio::test]
async fn spammer_gets_flood_warning() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();
    let pool = kdx_storage::connect(&dir.path().join("kdx.db")).await.unwrap();
    let phc = hash_password("pw").unwrap();
    accounts::create(&pool, "spammer", &phc, 1).await.unwrap();

    let mut client = connect_tls(server.local_addr).await;
    let mut seq = 0u32;
    kdx_handshake(&mut client, &mut seq).await;
    login(&mut client, &mut seq, "spammer", "pw").await;

    client
        .send(frame(
            PacketType::ChatJoin,
            bump(&mut seq),
            ChatJoin {
                room: "lobby".into(),
            }
            .encode(),
        ))
        .await
        .unwrap();

    // Blast messages well past the burst allowance.
    for i in 0..12 {
        let send = ChatSend {
            room: "lobby".into(),
            flags: 0,
            text: format!("spam {i}"),
        };
        client
            .send(frame(PacketType::ChatMessage, bump(&mut seq), send.encode()))
            .await
            .unwrap();
    }

    // Somewhere in the reply stream there must be a flood Warning.
    let warning = wait_for(&mut client, PacketType::Warning).await;
    assert!(String::from_utf8_lossy(&warning.payload).contains("flood"));

    server.handle.abort();
}
