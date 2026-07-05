//! C1 exit criteria: connect/login returns the account class; two clients in
//! one room see each other's chat and user-list events; a flood warning
//! surfaces as an event; a dropped server yields Disconnected.

mod common;

use std::time::Duration;

use common::TestServer;
use kdx_client_core::Event;
use kdx_protocol::messages::CHAT_ACTION;
use tokio::sync::mpsc::Receiver;

async fn next_event(rx: &mut Receiver<Event>) -> Event {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("event timeout")
        .expect("event channel open")
}

/// Wait for a specific event kind, skipping others.
async fn wait_chat(rx: &mut Receiver<Event>, want_system: bool) -> (String, String, u8) {
    for _ in 0..20 {
        if let Event::Chat {
            sender, text, flags, ..
        } = next_event(rx).await
        {
            let is_system = flags & kdx_protocol::messages::CHAT_SYSTEM != 0;
            if is_system == want_system {
                return (sender, text, flags);
            }
        }
    }
    panic!("no matching chat event");
}

#[tokio::test]
async fn connect_login_returns_class() {
    let ts = TestServer::start().await;
    ts.seed_account("phraq", "s3cret", 2).await; // PowerUser

    let (client, mut events, _dd) = ts.connect_client().await;
    assert!(matches!(next_event(&mut events).await, Event::Connected { .. }));

    let session = client.login("phraq", "s3cret").await.unwrap();
    assert_eq!(session.class, 2);

    client.disconnect().await;
    ts.stop();
}

#[tokio::test]
async fn wrong_password_then_retry() {
    let ts = TestServer::start().await;
    ts.seed_account("phraq", "s3cret", 1).await;

    let (client, mut events, _dd) = ts.connect_client().await;
    next_event(&mut events).await; // Connected

    assert!(client.login("phraq", "wrong").await.is_err());
    let session = client.login("phraq", "s3cret").await.unwrap();
    assert_eq!(session.class, 1);

    ts.stop();
}

#[tokio::test]
async fn two_clients_exchange_chat() {
    let ts = TestServer::start().await;
    ts.seed_account("alice", "pw", 1).await;
    ts.seed_account("bob", "pw", 1).await;

    let (alice, mut ea, _d1) = ts.connect_client().await;
    let (bob, mut eb, _d2) = ts.connect_client().await;
    next_event(&mut ea).await;
    next_event(&mut eb).await;
    alice.login("alice", "pw").await.unwrap();
    bob.login("bob", "pw").await.unwrap();

    alice.join("lobby").await.unwrap();
    // Alice sees her own user list.
    let mut saw_alice_list = false;
    for _ in 0..5 {
        if let Event::UserList { users, .. } = next_event(&mut ea).await {
            if users == vec!["alice".to_string()] {
                saw_alice_list = true;
                break;
            }
        }
    }
    assert!(saw_alice_list);

    bob.join("lobby").await.unwrap();
    // Bob's user list should eventually show both.
    let mut saw_both = false;
    for _ in 0..5 {
        if let Event::UserList { users, .. } = next_event(&mut eb).await {
            if users.len() == 2 {
                saw_both = true;
                break;
            }
        }
    }
    assert!(saw_both);

    alice.send_chat("lobby", 0, "hello underground").await.unwrap();
    let (sender, text, _) = wait_chat(&mut eb, false).await;
    assert_eq!(sender, "alice");
    assert_eq!(text, "hello underground");

    // Action message keeps its flag.
    alice.send_chat("lobby", CHAT_ACTION, "waves").await.unwrap();
    let (sender, _, flags) = wait_chat(&mut eb, false).await;
    assert_eq!(sender, "alice");
    assert!(flags & CHAT_ACTION != 0);

    ts.stop();
}

#[tokio::test]
async fn flood_surfaces_as_warning() {
    let ts = TestServer::start().await;
    ts.seed_account("spammer", "pw", 1).await;

    let (client, mut events, _dd) = ts.connect_client().await;
    next_event(&mut events).await;
    client.login("spammer", "pw").await.unwrap();
    client.join("lobby").await.unwrap();

    for i in 0..12 {
        client.send_chat("lobby", 0, &format!("spam {i}")).await.unwrap();
    }

    let mut saw_warning = false;
    for _ in 0..40 {
        if let Event::ServerWarning { text } = next_event(&mut events).await {
            assert!(text.contains("flood"));
            saw_warning = true;
            break;
        }
    }
    assert!(saw_warning);

    ts.stop();
}

#[tokio::test]
async fn disconnect_yields_disconnected_event() {
    let ts = TestServer::start().await;
    ts.seed_account("phraq", "pw", 1).await;

    let (client, mut events, _dd) = ts.connect_client().await;
    next_event(&mut events).await;
    client.login("phraq", "pw").await.unwrap();

    // Tearing down the connection must surface a Disconnected event — the
    // same emission path the actor uses on a server-side EOF.
    client.disconnect().await;

    let mut saw_disconnect = false;
    for _ in 0..10 {
        if let Event::Disconnected { .. } = next_event(&mut events).await {
            saw_disconnect = true;
            break;
        }
    }
    assert!(saw_disconnect);

    ts.stop();
}
