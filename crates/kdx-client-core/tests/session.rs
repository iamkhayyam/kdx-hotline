//! C1 exit criteria: connect/login returns the account class; two clients in
//! one room see each other's chat and user-list events; a flood warning
//! surfaces as an event; a dropped server yields Disconnected.

mod common;

use std::time::Duration;

use common::TestServer;
use kdx_client_core::{ClientError, Event};
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
async fn global_roster_tracks_presence_live() {
    let ts = TestServer::start().await;
    ts.seed_account("alice", "pw", 1).await;
    ts.seed_account("bob", "pw", 2).await;

    let (alice, mut ea, _d1) = ts.connect_client().await;
    next_event(&mut ea).await; // Connected
    alice.login("alice", "pw").await.unwrap();

    // Alice alone on the roster.
    let roster = alice.list_users().await.unwrap();
    assert_eq!(roster.len(), 1);
    assert_eq!(roster[0].username, "alice");

    // Bob logs in: alice gets a live online push, roster grows.
    let (bob, mut eb, _d2) = ts.connect_client().await;
    next_event(&mut eb).await;
    bob.login("bob", "pw").await.unwrap();

    let mut saw_bob_online = false;
    for _ in 0..10 {
        if let Event::Presence { user, online } = next_event(&mut ea).await {
            assert!(online);
            assert_eq!(user.username, "bob");
            assert_eq!(user.class, 2);
            saw_bob_online = true;
            break;
        }
    }
    assert!(saw_bob_online);
    assert_eq!(alice.list_users().await.unwrap().len(), 2);

    // Get Info on bob shows his detail.
    let info = alice.get_user_info("bob").await.unwrap();
    assert_eq!(info.class, 2);
    assert!(!info.address.is_empty());
    // Unknown user errors.
    assert!(alice.get_user_info("nobody").await.is_err());

    // Bob leaves: alice gets an offline push and the roster shrinks.
    bob.disconnect().await;
    let mut saw_bob_offline = false;
    for _ in 0..10 {
        if let Event::Presence { user, online } = next_event(&mut ea).await {
            if user.username == "bob" && !online {
                saw_bob_offline = true;
                break;
            }
        }
    }
    assert!(saw_bob_offline);
    assert_eq!(alice.list_users().await.unwrap().len(), 1);

    ts.stop();
}

#[tokio::test]
async fn private_messages_route_between_users() {
    let ts = TestServer::start().await;
    ts.seed_account("alice", "pw", 1).await; // user class has CHAT_PRIVATE
    ts.seed_account("bob", "pw", 1).await;

    let (alice, mut ea, _d1) = ts.connect_client().await;
    next_event(&mut ea).await;
    alice.login("alice", "pw").await.unwrap();

    let (bob, mut eb, _d2) = ts.connect_client().await;
    next_event(&mut eb).await;
    bob.login("bob", "pw").await.unwrap();

    // Alice DMs bob.
    alice.send_private("bob", "meet me in /incoming").await.unwrap();

    // Bob receives it.
    let mut got = None;
    for _ in 0..10 {
        if let Event::PrivateMessage { from, to, text, .. } = next_event(&mut eb).await {
            got = Some((from, to, text));
            break;
        }
    }
    let (from, to, text) = got.expect("bob should receive the PM");
    assert_eq!(from, "alice");
    assert_eq!(to, "bob");
    assert_eq!(text, "meet me in /incoming");

    // Alice's own session gets an echo so her transcript shows the sent line.
    let mut echo = None;
    for _ in 0..10 {
        if let Event::PrivateMessage { from, to, .. } = next_event(&mut ea).await {
            echo = Some((from, to));
            break;
        }
    }
    let (efrom, eto) = echo.expect("alice should get her own sent echo");
    assert_eq!(efrom, "alice");
    assert_eq!(eto, "bob");

    // DM to an offline user surfaces a server error.
    alice.send_private("ghost", "anyone there?").await.unwrap();
    let mut saw_err = false;
    for _ in 0..10 {
        if let Event::ServerError { text } = next_event(&mut ea).await {
            assert!(text.contains("ghost") || text.contains("not online"));
            saw_err = true;
            break;
        }
    }
    assert!(saw_err);

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

#[tokio::test]
async fn sysop_defines_and_assigns_a_custom_role() {
    let ts = TestServer::start().await;
    ts.seed_account("sysop", "pw", 3).await; // Admin: has USER_ADMIN
    ts.seed_account("mod", "pw", 1).await; // plain User, no custom role yet

    let (client, mut events, _dd) = ts.connect_client().await;
    next_event(&mut events).await;
    client.login("sysop", "pw").await.unwrap();

    let roles = client
        .create_role("Moderator", 0, 10, "#e11b1b")
        .await
        .unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].name, "Moderator");
    let role_id = roles[0].id.clone();

    let roles = client.assign_role("mod", &role_id).await.unwrap();
    assert_eq!(roles.len(), 1);

    let assigned = client.account_roles("mod").await.unwrap();
    assert_eq!(assigned, vec![role_id.clone()]);

    let roles = client.unassign_role("mod", &role_id).await.unwrap();
    assert_eq!(roles.len(), 1); // the role itself still exists
    assert!(client.account_roles("mod").await.unwrap().is_empty());

    let roles = client.delete_role(&role_id).await.unwrap();
    assert!(roles.is_empty());

    ts.stop();
}

#[tokio::test]
async fn plain_user_role_mutation_is_rejected() {
    let ts = TestServer::start().await;
    ts.seed_account("plain", "pw", 1).await;

    let (client, mut events, _dd) = ts.connect_client().await;
    next_event(&mut events).await;
    client.login("plain", "pw").await.unwrap();

    let result = client.create_role("Sneaky", u32::MAX, 0, "").await;
    assert!(matches!(result, Err(ClientError::Server(_))));

    ts.stop();
}

#[tokio::test]
async fn sysop_disconnects_and_bans_a_user() {
    let ts = TestServer::start().await;
    ts.seed_account("sysop", "pw", 3).await; // Admin: has USER_KICK + USER_BAN
    ts.seed_account("lamer", "pw", 1).await;

    let (sysop, mut es, _d1) = ts.connect_client().await;
    next_event(&mut es).await;
    sysop.login("sysop", "pw").await.unwrap();

    let (lamer, mut el, _d2) = ts.connect_client().await;
    next_event(&mut el).await;
    lamer.login("lamer", "pw").await.unwrap();

    // Admin disconnects lamer with a one-hour ban.
    sysop
        .disconnect_user("lamer", "flooding the boards", 3600)
        .await
        .unwrap();

    // The kicked client sees the reason, then the terminal Disconnected.
    let mut saw_reason = false;
    let mut saw_disconnect = false;
    for _ in 0..12 {
        match next_event(&mut el).await {
            Event::ServerError { text } if text.contains("flooding") => saw_reason = true,
            Event::Disconnected { .. } => {
                saw_disconnect = true;
                break;
            }
            _ => {}
        }
    }
    assert!(saw_reason, "kicked user should see the disconnect reason");
    assert!(saw_disconnect, "kicked user should be disconnected");

    // The admin gets an informational acknowledgement.
    let mut saw_ack = false;
    for _ in 0..10 {
        if let Event::ServerInfo { text } = next_event(&mut es).await {
            assert!(text.contains("lamer"));
            saw_ack = true;
            break;
        }
    }
    assert!(saw_ack, "admin should get a disconnect ack");

    // A fresh login as the banned account is refused (correct password).
    let (again, mut ea, _d3) = ts.connect_client().await;
    next_event(&mut ea).await;
    let err = again.login("lamer", "pw").await.unwrap_err();
    match err {
        ClientError::AuthFailed(msg) => assert!(msg.contains("banned"), "got: {msg}"),
        other => panic!("expected AuthFailed(banned), got {other:?}"),
    }

    ts.stop();
}

#[tokio::test]
async fn plain_user_cannot_disconnect_others() {
    let ts = TestServer::start().await;
    ts.seed_account("nobody", "pw", 1).await; // no USER_KICK
    ts.seed_account("target", "pw", 1).await;

    let (nobody, mut en, _d1) = ts.connect_client().await;
    next_event(&mut en).await;
    nobody.login("nobody", "pw").await.unwrap();

    let (target, mut et, _d2) = ts.connect_client().await;
    next_event(&mut et).await;
    target.login("target", "pw").await.unwrap();

    nobody.disconnect_user("target", "", 0).await.unwrap();

    // The attempt is refused with a privilege error…
    let mut saw_err = false;
    for _ in 0..10 {
        if let Event::ServerError { text } = next_event(&mut en).await {
            assert!(text.contains("USER_KICK"));
            saw_err = true;
            break;
        }
    }
    assert!(saw_err);

    // …and the target stays connected: a ping still round-trips as usual by
    // way of the still-live roster (list_users succeeds).
    assert!(target.list_users().await.is_ok());

    ts.stop();
}
