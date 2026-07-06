//! C1 exit criteria: connect/login returns the account class; two clients in
//! one room see each other's chat and user-list events; a flood warning
//! surfaces as an event; a dropped server yields Disconnected.

mod common;

use std::time::Duration;

use common::TestServer;
use kdx_client_core::{connect, ClientConfig, ClientError, Event};
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
async fn sysop_creates_and_edits_an_account() {
    let ts = TestServer::start().await;
    ts.seed_account("sysop", "pw", 3).await; // Admin: has USER_ADMIN

    let (sysop, mut es, _d1) = ts.connect_client().await;
    next_event(&mut es).await;
    sysop.login("sysop", "pw").await.unwrap();

    // Create a new account with one granted override (CHAT_SET_TOPIC = 1<<3).
    let granted = 1u32 << 3;
    let accounts = sysop
        .create_account("newbie", "letmein", 1, granted, 0)
        .await
        .unwrap();
    let created = accounts.iter().find(|a| a.username == "newbie").expect("listed");
    assert_eq!(created.base_class, 1);
    assert_eq!(created.granted, granted);

    // The freshly-minted account can log in with its initial password.
    let (newbie, mut en, _d2) = ts.connect_client().await;
    next_event(&mut en).await;
    let session = newbie.login("newbie", "letmein").await.unwrap();
    assert_eq!(session.class, 1);

    // Editing promotes the account to power user and drops the override.
    let accounts = sysop.update_account("newbie", 2, 0, 0).await.unwrap();
    let edited = accounts.iter().find(|a| a.username == "newbie").unwrap();
    assert_eq!(edited.base_class, 2);
    assert_eq!(edited.granted, 0);

    // A duplicate username is refused.
    let dup = sysop.create_account("newbie", "x", 1, 0, 0).await;
    assert!(matches!(dup, Err(ClientError::Server(_))));

    ts.stop();
}

#[tokio::test]
async fn plain_user_cannot_manage_accounts() {
    let ts = TestServer::start().await;
    ts.seed_account("plain", "pw", 1).await; // no USER_ADMIN

    let (client, mut events, _dd) = ts.connect_client().await;
    next_event(&mut events).await;
    client.login("plain", "pw").await.unwrap();

    assert!(matches!(client.list_accounts().await, Err(ClientError::Server(_))));
    assert!(matches!(
        client.create_account("sneaky", "pw", 3, 0, 0).await,
        Err(ClientError::Server(_))
    ));

    ts.stop();
}

#[tokio::test]
async fn news_post_read_threaded_and_class_gated() {
    let ts = TestServer::start().await;
    ts.seed_account("sysop", "pw", 3).await; // Admin: USER_ADMIN, can create groups
    ts.seed_account("reader", "pw", 1).await; // plain user
    ts.seed_account("guest", "pw", 0).await; // guest

    let (sysop, mut es, _d1) = ts.connect_client().await;
    next_event(&mut es).await;
    sysop.login("sysop", "pw").await.unwrap();

    // Admin creates a newsgroup readable by all, postable by user+ (class >= 1).
    let groups = sysop.create_newsgroup("general", "chatter", 0, 1).await.unwrap();
    assert_eq!(groups.len(), 1);
    let group_id = groups[0].id.clone();

    // Admin starts a thread; the reader replies to it.
    let posts = sysop.create_post(&group_id, "", "welcome", "first post").await.unwrap();
    assert_eq!(posts.len(), 1);
    let root_id = posts[0].id.clone();
    assert_eq!(posts[0].parent_id, "");

    let (reader, mut er, _d2) = ts.connect_client().await;
    next_event(&mut er).await;
    reader.login("reader", "pw").await.unwrap();

    // The reader sees the admin's thread and replies under the root.
    let seen = reader.list_thread(&group_id).await.unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].subject, "welcome");

    let after_reply = reader.create_post(&group_id, &root_id, "re: welcome", "hi there").await.unwrap();
    assert_eq!(after_reply.len(), 2);
    let reply = after_reply.iter().find(|p| p.parent_id == root_id).expect("threaded reply");
    assert_eq!(reply.author, "reader");

    // A guest (class 0) may read (min_read 0) but not post (min_post 1).
    let (guest, mut eg, _d3) = ts.connect_client().await;
    next_event(&mut eg).await;
    guest.login("guest", "pw").await.unwrap();
    assert_eq!(guest.list_thread(&group_id).await.unwrap().len(), 2);
    assert!(matches!(
        guest.create_post(&group_id, "", "sneaky", "nope").await,
        Err(ClientError::Server(_))
    ));

    // The reader can delete their own reply; the leftover is the root.
    let after_delete = reader.delete_post(&reply.id).await.unwrap();
    assert_eq!(after_delete.len(), 1);
    assert_eq!(after_delete[0].id, root_id);

    ts.stop();
}

#[tokio::test]
async fn admin_moves_a_folder_into_another() {
    let ts = TestServer::start().await;
    ts.seed_account("sysop", "pw", 3).await; // Admin: has FILE_MANAGE_TREE

    let (sysop, mut es, _d1) = ts.connect_client().await;
    next_event(&mut es).await;
    sysop.login("sysop", "pw").await.unwrap();

    sysop.create_folder("/", "a", 0, 0, 1).await.unwrap();
    sysop.create_folder("/", "b", 0, 0, 1).await.unwrap();
    sysop.create_folder("/a", "sub", 0, 0, 1).await.unwrap();

    // Move /a (carrying /a/sub with it) into /b; the reply is /b's listing.
    let dest_listing = sysop.move_path("/a", "/b").await.unwrap();
    assert!(dest_listing.entries.iter().any(|e| e.name == "a"));

    // /a is gone from root; /b/a/sub still resolves.
    assert!(sysop.list_files("/a").await.is_err());
    assert!(sysop.list_files("/b/a/sub").await.is_ok());

    // Moving a folder into its own descendant is refused.
    assert!(matches!(
        sysop.move_path("/b/a", "/b/a/sub").await,
        Err(ClientError::Server(_))
    ));

    ts.stop();
}

#[tokio::test]
async fn plain_user_cannot_move_files() {
    let ts = TestServer::start().await;
    ts.seed_account("plain", "pw", 1).await; // no FILE_MANAGE_TREE
    ts.seed_account("sysop", "pw", 3).await;

    let (sysop, mut es, _d1) = ts.connect_client().await;
    next_event(&mut es).await;
    sysop.login("sysop", "pw").await.unwrap();
    sysop.create_folder("/", "a", 0, 0, 1).await.unwrap();
    sysop.create_folder("/", "b", 0, 0, 1).await.unwrap();

    let (plain, mut ep, _d2) = ts.connect_client().await;
    next_event(&mut ep).await;
    plain.login("plain", "pw").await.unwrap();

    assert!(matches!(
        plain.move_path("/a", "/b").await,
        Err(ClientError::Server(_))
    ));

    ts.stop();
}

#[tokio::test]
async fn admin_generates_catalog_and_search_is_class_filtered() {
    let ts = TestServer::start().await;
    ts.seed_account("sysop", "pw", 3).await; // Admin
    ts.seed_account("guest", "pw", 0).await; // Guest

    let (sysop, mut es, _d1) = ts.connect_client().await;
    next_event(&mut es).await;
    sysop.login("sysop", "pw").await.unwrap();

    sysop.create_folder("/", "pub", 0, 0, 1).await.unwrap();
    let listing = sysop.list_files("/pub").await.unwrap();
    let _ = listing; // just to exercise the freshly-created folder
    sysop.create_folder("/", "staff", 0, 3, 3).await.unwrap(); // admin-only

    // Before generating a catalog, search is refused.
    assert!(matches!(
        sysop.search_files("").await,
        Err(ClientError::Server(_))
    ));

    let count = sysop.generate_catalog().await.unwrap();
    assert!(count >= 2);

    // The admin sees both folders.
    let admin_hits = sysop.search_files("").await.unwrap();
    let names: Vec<_> = admin_hits.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"pub"));
    assert!(names.contains(&"staff"));

    // A guest's search is class-filtered to just the public folder.
    let (guest, mut eg, _d2) = ts.connect_client().await;
    next_event(&mut eg).await;
    guest.login("guest", "pw").await.unwrap();
    let guest_hits = guest.search_files("").await.unwrap();
    let guest_names: Vec<_> = guest_hits.iter().map(|e| e.name.as_str()).collect();
    assert!(guest_names.contains(&"pub"));
    assert!(!guest_names.contains(&"staff"));

    // A name filter narrows further.
    let filtered = sysop.search_files("staff").await.unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "staff");

    ts.stop();
}

#[tokio::test]
async fn plain_user_cannot_generate_catalog() {
    let ts = TestServer::start().await;
    ts.seed_account("plain", "pw", 1).await; // no FILE_MANAGE_TREE

    let (client, mut events, _dd) = ts.connect_client().await;
    next_event(&mut events).await;
    client.login("plain", "pw").await.unwrap();

    assert!(matches!(
        client.generate_catalog().await,
        Err(ClientError::Server(_))
    ));

    ts.stop();
}

#[tokio::test]
async fn tracker_lists_the_self_registered_server() {
    let ts = TestServer::start().await;
    ts.seed_account("phraq", "pw", 1).await;

    let (client, mut events, _dd) = ts.connect_client().await;
    next_event(&mut events).await;
    client.login("phraq", "pw").await.unwrap();

    // The server self-registers in its own tracker at startup; the directory
    // lists it (default name "KDX Server", advertised on the bound port).
    let servers = client.list_servers("").await.unwrap();
    let me = servers
        .iter()
        .find(|s| s.port == ts.port())
        .expect("self-registered server present");
    assert_eq!(me.name, "KDX Server");
    assert_eq!(me.max_users, 256);

    // The name filter is honored.
    assert_eq!(client.list_servers("KDX").await.unwrap().len(), 1);
    assert!(client.list_servers("no-such-server").await.unwrap().is_empty());

    ts.stop();
}

#[tokio::test]
async fn admin_views_and_updates_server_settings_and_greeting_shows_on_login() {
    let ts = TestServer::start().await;
    ts.seed_account("sysop", "pw", 3).await; // Admin: has SERVER_ADMIN
    ts.seed_account("later", "pw", 1).await;

    let (sysop, mut es, _d1) = ts.connect_client().await;
    next_event(&mut es).await;
    sysop.login("sysop", "pw").await.unwrap();

    let current = sysop.get_server_settings().await.unwrap();
    assert_eq!(current.name, "KDX Server");
    assert_eq!(current.greeting, "");
    assert_eq!(current.port, ts.port());

    let updated = sysop
        .update_server_settings("The Underground", "warez & wares", "welcome back", 42)
        .await
        .unwrap();
    assert_eq!(updated.name, "The Underground");
    assert_eq!(updated.description, "warez & wares");
    assert_eq!(updated.greeting, "welcome back");
    assert_eq!(updated.max_users, 42);

    // A fresh read agrees (it's live server state, not an echo).
    assert_eq!(sysop.get_server_settings().await.unwrap().name, "The Underground");

    // A newly-logging-in user sees the greeting right after AuthResult.
    let (later, mut el, _d2) = ts.connect_client().await;
    next_event(&mut el).await;
    later.login("later", "pw").await.unwrap();
    let mut saw_greeting = false;
    for _ in 0..5 {
        if let Event::ServerInfo { text } = next_event(&mut el).await {
            assert_eq!(text, "welcome back");
            saw_greeting = true;
            break;
        }
    }
    assert!(saw_greeting, "new login should see the greeting");

    ts.stop();
}

#[tokio::test]
async fn plain_user_cannot_view_or_update_server_settings() {
    let ts = TestServer::start().await;
    ts.seed_account("plain", "pw", 1).await; // no SERVER_ADMIN

    let (client, mut events, _dd) = ts.connect_client().await;
    next_event(&mut events).await;
    client.login("plain", "pw").await.unwrap();

    assert!(matches!(client.get_server_settings().await, Err(ClientError::Server(_))));
    assert!(matches!(
        client.update_server_settings("hax", "", "", 1).await,
        Err(ClientError::Server(_))
    ));

    ts.stop();
}

#[tokio::test]
async fn admin_broadcast_reaches_every_connected_session() {
    let ts = TestServer::start().await;
    ts.seed_account("sysop", "pw", 3).await;
    ts.seed_account("bystander", "pw", 1).await;

    let (sysop, mut es, _d1) = ts.connect_client().await;
    next_event(&mut es).await;
    sysop.login("sysop", "pw").await.unwrap();

    let (bystander, mut eb, _d2) = ts.connect_client().await;
    next_event(&mut eb).await;
    bystander.login("bystander", "pw").await.unwrap();

    sysop.broadcast("server restarting in 5 minutes").await.unwrap();

    // The bystander receives it even though they're in no chat room with
    // the admin and it's not a private message.
    let mut got = false;
    for _ in 0..10 {
        if let Event::ServerInfo { text } = next_event(&mut eb).await {
            assert_eq!(text, "server restarting in 5 minutes");
            got = true;
            break;
        }
    }
    assert!(got, "bystander should receive the broadcast");

    // The admin gets an ack naming how many sessions were reached.
    let mut saw_ack = false;
    for _ in 0..10 {
        if let Event::ServerInfo { text } = next_event(&mut es).await {
            if text.contains("session") {
                saw_ack = true;
                break;
            }
        }
    }
    assert!(saw_ack, "admin should get a reached-count ack");

    ts.stop();
}

#[tokio::test]
async fn plain_user_cannot_broadcast_or_shutdown() {
    let ts = TestServer::start().await;
    ts.seed_account("plain", "pw", 1).await;

    let (client, mut events, _dd) = ts.connect_client().await;
    next_event(&mut events).await;
    client.login("plain", "pw").await.unwrap();

    client.broadcast("nope").await.unwrap(); // the send itself succeeds...
    let mut refused = false;
    for _ in 0..10 {
        if let Event::ServerError { text } = next_event(&mut events).await {
            assert!(text.contains("SERVER_ADMIN"));
            refused = true;
            break;
        }
    }
    assert!(refused, "broadcast should be refused server-side");

    client.shutdown_server("nope").await.unwrap();
    let mut shutdown_refused = false;
    for _ in 0..10 {
        if let Event::ServerError { text } = next_event(&mut events).await {
            assert!(text.contains("SERVER_ADMIN"));
            shutdown_refused = true;
            break;
        }
    }
    assert!(shutdown_refused, "shutdown should be refused server-side");

    ts.stop();
}

#[tokio::test]
async fn admin_shutdown_disconnects_everyone_and_stops_the_listener() {
    let ts = TestServer::start().await;
    ts.seed_account("sysop", "pw", 3).await;
    ts.seed_account("bystander", "pw", 1).await;
    let port = ts.port();

    let (sysop, mut es, _d1) = ts.connect_client().await;
    next_event(&mut es).await;
    sysop.login("sysop", "pw").await.unwrap();

    let (bystander, mut eb, _d2) = ts.connect_client().await;
    next_event(&mut eb).await;
    bystander.login("bystander", "pw").await.unwrap();

    sysop.shutdown_server("goodnight").await.unwrap();

    // Both the admin and the bystander see the notice, then get disconnected.
    for rx in [&mut es, &mut eb] {
        let mut saw_notice = false;
        let mut saw_disconnect = false;
        for _ in 0..10 {
            match next_event(rx).await {
                Event::ServerInfo { text } if text == "goodnight" => saw_notice = true,
                Event::Disconnected { .. } => {
                    saw_disconnect = true;
                    break;
                }
                _ => {}
            }
        }
        assert!(saw_notice, "should see the shutdown notice");
        assert!(saw_disconnect, "should be disconnected");
    }

    // The accept loop stops taking new connections. A little slack for the
    // listener task to actually observe the shutdown notify and break.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let data_dir = tempfile::tempdir().unwrap();
    let cfg = ClientConfig::new("127.0.0.1", port, data_dir.path());
    assert!(connect(cfg).await.is_err(), "listener should have stopped accepting");

    // Not calling ts.stop(): the server already shut itself down; aborting a
    // finished task is a harmless no-op.
    ts.stop();
}

#[tokio::test]
async fn invite_delivers_and_both_parties_share_a_private_room() {
    let ts = TestServer::start().await;
    ts.seed_account("alice", "pw", 1).await; // User class: has CHAT_PRIVATE
    ts.seed_account("bob", "pw", 1).await;

    let (alice, mut ea, _d1) = ts.connect_client().await;
    next_event(&mut ea).await;
    alice.login("alice", "pw").await.unwrap();

    let (bob, mut eb, _d2) = ts.connect_client().await;
    next_event(&mut eb).await;
    bob.login("bob", "pw").await.unwrap();

    alice.invite_to_chat("bob").await.unwrap();

    // Alice gets an ack naming bob.
    let mut saw_ack = false;
    for _ in 0..10 {
        if let Event::ServerInfo { text } = next_event(&mut ea).await {
            assert!(text.contains("bob"));
            saw_ack = true;
            break;
        }
    }
    assert!(saw_ack);

    // Bob receives the invite and joins the named private room.
    let mut room = None;
    for _ in 0..10 {
        if let Event::ChatInvited { from, room: r } = next_event(&mut eb).await {
            assert_eq!(from, "alice");
            assert!(r.starts_with("priv-"));
            room = Some(r);
            break;
        }
    }
    let room = room.expect("bob should be invited");
    bob.join(&room).await.unwrap();

    // Alice's chat in that room reaches bob — they're sharing the same
    // private room, not just two independent one-member rooms.
    alice.send_chat(&room, 0, "you there?").await.unwrap();
    let (sender, text, _) = wait_chat(&mut eb, false).await;
    assert_eq!(sender, "alice");
    assert_eq!(text, "you there?");

    ts.stop();
}

#[tokio::test]
async fn invite_to_an_offline_user_is_refused() {
    let ts = TestServer::start().await;
    ts.seed_account("alice", "pw", 1).await;

    let (alice, mut ea, _d1) = ts.connect_client().await;
    next_event(&mut ea).await;
    alice.login("alice", "pw").await.unwrap();

    alice.invite_to_chat("ghost").await.unwrap();
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
async fn guest_cannot_invite_to_chat() {
    let ts = TestServer::start().await;
    ts.seed_account("guest1", "pw", 0).await; // Guest: no CHAT_PRIVATE
    ts.seed_account("guest2", "pw", 0).await;

    let (guest1, mut e1, _d1) = ts.connect_client().await;
    next_event(&mut e1).await;
    guest1.login("guest1", "pw").await.unwrap();

    guest1.invite_to_chat("guest2").await.unwrap(); // the send itself succeeds...
    let mut refused = false;
    for _ in 0..10 {
        if let Event::ServerError { text } = next_event(&mut e1).await {
            assert!(text.contains("CHAT_PRIVATE"));
            refused = true;
            break;
        }
    }
    assert!(refused);

    ts.stop();
}

#[tokio::test]
async fn cannot_invite_yourself() {
    let ts = TestServer::start().await;
    ts.seed_account("alice", "pw", 1).await;

    let (alice, mut ea, _d1) = ts.connect_client().await;
    next_event(&mut ea).await;
    alice.login("alice", "pw").await.unwrap();

    alice.invite_to_chat("alice").await.unwrap();
    let mut refused = false;
    for _ in 0..10 {
        if let Event::ServerError { text } = next_event(&mut ea).await {
            assert!(text.contains("yourself"));
            refused = true;
            break;
        }
    }
    assert!(refused);

    ts.stop();
}

#[tokio::test]
async fn admin_creates_and_deletes_folders() {
    let ts = TestServer::start().await;
    ts.seed_account("sysop", "pw", 3).await; // Admin: has FILE_MANAGE_TREE

    let (sysop, mut es, _d1) = ts.connect_client().await;
    next_event(&mut es).await;
    sysop.login("sysop", "pw").await.unwrap();

    // Create a normal folder and an upload folder at the root.
    let listing = sysop.create_folder("/", "pub", 0, 0, 1).await.unwrap();
    assert!(listing.entries.iter().any(|e| e.name == "pub"));
    sysop.create_folder("/", "incoming", 3, 0, 0).await.unwrap();

    // Nest a subfolder, then delete the whole /pub subtree.
    sysop.create_folder("/pub", "docs", 0, 0, 1).await.unwrap();
    let after = sysop.delete_path("/pub").await.unwrap();
    assert!(!after.entries.iter().any(|e| e.name == "pub"));
    assert!(after.entries.iter().any(|e| e.name == "incoming"));
    // /pub/docs went with it.
    assert!(sysop.list_files("/pub").await.is_err());

    ts.stop();
}

#[tokio::test]
async fn plain_user_cannot_manage_the_tree() {
    let ts = TestServer::start().await;
    ts.seed_account("plain", "pw", 1).await; // no FILE_MANAGE_TREE

    let (client, mut events, _dd) = ts.connect_client().await;
    next_event(&mut events).await;
    client.login("plain", "pw").await.unwrap();

    assert!(matches!(
        client.create_folder("/", "mine", 0, 0, 0).await,
        Err(ClientError::Server(_))
    ));
    assert!(matches!(
        client.delete_path("/anything").await,
        Err(ClientError::Server(_))
    ));

    ts.stop();
}

#[tokio::test]
async fn plain_user_cannot_create_newsgroup() {
    let ts = TestServer::start().await;
    ts.seed_account("plain", "pw", 1).await;

    let (client, mut events, _dd) = ts.connect_client().await;
    next_event(&mut events).await;
    client.login("plain", "pw").await.unwrap();

    assert!(matches!(
        client.create_newsgroup("hax", "", 0, 0).await,
        Err(ClientError::Server(_))
    ));
    // Listing (read) is open to any connected user.
    assert!(client.list_newsgroups().await.unwrap().is_empty());

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

#[tokio::test]
async fn admin_views_history_after_actions_newest_first() {
    let ts = TestServer::start().await;
    ts.seed_account("sysop", "pw", 3).await; // Admin: has SERVER_ADMIN + USER_ADMIN
    ts.seed_account("plain", "pw", 1).await;

    let (sysop, mut es, _d1) = ts.connect_client().await;
    next_event(&mut es).await;
    sysop.login("sysop", "pw").await.unwrap();

    // A plain login (recorded), then two admin-worthy actions.
    let (plain, mut ep, _d2) = ts.connect_client().await;
    next_event(&mut ep).await;
    plain.login("plain", "pw").await.unwrap();

    sysop.create_account("newbie", "letmein", 1, 0, 0).await.unwrap();
    sysop
        .update_server_settings("The Underground", "", "", 0)
        .await
        .unwrap();

    let entries = sysop.list_history(10).await.unwrap();
    assert!(entries.len() >= 3, "expected at least login + 2 admin actions");
    // Newest first: the most recent action (settings update) leads.
    assert_eq!(entries[0].action, "server_settings_updated");
    assert!(entries.iter().any(|e| e.action == "account_created" && e.detail == "newbie"));
    assert!(entries.iter().any(|e| e.action == "login" && e.actor == "plain"));
    // Strictly non-increasing timestamps (newest first).
    for pair in entries.windows(2) {
        assert!(pair[0].timestamp >= pair[1].timestamp);
    }

    ts.stop();
}

#[tokio::test]
async fn plain_user_cannot_view_history() {
    let ts = TestServer::start().await;
    ts.seed_account("plain", "pw", 1).await; // no SERVER_ADMIN

    let (client, mut events, _dd) = ts.connect_client().await;
    next_event(&mut events).await;
    client.login("plain", "pw").await.unwrap();

    assert!(matches!(client.list_history(10).await, Err(ClientError::Server(_))));

    ts.stop();
}
