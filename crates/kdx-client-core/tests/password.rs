//! Credentials through the public `ClientHandle` API against the real
//! server: self-service password change, an administrator's reset, and
//! account creation — each with the credential derived on the client, so no
//! password crosses the wire.

mod common;

use std::time::Duration;

use common::TestServer;
use kdx_client_core::{ClientError, ClientHandle, Event};
use kdx_storage::accounts;
use tokio::sync::mpsc::Receiver;

async fn next_event(rx: &mut Receiver<Event>) -> Event {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("event timeout")
        .expect("event channel open")
}

/// The reason a server-closed session was given, then its `Disconnected`.
async fn kicked_reason(rx: &mut Receiver<Event>) -> String {
    let mut reason = None;
    loop {
        match next_event(rx).await {
            Event::ServerError { text } if text.starts_with("disconnected by the server") => {
                reason = Some(text)
            }
            Event::Disconnected { .. } => return reason.expect("a reason before the close"),
            _ => {}
        }
    }
}

/// Connect and log in; keeps the event stream and the client's data dir.
async fn logged_in(
    ts: &TestServer,
    username: &str,
    password: &str,
) -> (ClientHandle, Receiver<Event>, tempfile::TempDir) {
    let (client, mut events, dir) = ts.connect_client().await;
    next_event(&mut events).await; // Connected
    client.login(username, password).await.unwrap();
    (client, events, dir)
}

/// Whether a fresh connection can log in with `password`.
async fn can_log_in(ts: &TestServer, username: &str, password: &str) -> bool {
    let (client, mut events, _dir) = ts.connect_client().await;
    next_event(&mut events).await;
    let ok = match client.login(username, password).await {
        Ok(_) => true,
        Err(ClientError::AuthFailed(_)) => false,
        Err(other) => panic!("unexpected login error: {other}"),
    };
    client.disconnect().await;
    ok
}

/// Seed an account with privilege overrides (the harness's `seed_account`
/// has none).
async fn seed_with(ts: &TestServer, username: &str, class: i64, granted: u32) {
    let pool = kdx_storage::connect(&ts.db_path).await.unwrap();
    let credential = kdx_crypto::hash_password("pw").unwrap();
    accounts::create(&pool, username, &credential, class, granted as i64, 0)
        .await
        .unwrap();
}

#[tokio::test]
async fn change_password_signs_out_other_sessions_and_keeps_this_one() {
    let ts = TestServer::start().await;
    ts.seed_account("phraq", "s3cret", 1).await;
    let (mine, _mine_events, _d1) = logged_in(&ts, "phraq", "s3cret").await;
    let (_other, mut other_events, _d2) = logged_in(&ts, "phraq", "s3cret").await;

    let message = mine.change_password("s3cret", "n3w-pass").await.unwrap();
    assert!(message.contains("1 other session"), "{message}");

    // The other session is told why and closed; this one carries on.
    let reason = kicked_reason(&mut other_events).await;
    assert!(reason.contains("password was changed"), "{reason}");
    assert!(mine.list_users().await.is_ok());

    assert!(!can_log_in(&ts, "phraq", "s3cret").await);
    assert!(can_log_in(&ts, "phraq", "n3w-pass").await);

    // The stored credential is the client-derived SCRAM record.
    let pool = kdx_storage::connect(&ts.db_path).await.unwrap();
    let row = accounts::by_username(&pool, "phraq").await.unwrap().unwrap();
    let stored = row.credential.expect("a credential");
    assert!(kdx_crypto::verify_password("n3w-pass", &stored).unwrap());
    ts.stop();
}

#[tokio::test]
async fn wrong_current_password_is_refused_and_changes_nothing() {
    let ts = TestServer::start().await;
    ts.seed_account("phraq", "s3cret", 1).await;
    let (client, _events, _dir) = logged_in(&ts, "phraq", "s3cret").await;

    match client.change_password("guess", "hijacked").await {
        Err(ClientError::AuthFailed(message)) => {
            assert_eq!(message, "the current password is incorrect")
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
    // Still logged in, and the request queue is still in step.
    assert!(client.list_users().await.is_ok());
    // A right one afterwards goes through.
    client.change_password("s3cret", "next").await.unwrap();
    assert!(can_log_in(&ts, "phraq", "next").await);
    assert!(!can_log_in(&ts, "phraq", "hijacked").await);
    ts.stop();
}

#[tokio::test]
async fn concurrent_changes_on_one_connection_take_turns() {
    let ts = TestServer::start().await;
    ts.seed_account("phraq", "s3cret", 1).await;
    let (client, _events, _dir) = logged_in(&ts, "phraq", "s3cret").await;
    let other = client.clone();

    // The server holds one challenge per connection; interleaved changes
    // would answer each other's. Serialized, the first wins and the second
    // (still proving the old password) is a plain wrong-password refusal.
    let (a, b) = tokio::join!(
        client.change_password("s3cret", "first-pass"),
        other.change_password("s3cret", "second-pass")
    );
    let (won, lost) = match (a, b) {
        (Ok(_), Err(e)) => ("first-pass", e),
        (Err(e), Ok(_)) => ("second-pass", e),
        other => panic!("expected exactly one change to win: {other:?}"),
    };
    assert!(matches!(lost, ClientError::AuthFailed(_)), "{lost:?}");
    assert!(can_log_in(&ts, "phraq", won).await);
    assert!(!can_log_in(&ts, "phraq", "s3cret").await);
    ts.stop();
}

#[tokio::test]
async fn change_password_needs_a_login_and_a_non_guest_account() {
    let ts = TestServer::start().await;
    ts.seed_account("visitor", "pw", 0).await;

    // Before login nothing is sent (the server would drop the connection).
    let (client, mut events, _dir) = ts.connect_client().await;
    next_event(&mut events).await;
    assert!(matches!(
        client.change_password("pw", "new").await,
        Err(ClientError::InvalidInput(_))
    ));
    assert!(matches!(
        client.change_password("pw", "").await,
        Err(ClientError::InvalidInput(_))
    ));
    // The connection is fine: log in, as a guest.
    client.login("visitor", "pw").await.unwrap();
    match client.change_password("pw", "mine now").await {
        Err(ClientError::Server(message)) => assert!(message.contains("guest"), "{message}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(client.list_users().await.is_ok());
    assert!(can_log_in(&ts, "visitor", "pw").await);
    ts.stop();
}

#[tokio::test]
async fn admin_resets_a_password_within_the_policy() {
    let ts = TestServer::start().await;
    ts.seed_account("sysop", "pw", 3).await;
    ts.seed_account("plain", "pw", 1).await;
    seed_with(&ts, "helpdesk", 2, 1 << 18).await; // PowerUser + USER_ADMIN
    let (_plain, mut plain_events, _d1) = logged_in(&ts, "plain", "pw").await;
    let (helpdesk, _he, _d2) = logged_in(&ts, "helpdesk", "pw").await;

    // A delegated admin can't reset an Admin, nor its own password.
    for target in ["sysop", "helpdesk"] {
        assert!(
            matches!(
                helpdesk.set_account_password(target, "pwned").await,
                Err(ClientError::Server(_))
            ),
            "{target}"
        );
    }
    assert!(can_log_in(&ts, "sysop", "pw").await);

    // A lower account: reset, listed, and its session is kicked.
    let accounts = helpdesk.set_account_password("plain", "temp-pass").await.unwrap();
    assert!(accounts.iter().any(|a| a.username == "plain"));
    let reason = kicked_reason(&mut plain_events).await;
    assert!(reason.contains("reset by an administrator"), "{reason}");
    assert!(!can_log_in(&ts, "plain", "pw").await);
    assert!(can_log_in(&ts, "plain", "temp-pass").await);

    // An empty password is refused before anything is sent.
    assert!(matches!(
        helpdesk.set_account_password("plain", "").await,
        Err(ClientError::InvalidInput(_))
    ));
    ts.stop();
}

#[tokio::test]
async fn create_account_sends_a_client_derived_credential() {
    let ts = TestServer::start().await;
    ts.seed_account("sysop", "pw", 3).await;
    let (sysop, _events, _dir) = logged_in(&ts, "sysop", "pw").await;

    sysop.create_account("newbie", "letmein", 1, 0, 0).await.unwrap();
    assert!(matches!(
        sysop.create_account("blank", "", 1, 0, 0).await,
        Err(ClientError::InvalidInput(_))
    ));

    let pool = kdx_storage::connect(&ts.db_path).await.unwrap();
    let row = accounts::by_username(&pool, "newbie").await.unwrap().unwrap();
    let credential = kdx_crypto::StoredCredential::decode(row.credential.as_deref().unwrap()).unwrap();
    assert_eq!(credential.params, kdx_crypto::KdfParams::DEFAULT);
    assert!(credential.matches_password("letmein").unwrap());
    assert!(accounts::by_username(&pool, "blank").await.unwrap().is_none());
    assert!(can_log_in(&ts, "newbie", "letmein").await);
    ts.stop();
}
