//! File-tree authorization at the handler boundary, end to end over TLS:
//! FILE_DELETE is the privilege that governs deletes, a new folder needs
//! write access to its parent (and can't hand out more than the creator
//! has), and a drop box's contents can't be moved out and then downloaded.

mod common;

use std::time::Duration;

use common::TestServer;
use kdx_client_core::{ClientError, ClientHandle, Event};
use kdx_storage::accounts;
use tokio::sync::mpsc::Receiver;

/// `Privileges::FILE_DELETE` (kdx-server-core `auth/classes.rs`).
const FILE_DELETE: i64 = 1 << 7;

async fn next_event(rx: &mut Receiver<Event>) -> Event {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("event timeout")
        .expect("event channel open")
}

async fn login_as(
    ts: &TestServer,
    username: &str,
) -> (ClientHandle, Receiver<Event>, tempfile::TempDir) {
    let (client, mut events, data_dir) = ts.connect_client().await;
    next_event(&mut events).await; // Connected
    client.login(username, "pw").await.unwrap();
    (client, events, data_dir)
}

async fn upload_text(client: &ClientHandle, data_dir: &tempfile::TempDir, dir: &str, name: &str) {
    let local = data_dir.path().join(name);
    std::fs::write(&local, name.as_bytes()).unwrap();
    client.upload(local, dir).await.unwrap();
}

#[tokio::test]
async fn file_delete_privilege_governs_deletes() {
    let ts = TestServer::start().await;
    ts.seed_account("sysop", "pw", 3).await;
    ts.seed_account("mallory", "pw", 2).await; // PowerUser, FILE_DELETE revoked
    ts.seed_account("ursula", "pw", 1).await; // User, FILE_DELETE granted
    let pool = kdx_storage::connect(&ts.db_path).await.unwrap();
    accounts::set_overrides(&pool, "mallory", 0, FILE_DELETE).await.unwrap();
    accounts::set_overrides(&pool, "ursula", FILE_DELETE, 0).await.unwrap();

    let (sysop, _es, sd) = login_as(&ts, "sysop").await;
    sysop.create_folder("/", "pub", 0, 0, 1, None).await.unwrap();
    upload_text(&sysop, &sd, "/pub", "a.txt").await;

    let (mallory, _em, _md) = login_as(&ts, "mallory").await;
    match mallory.delete_path("/pub/a.txt").await {
        Err(ClientError::Server(msg)) => assert!(msg.contains("FILE_DELETE"), "{msg}"),
        other => panic!("revoked FILE_DELETE still deleted: {other:?}"),
    }
    assert!(sysop.list_files("/pub").await.unwrap().entries.iter().any(|e| e.name == "a.txt"));

    // A grant works too: a User holding FILE_DELETE may delete a file in a
    // folder their class may write to.
    let (ursula, _eu, _ud) = login_as(&ts, "ursula").await;
    let after = ursula.delete_path("/pub/a.txt").await.unwrap();
    assert!(after.entries.iter().all(|e| e.name != "a.txt"));

    ts.stop();
}

#[tokio::test]
async fn create_folder_honours_the_parent_acl_and_the_creators_rights() {
    let ts = TestServer::start().await;
    ts.seed_account("sysop", "pw", 3).await;
    ts.seed_account("phraq", "pw", 2).await; // PowerUser: has FILE_MANAGE_TREE

    let (sysop, _es, _sd) = login_as(&ts, "sysop").await;
    sysop.create_folder("/", "locked", 0, 0, 3, None).await.unwrap(); // admin-write

    let (phraq, _ep, _pd) = login_as(&ts, "phraq").await;
    assert!(matches!(
        phraq.create_folder("/locked", "x", 0, 0, 0, None).await,
        Err(ClientError::Server(_))
    ));
    assert!(sysop.list_files("/locked").await.unwrap().entries.is_empty());

    // Someone else as owner needs USER_ADMIN; names are validated.
    assert!(matches!(
        phraq.create_folder("/", "mine", 0, 0, 0, Some("sysop")).await,
        Err(ClientError::Server(_))
    ));
    assert!(matches!(
        phraq.create_folder("/", "a/b", 0, 0, 0, None).await,
        Err(ClientError::Server(_))
    ));

    // Asking for admin-only classes gets the creator's own class instead.
    phraq.create_folder("/", "mine", 0, 3, 3, None).await.unwrap();
    let info = sysop.get_file_info("/mine").await.unwrap();
    assert_eq!(info.min_read_class, 2);
    assert_eq!(info.min_write_class, 2);

    ts.stop();
}

#[tokio::test]
async fn drop_box_contents_cannot_be_moved_out_and_downloaded() {
    let ts = TestServer::start().await;
    ts.seed_account("sysop", "pw", 3).await;
    ts.seed_account("phraq", "pw", 2).await;

    let (sysop, _es, sd) = login_as(&ts, "sysop").await;
    sysop.create_folder("/", "drop", 2, 0, 1, Some("bob")).await.unwrap();
    upload_text(&sysop, &sd, "/drop", "secret.txt").await;

    let (phraq, _ep, pd) = login_as(&ts, "phraq").await;
    assert!(matches!(
        phraq.move_path("/drop/secret.txt", "/").await,
        Err(ClientError::Server(_))
    ));
    assert!(matches!(
        phraq.delete_path("/drop/secret.txt").await,
        Err(ClientError::Server(_))
    ));
    for path in ["/secret.txt", "/drop/secret.txt"] {
        assert!(
            phraq.download(path, pd.path().join("got.bin")).await.is_err(),
            "{path} downloaded"
        );
    }
    // Still there for the admin.
    let listing = sysop.list_files("/drop").await.unwrap();
    assert!(listing.entries.iter().any(|e| e.name == "secret.txt"));

    ts.stop();
}
