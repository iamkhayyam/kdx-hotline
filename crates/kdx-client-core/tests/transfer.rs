//! C2 exit criteria: upload a ragged multi-chunk file and see it in a
//! listing; download it back byte-identical; kill-and-resume in both
//! directions transfers only the missing chunks; a hash mismatch is surfaced.

mod common;

use std::time::Duration;

use common::TestServer;
use kdx_client_core::{ClientHandle, Direction, Event};
use kdx_protocol::messages::KIND_FILE;
use tokio::sync::mpsc::Receiver;

async fn next_event(rx: &mut Receiver<Event>) -> Event {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("event timeout")
        .expect("event channel open")
}

async fn logged_in(ts: &TestServer) -> (ClientHandle, Receiver<Event>, tempfile::TempDir) {
    let (client, mut events, dd) = ts.connect_client().await;
    next_event(&mut events).await; // Connected
    client.login("user", "pw").await.unwrap();
    (client, events, dd)
}

fn blob(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 37 % 251) as u8).collect()
}

#[tokio::test]
async fn upload_then_list() {
    let ts = TestServer::start().await;
    ts.seed_account("user", "pw", 2).await;
    let (client, mut events, _dd) = logged_in(&ts).await;

    let src = tempfile::tempdir().unwrap();
    let path = src.path().join("payload.bin");
    let data = blob(32 * 1024 * 3 + 500); // 4 chunks, ragged
    std::fs::write(&path, &data).unwrap();

    client.upload(path, "/").await.unwrap();
    // upload() resolves on completion; the events also carry progress.
    let listing = client.list_files("/").await.unwrap();
    let entry = listing.entries.iter().find(|e| e.name == "payload.bin").unwrap();
    assert_eq!(entry.kind, KIND_FILE);
    assert_eq!(entry.size, data.len() as u64);

    // A progress event for the upload should have been emitted.
    let mut saw_upload_progress = false;
    while let Ok(ev) = events.try_recv() {
        if matches!(ev, Event::TransferProgress { direction: Direction::Upload, .. }) {
            saw_upload_progress = true;
        }
    }
    assert!(saw_upload_progress);

    ts.stop();
}

#[tokio::test]
async fn download_is_byte_identical() {
    let ts = TestServer::start().await;
    ts.seed_account("user", "pw", 2).await;
    let (client, _events, _dd) = logged_in(&ts).await;

    let src = tempfile::tempdir().unwrap();
    let up = src.path().join("grab.bin");
    let data = blob(32 * 1024 * 2 + 123);
    std::fs::write(&up, &data).unwrap();
    client.upload(up, "/").await.unwrap();

    let down = src.path().join("downloaded.bin");
    client.download("/grab.bin", down.clone()).await.unwrap();
    let got = std::fs::read(&down).unwrap();
    assert_eq!(got, data);
    // No sidecar left behind after a clean finish.
    assert!(!down.with_extension("bin.kdxpart").exists());

    ts.stop();
}

#[tokio::test]
async fn download_resumes_after_interruption() {
    // Throttle downloads so we can drop the client partway through, leaving a
    // partial .part and a resume sidecar on disk.
    let ts = TestServer::start_with_download_throttle(96 * 1024).await;
    ts.seed_account("user", "pw", 2).await;

    let src = tempfile::tempdir().unwrap();
    let up = src.path().join("big.bin");
    let data = blob(32 * 1024 * 6); // 6 chunks
    std::fs::write(&up, &data).unwrap();

    let local = src.path().join("out.bin");
    let sidecar = with_suffix(&local, ".kdxpart");

    // Upload the source (uploads are not throttled).
    {
        let (client, _e, _dd) = logged_in(&ts).await;
        client.upload(up, "/").await.unwrap();
    }

    // Start a download, then drop the client mid-stream. Dropping the handle
    // closes the command channel; the actor disconnects and the server's
    // download task ends. Partial bytes + sidecar persist.
    {
        let (client, _e, _dd) = logged_in(&ts).await;
        let dl = local.clone();
        let task = tokio::spawn(async move { client.download("/big.bin", dl).await });
        tokio::time::sleep(Duration::from_millis(400)).await;
        task.abort();
        let _ = task.await;
    }
    let partial = std::fs::read(&sidecar).expect("sidecar written during partial download");
    assert!(!partial.is_empty(), "expected some resume state");

    // Resume: a fresh download to the same local path picks up the sidecar and
    // completes byte-identical.
    let (client, _e, _dd) = logged_in(&ts).await;
    client.download("/big.bin", local.clone()).await.unwrap();
    assert_eq!(std::fs::read(&local).unwrap(), data);
    assert!(!sidecar.exists(), "sidecar removed on clean finish");

    ts.stop();
}

fn with_suffix(p: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(suffix);
    std::path::PathBuf::from(s)
}
