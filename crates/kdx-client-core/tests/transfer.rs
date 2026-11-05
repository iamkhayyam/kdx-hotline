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

/// CLIENT-9: a partial download's resume state must not be trusted once the
/// remote file has changed; the retry must produce the new bytes (and must
/// not stay stuck on a hash mismatch).
#[tokio::test]
async fn resume_recovers_when_the_remote_file_changed() {
    let ts = TestServer::start_with_download_throttle(96 * 1024).await;
    ts.seed_account("user", "pw", 2).await;

    let src = tempfile::tempdir().unwrap();
    let up = src.path().join("big.bin");
    let old = blob(32 * 1024 * 6);
    std::fs::write(&up, &old).unwrap();
    let local = src.path().join("out.bin");
    let sidecar = with_suffix(&local, ".kdxpart");

    {
        let (client, _e, _dd) = logged_in(&ts).await;
        client.upload(up.clone(), "/").await.unwrap();
    }
    {
        let (client, _e, _dd) = logged_in(&ts).await;
        let dl = local.clone();
        let task = tokio::spawn(async move { client.download("/big.bin", dl).await });
        tokio::time::sleep(Duration::from_millis(400)).await;
        task.abort();
        let _ = task.await;
    }
    assert!(sidecar.exists(), "resume state written during the partial download");

    // Replace the remote file with different bytes of the same size.
    let new: Vec<u8> = old.iter().map(|b| b.wrapping_add(1)).collect();
    std::fs::write(&up, &new).unwrap();
    let (client, _e, _dd) = logged_in(&ts).await;
    client.delete_path("/big.bin").await.unwrap();
    client.upload(up, "/").await.unwrap();

    client.download("/big.bin", local.clone()).await.unwrap();
    assert_eq!(std::fs::read(&local).unwrap(), new);
    assert!(!sidecar.exists());
    assert!(!with_suffix(&local, ".kdxdata").exists());

    ts.stop();
}

/// CLIENT-12: a resume request whose bitmap exceeds one frame is sent
/// fragmented instead of killing the session.
#[tokio::test]
async fn oversized_resume_bitmap_does_not_kill_the_session() {
    let ts = TestServer::start().await;
    ts.seed_account("user", "pw", 2).await;
    let (client, _events, _dd) = logged_in(&ts).await;

    let src = tempfile::tempdir().unwrap();
    let up = src.path().join("grab.bin");
    let data = blob(32 * 1024 * 2 + 9);
    std::fs::write(&up, &data).unwrap();
    client.upload(up, "/").await.unwrap();

    // A (stale) sidecar for a ~5 GiB file: its 20 KiB bitmap doesn't fit a
    // 16 KiB frame.
    let local = src.path().join("down.bin");
    let size: u64 = 32 * 1024 * 163_840;
    let bitmap = base64_encode(&vec![0u8; 20 * 1024]);
    let server = base64_encode(format!("127.0.0.1:{}", ts.port()).as_bytes());
    let remote = base64_encode(b"/grab.bin");
    let sha = base64_encode(&[0u8; 32]);
    std::fs::write(
        with_suffix(&local, ".kdxpart"),
        format!(
            "version=2\nserver={server}\nremote={remote}\nid=07070707-0707-0707-0707-070707070707\n\
             size={size}\nchunk_size=32768\nsha256={sha}\nbitmap={bitmap}\n"
        ),
    )
    .unwrap();
    std::fs::write(with_suffix(&local, ".kdxdata"), b"").unwrap();

    client.download("/grab.bin", local.clone()).await.unwrap();
    assert_eq!(std::fs::read(&local).unwrap(), data);
    client.list_files("/").await.expect("session still alive");

    ts.stop();
}

/// CLIENT-10: uploading an empty file must not wedge the client. A server
/// that finishes zero-chunk uploads (XFER-7) completes it; against one
/// that never sends TransferEnd the client stays usable and can cancel.
#[tokio::test]
async fn empty_upload_does_not_wedge_the_client() {
    let ts = TestServer::start().await;
    ts.seed_account("user", "pw", 2).await;
    let (client, _events, _dd) = logged_in(&ts).await;

    let src = tempfile::tempdir().unwrap();
    let empty = src.path().join(".gitkeep");
    std::fs::write(&empty, b"").unwrap();
    match tokio::time::timeout(Duration::from_secs(1), client.upload(empty, "/")).await {
        Ok(result) => {
            result.unwrap();
            let listing = client.list_files("/").await.unwrap();
            let entry = listing.entries.iter().find(|e| e.name == ".gitkeep").unwrap();
            assert_eq!(entry.size, 0);
        }
        Err(_) => {
            // Older server: no TransferEnd ever comes. The actor is still
            // responsive and the transfer can be cancelled.
            assert!(client.cancel_transfer().await.unwrap());
            client.list_files("/").await.unwrap();
        }
    }

    ts.stop();
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn with_suffix(p: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(suffix);
    std::path::PathBuf::from(s)
}
