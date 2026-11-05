//! C2 exit criteria: upload a ragged multi-chunk file and see it in a
//! listing; download it back byte-identical; kill-and-resume in both
//! directions transfers only the missing chunks; a hash mismatch is surfaced.
//!
//! Partial downloads live in the client's data dir (`<data_dir>/transfers`),
//! never beside the destination (macOS App Sandbox): resuming needs the same
//! data dir, as an app restart has.

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::TestServer;
use kdx_client_core::{ClientHandle, Direction, Event, TRANSFERS_DIR};
use kdx_protocol::messages::KIND_FILE;
use sha2::{Digest, Sha256};
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

/// Log in with the given (persistent) data dir.
async fn logged_in_with(ts: &TestServer, data_dir: &Path) -> (ClientHandle, Receiver<Event>) {
    let (client, mut events) = ts.connect_client_in(data_dir).await;
    next_event(&mut events).await; // Connected
    client.login("user", "pw").await.unwrap();
    (client, events)
}

/// A partial download's data file and sidecar, re-derived here from the
/// documented layout: `<data_dir>/transfers/<id>.kdxdata|.kdxpart`, `<id>` =
/// the first 16 bytes (hex) of SHA-256("kdx-partial-download-v1" ‖ each of
/// server, remote, destination as u64-BE length + bytes).
fn partial_paths(data_dir: &Path, port: u16, remote: &str, local: &Path) -> (PathBuf, PathBuf) {
    let mut h = Sha256::new();
    h.update(b"kdx-partial-download-v1");
    let server = format!("127.0.0.1:{port}");
    for field in [server.as_bytes(), remote.as_bytes(), local.as_os_str().as_encoded_bytes()] {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field);
    }
    let id: String = h.finalize()[..16].iter().map(|b| format!("{b:02x}")).collect();
    let dir = data_dir.join(TRANSFERS_DIR);
    (dir.join(format!("{id}.kdxdata")), dir.join(format!("{id}.kdxpart")))
}

/// Every file name in `dir` (empty if it doesn't exist).
fn names(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
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
    let (client, _events, dd) = logged_in(&ts).await;

    let src = tempfile::tempdir().unwrap();
    let up = src.path().join("grab.bin");
    let data = blob(32 * 1024 * 2 + 123);
    std::fs::write(&up, &data).unwrap();
    client.upload(up, "/").await.unwrap();

    let down = src.path().join("downloaded.bin");
    client.download("/grab.bin", down.clone()).await.unwrap();
    let got = std::fs::read(&down).unwrap();
    assert_eq!(got, data);
    // Nothing but the file beside it, and no partial left after a clean finish.
    assert_eq!(names(src.path()), vec!["downloaded.bin", "grab.bin"]);
    assert!(names(&dd.path().join(TRANSFERS_DIR)).is_empty());

    ts.stop();
}

#[tokio::test]
async fn download_resumes_after_interruption() {
    // Throttle downloads so we can drop the client partway through, leaving
    // partial bytes and a resume sidecar on disk.
    let ts = TestServer::start_with_download_throttle(96 * 1024).await;
    ts.seed_account("user", "pw", 2).await;
    // The app's data dir, kept across "restarts".
    let dd = tempfile::tempdir().unwrap();

    let src = tempfile::tempdir().unwrap();
    let up = src.path().join("big.bin");
    let data = blob(32 * 1024 * 6); // 6 chunks
    std::fs::write(&up, &data).unwrap();

    let dest = tempfile::tempdir().unwrap();
    let local = dest.path().join("out.bin");
    let (data_file, sidecar) = partial_paths(dd.path(), ts.port(), "/big.bin", &local);

    // Upload the source (uploads are not throttled).
    {
        let (client, _e) = logged_in_with(&ts, dd.path()).await;
        client.upload(up, "/").await.unwrap();
    }

    // Start a download, then drop the client mid-stream (once at least one
    // chunk is in). Dropping the handle closes the command channel; the
    // actor disconnects and the server's download task ends. Partial bytes +
    // sidecar persist — in the data dir.
    {
        let (client, mut events) = logged_in_with(&ts, dd.path()).await;
        let dl = local.clone();
        let task = tokio::spawn(async move { client.download("/big.bin", dl).await });
        loop {
            match next_event(&mut events).await {
                Event::TransferProgress { direction: Direction::Download, done, total, .. }
                    if done >= 1 =>
                {
                    assert!(done < total, "the download finished before it was interrupted");
                    break;
                }
                _ => {}
            }
        }
        task.abort();
        let _ = task.await;
        // The actor saves the resume state before it reports the end.
        while !matches!(next_event(&mut events).await, Event::Disconnected { .. }) {}
    }
    let partial = std::fs::read(&sidecar).expect("sidecar written during partial download");
    assert!(!partial.is_empty(), "expected some resume state");
    assert!(data_file.exists(), "partial bytes kept in the data dir");
    assert!(names(dest.path()).is_empty(), "nothing beside the destination: {:?}", names(dest.path()));

    // Resume after a "restart" (new connection, same data dir): a download
    // to the same local path picks up the sidecar and completes
    // byte-identical, fetching only what's missing.
    let (client, mut events) = logged_in_with(&ts, dd.path()).await;
    client.download("/big.bin", local.clone()).await.unwrap();
    assert_eq!(std::fs::read(&local).unwrap(), data);
    assert!(!sidecar.exists(), "sidecar removed on clean finish");
    assert!(names(&dd.path().join(TRANSFERS_DIR)).is_empty());
    assert_eq!(names(dest.path()), vec!["out.bin"]);
    let mut first_done = None;
    while let Ok(ev) = events.try_recv() {
        if let Event::TransferProgress { done, direction: Direction::Download, .. } = ev {
            first_done.get_or_insert(done);
        }
    }
    assert!(first_done.is_some_and(|d| d > 0), "resumed with chunks already done: {first_done:?}");

    ts.stop();
}

/// CLIENT-9: a partial download's resume state must not be trusted once the
/// remote file has changed; the retry must produce the new bytes (and must
/// not stay stuck on a hash mismatch).
#[tokio::test]
async fn resume_recovers_when_the_remote_file_changed() {
    let ts = TestServer::start_with_download_throttle(96 * 1024).await;
    ts.seed_account("user", "pw", 2).await;
    let dd = tempfile::tempdir().unwrap();

    let src = tempfile::tempdir().unwrap();
    let up = src.path().join("big.bin");
    let old = blob(32 * 1024 * 6);
    std::fs::write(&up, &old).unwrap();
    let local = src.path().join("out.bin");
    let (data_file, sidecar) = partial_paths(dd.path(), ts.port(), "/big.bin", &local);

    {
        let (client, _e) = logged_in_with(&ts, dd.path()).await;
        client.upload(up.clone(), "/").await.unwrap();
    }
    {
        let (client, _e) = logged_in_with(&ts, dd.path()).await;
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
    let (client, _e) = logged_in_with(&ts, dd.path()).await;
    client.delete_path("/big.bin").await.unwrap();
    client.upload(up, "/").await.unwrap();

    client.download("/big.bin", local.clone()).await.unwrap();
    assert_eq!(std::fs::read(&local).unwrap(), new);
    assert!(!sidecar.exists());
    assert!(!data_file.exists());

    ts.stop();
}

/// CLIENT-12: a resume request whose bitmap exceeds one frame is sent
/// fragmented instead of killing the session.
#[tokio::test]
async fn oversized_resume_bitmap_does_not_kill_the_session() {
    let ts = TestServer::start().await;
    ts.seed_account("user", "pw", 2).await;
    let (client, _events, dd) = logged_in(&ts).await;

    let src = tempfile::tempdir().unwrap();
    let up = src.path().join("grab.bin");
    let data = blob(32 * 1024 * 2 + 9);
    std::fs::write(&up, &data).unwrap();
    client.upload(up, "/").await.unwrap();

    // A (stale) sidecar for a ~5 GiB file: its 20 KiB bitmap doesn't fit a
    // 16 KiB frame.
    let local = src.path().join("down.bin");
    let (data_file, sidecar) = partial_paths(dd.path(), ts.port(), "/grab.bin", &local);
    let size: u64 = 32 * 1024 * 163_840;
    let bitmap = base64_encode(&vec![0u8; 20 * 1024]);
    let server = base64_encode(format!("127.0.0.1:{}", ts.port()).as_bytes());
    let remote = base64_encode(b"/grab.bin");
    let destination = base64_encode(local.as_os_str().as_encoded_bytes());
    let sha = base64_encode(&[0u8; 32]);
    std::fs::create_dir_all(sidecar.parent().unwrap()).unwrap();
    std::fs::write(
        &sidecar,
        format!(
            "version=3\nserver={server}\nremote={remote}\ndestination={destination}\n\
             id=07070707-0707-0707-0707-070707070707\n\
             size={size}\nchunk_size=32768\nsha256={sha}\nbitmap={bitmap}\n"
        ),
    )
    .unwrap();
    std::fs::write(&data_file, b"").unwrap();

    client.download("/grab.bin", local.clone()).await.unwrap();
    assert_eq!(std::fs::read(&local).unwrap(), data);
    client.list_files("/").await.expect("session still alive");

    ts.stop();
}

/// Partials nobody has touched for `stale_partial_age` are deleted when
/// connecting, so abandoned downloads can't fill the disk; recent ones (and
/// anything that isn't a partial) are left alone.
#[tokio::test]
async fn connecting_sweeps_stale_partial_downloads() {
    let ts = TestServer::start().await;
    let dd = tempfile::tempdir().unwrap();
    let transfers = dd.path().join(TRANSFERS_DIR);
    std::fs::create_dir_all(&transfers).unwrap();
    let now = std::time::SystemTime::now();
    let day = Duration::from_secs(24 * 60 * 60);
    let put = |name: &str, age: Duration| {
        let path = transfers.join(name);
        std::fs::write(&path, b"partial").unwrap();
        let f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.set_modified(now - age).unwrap();
    };
    let (stale, recent) = ("a".repeat(32), "b".repeat(32));
    put(&format!("{stale}.kdxdata"), 30 * day);
    put(&format!("{stale}.kdxpart"), 30 * day);
    put(&format!("{recent}.kdxdata"), day);
    put(&format!("{recent}.kdxpart"), day);
    put("README.txt", 30 * day);

    // Sweeping off: nothing is removed.
    let (client, _e) = ts.connect_client_with(dd.path(), |c| c.stale_partial_age = None).await;
    drop(client);
    assert_eq!(names(&transfers).len(), 5);

    // The default (7 days) removes only the stale partial.
    let (_client, _e) = ts.connect_client_in(dd.path()).await;
    assert_eq!(
        names(&transfers),
        vec![
            "README.txt".to_string(),
            format!("{recent}.kdxdata"),
            format!("{recent}.kdxpart"),
        ]
    );

    ts.stop();
}

/// A destination on another filesystem than the data dir (a USB stick, a
/// network share): the rename fails with EXDEV and the verified file is
/// copied over instead. Runs where the machine has a second filesystem
/// (tmpfs on /dev/shm) to try it with.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn download_to_another_filesystem_is_copied_into_place() {
    use std::os::unix::fs::MetadataExt;
    let Ok(other_fs) = tempfile::tempdir_in("/dev/shm") else {
        eprintln!("no /dev/shm; skipping");
        return;
    };
    let ts = TestServer::start().await;
    ts.seed_account("user", "pw", 2).await;
    let (client, _events, dd) = logged_in(&ts).await;
    let dev = |p: &Path| std::fs::metadata(p).unwrap().dev();
    if dev(other_fs.path()) == dev(dd.path()) {
        eprintln!("/dev/shm shares the data dir's filesystem; skipping");
        return;
    }

    let src = tempfile::tempdir().unwrap();
    let up = src.path().join("grab.bin");
    let data = blob(32 * 1024 * 3 + 17);
    std::fs::write(&up, &data).unwrap();
    client.upload(up, "/").await.unwrap();

    let local = other_fs.path().join("grab.bin");
    client.download("/grab.bin", local.clone()).await.unwrap();
    assert_eq!(std::fs::read(&local).unwrap(), data);
    assert_eq!(names(other_fs.path()), vec!["grab.bin"], "no temp file left");
    assert!(names(&dd.path().join(TRANSFERS_DIR)).is_empty(), "partial removed");

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
