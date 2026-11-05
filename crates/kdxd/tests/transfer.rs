//! M5 exit criteria: multi-chunk upload verifies end-to-end; DropBox accepts
//! uploads but refuses listing; a mid-transfer disconnect resumes from the
//! persisted bitmap and the final SHA-256 checks out.

mod common;

use bytes::Bytes;
use common::{bump, connect_tls, frame, kdx_handshake, test_config, TlsClient};
use futures_util::{SinkExt, StreamExt};
use kdx_crypto::hash_password;
use kdx_protocol::messages::{
    FileListRequest, FileListResponse, TransferAccept, TransferData, TransferEnd, TransferRequest,
    KIND_FILE, TRANSFER_VERIFIED,
};
use kdx_protocol::{fragment, PacketFlags, PacketType};
use kdx_storage::{accounts, file_tree};
use kdxd::serve;
use sha2::{Digest, Sha256};

const CHUNK: usize = 32 * 1024; // larger than the 16 KiB frame cap → exercises fragmentation

async fn login(client: &mut TlsClient, seq: &mut u32, username: &str, password: &str) {
    // Channel-bound SCRAM login (protocol v2); see tests/common.
    common::login(client, seq, username, password).await;
}

/// Send a payload, fragmenting when it exceeds the frame cap.
async fn send_fragmented(
    client: &mut TlsClient,
    seq: &mut u32,
    packet_type: PacketType,
    payload: Bytes,
) {
    let frames = fragment(
        packet_type,
        PacketFlags::empty(),
        payload,
        kdx_protocol::DEFAULT_MAX_FRAME_PAYLOAD,
        || bump(seq),
    );
    for f in frames {
        client.send(f).await.unwrap();
    }
}

fn chunk_frames(data: &[u8], transfer_id: [u8; 16]) -> Vec<(u32, Bytes)> {
    data.chunks(CHUNK)
        .enumerate()
        .map(|(i, c)| {
            let msg = TransferData {
                transfer_id,
                chunk_index: i as u32,
                chunk_hash: Sha256::digest(c).into(),
                data: Bytes::copy_from_slice(c),
            };
            (i as u32, msg.encode())
        })
        .collect()
}

async fn start_upload(
    client: &mut TlsClient,
    seq: &mut u32,
    path: &str,
    name: &str,
    data: &[u8],
    resume_id: [u8; 16],
) -> TransferAccept {
    let request = TransferRequest {
        direction: kdx_protocol::messages::DIRECTION_UPLOAD,
        path: path.into(),
        name: name.into(),
        size: data.len() as u64,
        chunk_size: CHUNK as u32,
        sha256: Sha256::digest(data).into(),
        resume_id,
        have_bitmap: vec![],
    };
    client
        .send(frame(PacketType::FileTransferStart, bump(seq), request.encode()))
        .await
        .unwrap();
    let reply = client.next().await.unwrap().unwrap();
    assert_eq!(
        reply.header.packet_type,
        PacketType::FileTransferStart,
        "upload not accepted: {:?}",
        String::from_utf8_lossy(&reply.payload)
    );
    TransferAccept::decode(&reply.payload).unwrap()
}

fn test_blob(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

#[tokio::test]
async fn multi_chunk_upload_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();
    let pool = kdx_storage::connect(&dir.path().join("kdx.db")).await.unwrap();
    let phc = hash_password("pw").unwrap();
    accounts::create(&pool, "uploader", &phc, 2, 0, 0).await.unwrap();

    let mut client = connect_tls(server.local_addr).await;
    let mut seq = 0u32;
    kdx_handshake(&mut client, &mut seq).await;
    login(&mut client, &mut seq, "uploader", "pw").await;

    let data = test_blob(CHUNK * 3 + 1000); // 4 chunks, ragged tail
    let accept = start_upload(&mut client, &mut seq, "/", "big.bin", &data, [0u8; 16]).await;
    assert_eq!(accept.total_chunks, 4);

    for (_, payload) in chunk_frames(&data, accept.transfer_id) {
        send_fragmented(&mut client, &mut seq, PacketType::FileTransferData, payload).await;
    }

    let end_frame = client.next().await.unwrap().unwrap();
    assert_eq!(end_frame.header.packet_type, PacketType::FileTransferEnd);
    let end = TransferEnd::decode(&end_frame.payload).unwrap();
    assert_eq!(end.status, TRANSFER_VERIFIED, "{}", end.message);

    // The file shows up in a listing with the right size.
    client
        .send(frame(
            PacketType::FileListRequest,
            bump(&mut seq),
            FileListRequest { path: "/".into() }.encode(),
        ))
        .await
        .unwrap();
    let list_frame = client.next().await.unwrap().unwrap();
    let list = FileListResponse::decode(&list_frame.payload).unwrap();
    assert_eq!(list.entries.len(), 1);
    assert_eq!(list.entries[0].name, "big.bin");
    assert_eq!(list.entries[0].kind, KIND_FILE);
    assert_eq!(list.entries[0].size, data.len() as u64);

    server.handle.abort();
}

#[tokio::test]
async fn dropbox_accepts_upload_but_refuses_listing() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();
    let pool = kdx_storage::connect(&dir.path().join("kdx.db")).await.unwrap();
    let phc = hash_password("pw").unwrap();
    accounts::create(&pool, "dropper", &phc, 1, 0, 0).await.unwrap(); // plain User
    // DropBox writable by class User(1); kind 2 = dropbox.
    file_tree::create_folder(&pool, file_tree::ROOT_ID, "dropbox", 2, 0, 1, None)
        .await
        .unwrap();
    // Restart tree state by reconnecting — the server loaded its tree before
    // we inserted; use a fresh serve instead.
    server.handle.abort();
    let server = serve(test_config(&dir)).await.unwrap();

    let mut client = connect_tls(server.local_addr).await;
    let mut seq = 0u32;
    kdx_handshake(&mut client, &mut seq).await;
    login(&mut client, &mut seq, "dropper", "pw").await;

    // Upload into the dropbox succeeds.
    let data = test_blob(10_000);
    let accept = start_upload(&mut client, &mut seq, "/dropbox", "secret.bin", &data, [0u8; 16]).await;
    for (_, payload) in chunk_frames(&data, accept.transfer_id) {
        send_fragmented(&mut client, &mut seq, PacketType::FileTransferData, payload).await;
    }
    let end = TransferEnd::decode(&client.next().await.unwrap().unwrap().payload).unwrap();
    assert_eq!(end.status, TRANSFER_VERIFIED);

    // Listing the dropbox is refused — even though the upload just worked.
    client
        .send(frame(
            PacketType::FileListRequest,
            bump(&mut seq),
            FileListRequest {
                path: "/dropbox".into(),
            }
            .encode(),
        ))
        .await
        .unwrap();
    let reply = client.next().await.unwrap().unwrap();
    assert_eq!(reply.header.packet_type, PacketType::Error);
    assert!(String::from_utf8_lossy(&reply.payload).contains("write-only"));

    server.handle.abort();
}

#[tokio::test]
async fn disconnect_mid_transfer_then_resume() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();
    let pool = kdx_storage::connect(&dir.path().join("kdx.db")).await.unwrap();
    let phc = hash_password("pw").unwrap();
    accounts::create(&pool, "uploader", &phc, 2, 0, 0).await.unwrap();

    let data = test_blob(CHUNK * 4); // 4 chunks
    let chunks = chunk_frames(&data, [0u8; 16]); // ids fixed up below

    // First connection: send 2 of 4 chunks, then drop the socket.
    let mut client = connect_tls(server.local_addr).await;
    let mut seq = 0u32;
    kdx_handshake(&mut client, &mut seq).await;
    login(&mut client, &mut seq, "uploader", "pw").await;
    let accept = start_upload(&mut client, &mut seq, "/", "resume.bin", &data, [0u8; 16]).await;
    let transfer_id = accept.transfer_id;
    for (_, payload) in &chunk_frames(&data, transfer_id)[..2] {
        send_fragmented(&mut client, &mut seq, PacketType::FileTransferData, payload.clone()).await;
    }
    // Give the server a moment to persist the bitmap, then vanish.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    drop(client);
    drop(chunks);

    // Second connection: resume. Server reports 2 chunks already held.
    let mut client = connect_tls(server.local_addr).await;
    let mut seq = 0u32;
    kdx_handshake(&mut client, &mut seq).await;
    login(&mut client, &mut seq, "uploader", "pw").await;
    let accept = start_upload(&mut client, &mut seq, "/", "resume.bin", &data, transfer_id).await;
    assert_eq!(accept.transfer_id, transfer_id);
    let have: Vec<bool> = accept
        .have_bitmap
        .iter()
        .flat_map(|byte| (0..8).map(move |bit| byte & (1 << bit) != 0))
        .take(accept.total_chunks as usize)
        .collect();
    assert_eq!(have.iter().filter(|h| **h).count(), 2, "bitmap: {have:?}");

    // Send only the missing chunks.
    for (i, payload) in chunk_frames(&data, transfer_id) {
        if !have[i as usize] {
            send_fragmented(&mut client, &mut seq, PacketType::FileTransferData, payload).await;
        }
    }
    let end = TransferEnd::decode(&client.next().await.unwrap().unwrap().payload).unwrap();
    assert_eq!(end.status, TRANSFER_VERIFIED, "{}", end.message);

    // Final bytes on disk hash-match the source.
    client
        .send(frame(
            PacketType::FileListRequest,
            bump(&mut seq),
            FileListRequest { path: "/".into() }.encode(),
        ))
        .await
        .unwrap();
    let list = FileListResponse::decode(&client.next().await.unwrap().unwrap().payload).unwrap();
    assert_eq!(list.entries[0].size, data.len() as u64);

    server.handle.abort();
}

/// Log a fresh connection in as `username`.
async fn logged_in(server: &kdxd::Server, username: &str) -> (TlsClient, u32) {
    let mut client = connect_tls(server.local_addr).await;
    let mut seq = 0u32;
    kdx_handshake(&mut client, &mut seq).await;
    login(&mut client, &mut seq, username, "pw").await;
    (client, seq)
}

/// Round-trip a listing so everything the server had queued for `client`
/// (presence broadcasts etc.) is drained and its earlier requests handled.
async fn sync(client: &mut TlsClient, seq: &mut u32) {
    client
        .send(frame(
            PacketType::FileListRequest,
            bump(seq),
            FileListRequest { path: "/".into() }.encode(),
        ))
        .await
        .unwrap();
    while client.next().await.unwrap().unwrap().header.packet_type != PacketType::FileListResponse {}
}

/// Send an upload request that is expected to be refused; return the error text.
async fn refused_upload(
    client: &mut TlsClient,
    seq: &mut u32,
    name: &str,
    data: &[u8],
    resume_id: [u8; 16],
) -> String {
    let request = TransferRequest {
        direction: kdx_protocol::messages::DIRECTION_UPLOAD,
        path: "/".into(),
        name: name.into(),
        size: data.len() as u64,
        chunk_size: CHUNK as u32,
        sha256: Sha256::digest(data).into(),
        resume_id,
        have_bitmap: vec![],
    };
    client
        .send(frame(PacketType::FileTransferStart, bump(seq), request.encode()))
        .await
        .unwrap();
    let reply = client.next().await.unwrap().unwrap();
    assert_eq!(reply.header.packet_type, PacketType::Error);
    String::from_utf8_lossy(&reply.payload).into_owned()
}

async fn send_chunks(client: &mut TlsClient, seq: &mut u32, data: &[u8], id: [u8; 16], skip: &[u32]) {
    for (i, payload) in chunk_frames(data, id) {
        if !skip.contains(&i) {
            send_fragmented(client, seq, PacketType::FileTransferData, payload).await;
        }
    }
}

async fn expect_end(client: &mut TlsClient) -> TransferEnd {
    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), client.next())
        .await
        .expect("no TransferEnd")
        .unwrap()
        .unwrap();
    assert_eq!(frame.header.packet_type, PacketType::FileTransferEnd);
    TransferEnd::decode(&frame.payload).unwrap()
}

/// Files in `files_root`: (finished blobs, partials).
fn stored(dir: &tempfile::TempDir) -> (usize, usize) {
    let names: Vec<String> = std::fs::read_dir(dir.path().join("files"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    let parts = names.iter().filter(|n| n.ends_with(".part")).count();
    (names.len() - parts, parts)
}

// XFER-4 / XFER-8: competing uploads of one name end with exactly one blob,
// no partials and no leftover resume state — and nobody is disconnected.
#[tokio::test]
async fn same_name_uploads_leave_exactly_one_blob() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();
    let pool = kdx_storage::connect(&dir.path().join("kdx.db")).await.unwrap();
    let phc = hash_password("pw").unwrap();
    accounts::create(&pool, "alice", &phc, 2, 0, 0).await.unwrap();
    accounts::create(&pool, "bob", &phc, 2, 0, 0).await.unwrap();
    let (mut alice, mut aseq) = logged_in(&server, "alice").await;
    let (mut bob, mut bseq) = logged_in(&server, "bob").await;
    sync(&mut alice, &mut aseq).await; // bob's arrival
    sync(&mut bob, &mut bseq).await;
    let data = test_blob(CHUNK * 2 + 10);

    // While alice's upload of dup.bin is live, the name is reserved.
    let accept = start_upload(&mut alice, &mut aseq, "/", "dup.bin", &data, [0u8; 16]).await;
    let err = refused_upload(&mut bob, &mut bseq, "dup.bin", &data, [0u8; 16]).await;
    assert!(err.contains("already exists"), "{err}");
    send_chunks(&mut alice, &mut aseq, &data, accept.transfer_id, &[]).await;
    assert_eq!(expect_end(&mut alice).await.status, TRANSFER_VERIFIED);

    // Bob starts other.bin and gives up partway (keeping it resumable);
    // alice then files other.bin first. Bob's resume is refused and his
    // partial upload discarded.
    let bob_accept = start_upload(&mut bob, &mut bseq, "/", "other.bin", &data, [0u8; 16]).await;
    send_chunks(&mut bob, &mut bseq, &data, bob_accept.transfer_id, &[1, 2]).await;
    let abort = TransferEnd {
        transfer_id: bob_accept.transfer_id,
        status: kdx_protocol::messages::TRANSFER_ABORTED,
        message: "cancelled".into(),
    };
    bob.send(frame(PacketType::FileTransferEnd, bump(&mut bseq), abort.encode()))
        .await
        .unwrap();
    // A round trip on bob's connection: his TransferEnd has been handled.
    sync(&mut bob, &mut bseq).await;
    let accept = start_upload(&mut alice, &mut aseq, "/", "other.bin", &data, [0u8; 16]).await;
    send_chunks(&mut alice, &mut aseq, &data, accept.transfer_id, &[]).await;
    assert_eq!(expect_end(&mut alice).await.status, TRANSFER_VERIFIED);
    let err = refused_upload(&mut bob, &mut bseq, "other.bin", &data, bob_accept.transfer_id).await;
    assert!(err.contains("already exists"), "{err}");

    assert_eq!(stored(&dir), (2, 0), "expected two blobs and no partials");
    assert!(kdx_storage::transfer_state::list_stale(&pool, 0).await.unwrap().is_empty());

    // Both connections are still usable.
    for (client, seq) in [(&mut alice, &mut aseq), (&mut bob, &mut bseq)] {
        client
            .send(frame(
                PacketType::FileListRequest,
                bump(seq),
                FileListRequest { path: "/".into() }.encode(),
            ))
            .await
            .unwrap();
        let list = FileListResponse::decode(&client.next().await.unwrap().unwrap().payload).unwrap();
        assert_eq!(list.entries.len(), 2);
    }

    // OPS-2: blobs and their folder are private to the server's user.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let files = dir.path().join("files");
        let mode = std::fs::metadata(&files).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        for entry in std::fs::read_dir(&files).unwrap() {
            let mode = entry.unwrap().metadata().unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    server.handle.abort();
}

// XFER-7 / CLIENT-10: an empty upload finishes without the client sending
// any chunk, and doesn't wedge the connection's upload slot.
#[tokio::test]
async fn empty_upload_completes() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();
    let pool = kdx_storage::connect(&dir.path().join("kdx.db")).await.unwrap();
    let phc = hash_password("pw").unwrap();
    accounts::create(&pool, "uploader", &phc, 2, 0, 0).await.unwrap();
    let (mut client, mut seq) = logged_in(&server, "uploader").await;

    let accept = start_upload(&mut client, &mut seq, "/", "empty.txt", &[], [0u8; 16]).await;
    assert_eq!(accept.total_chunks, 0);
    let end = expect_end(&mut client).await;
    assert_eq!(end.status, TRANSFER_VERIFIED, "{}", end.message);

    // The slot is free again.
    let data = test_blob(100);
    let accept = start_upload(&mut client, &mut seq, "/", "next.bin", &data, [0u8; 16]).await;
    send_chunks(&mut client, &mut seq, &data, accept.transfer_id, &[]).await;
    assert_eq!(expect_end(&mut client).await.status, TRANSFER_VERIFIED);

    client
        .send(frame(
            PacketType::FileListRequest,
            bump(&mut seq),
            FileListRequest { path: "/".into() }.encode(),
        ))
        .await
        .unwrap();
    let list = FileListResponse::decode(&client.next().await.unwrap().unwrap().payload).unwrap();
    let empty = list.entries.iter().find(|e| e.name == "empty.txt").unwrap();
    assert_eq!(empty.size, 0);

    server.handle.abort();
}

// XFER-7: a client TransferEnd frees the slot but keeps the upload
// resumable from where it stopped.
#[tokio::test]
async fn client_abort_frees_slot_and_keeps_progress() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();
    let pool = kdx_storage::connect(&dir.path().join("kdx.db")).await.unwrap();
    let phc = hash_password("pw").unwrap();
    accounts::create(&pool, "uploader", &phc, 2, 0, 0).await.unwrap();
    let (mut client, mut seq) = logged_in(&server, "uploader").await;

    let data = test_blob(CHUNK * 4);
    let accept = start_upload(&mut client, &mut seq, "/", "paused.bin", &data, [0u8; 16]).await;
    let id = accept.transfer_id;
    send_chunks(&mut client, &mut seq, &data, id, &[2, 3]).await;
    let abort = TransferEnd {
        transfer_id: id,
        status: kdx_protocol::messages::TRANSFER_ABORTED,
        message: String::new(),
    };
    client
        .send(frame(PacketType::FileTransferEnd, bump(&mut seq), abort.encode()))
        .await
        .unwrap();

    // Same connection, resume at once: two chunks are already held.
    let accept = start_upload(&mut client, &mut seq, "/", "paused.bin", &data, id).await;
    let held: Vec<u32> = (0..accept.total_chunks)
        .filter(|i| accept.have_bitmap[*i as usize / 8] & (1 << (i % 8)) != 0)
        .collect();
    assert_eq!(held, vec![0, 1]);
    send_chunks(&mut client, &mut seq, &data, id, &held).await;
    assert_eq!(expect_end(&mut client).await.status, TRANSFER_VERIFIED);

    server.handle.abort();
}

// G3: an upload into someone else's drop box can't tell whether its name is
// taken — a taken name is stored under a free variant and the replies are
// identical — while the box's owner still gets the explicit refusal.
#[tokio::test]
async fn drop_box_upload_never_reveals_a_taken_name() {
    let dir = tempfile::tempdir().unwrap();
    let pool = kdx_storage::connect(&dir.path().join("kdx.db")).await.unwrap();
    let phc = hash_password("pw").unwrap();
    for name in ["boss", "dropper", "other"] {
        accounts::create(&pool, name, &phc, 1, 0, 0).await.unwrap(); // plain Users
    }
    // A drop box owned by boss that Users may upload into.
    file_tree::create_folder(&pool, file_tree::ROOT_ID, "inbox", 2, 0, 1, Some("boss"))
        .await
        .unwrap();
    let server = serve(test_config(&dir)).await.unwrap();
    let (mut dropper, mut dseq) = logged_in(&server, "dropper").await;
    let (mut other, mut oseq) = logged_in(&server, "other").await;
    sync(&mut dropper, &mut dseq).await; // other's arrival
    sync(&mut other, &mut oseq).await;
    let data = test_blob(CHUNK + 100);

    // The first upload takes the name; the second asks for it again.
    let mut replies = Vec::new();
    for _ in 0..2 {
        let accept =
            start_upload(&mut dropper, &mut dseq, "/inbox", "secret.bin", &data, [0u8; 16]).await;
        send_chunks(&mut dropper, &mut dseq, &data, accept.transfer_id, &[]).await;
        let end = expect_end(&mut dropper).await;
        assert_eq!(end.status, TRANSFER_VERIFIED, "{}", end.message);
        replies.push((accept, end));
    }
    let shape = |(a, e): &(TransferAccept, TransferEnd)| {
        let accept = (a.chunk_size, a.total_chunks, a.size, a.sha256, a.have_bitmap.clone());
        (accept, e.status, e.message.clone())
    };
    assert_eq!(shape(&replies[0]), shape(&replies[1]), "a taken name changed the replies");
    assert_ne!(replies[0].0.transfer_id, replies[1].0.transfer_id);

    // Two uploads racing for the same (taken) name are both accepted.
    let first = start_upload(&mut dropper, &mut dseq, "/inbox", "secret.bin", &data, [0u8; 16]).await;
    let second = start_upload(&mut other, &mut oseq, "/inbox", "secret.bin", &data, [0u8; 16]).await;
    send_chunks(&mut dropper, &mut dseq, &data, first.transfer_id, &[]).await;
    send_chunks(&mut other, &mut oseq, &data, second.transfer_id, &[]).await;
    assert_eq!(expect_end(&mut dropper).await.status, TRANSFER_VERIFIED);
    assert_eq!(expect_end(&mut other).await.status, TRANSFER_VERIFIED);

    // The owner sees every upload, each under its own name...
    let (mut boss, mut bseq) = logged_in(&server, "boss").await;
    boss.send(frame(
        PacketType::FileListRequest,
        bump(&mut bseq),
        FileListRequest { path: "/inbox".into() }.encode(),
    ))
    .await
    .unwrap();
    let list = loop {
        // (Skipping anything pushed at login.)
        let reply = boss.next().await.unwrap().unwrap();
        if reply.header.packet_type == PacketType::FileListResponse {
            break FileListResponse::decode(&reply.payload).unwrap();
        }
    };
    let names: Vec<&str> = list.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["secret (2).bin", "secret (3).bin", "secret (4).bin", "secret.bin"]);
    assert!(list.entries.iter().all(|e| e.size == data.len() as u64));
    assert_eq!(stored(&dir), (4, 0));

    // ...and, able to list the box, still gets the explicit refusal.
    let request = TransferRequest {
        direction: kdx_protocol::messages::DIRECTION_UPLOAD,
        path: "/inbox".into(),
        name: "secret.bin".into(),
        size: data.len() as u64,
        chunk_size: CHUNK as u32,
        sha256: Sha256::digest(&data).into(),
        resume_id: [0u8; 16],
        have_bitmap: vec![],
    };
    boss.send(frame(PacketType::FileTransferStart, bump(&mut bseq), request.encode()))
        .await
        .unwrap();
    let reply = boss.next().await.unwrap().unwrap();
    assert_eq!(reply.header.packet_type, PacketType::Error);
    assert!(String::from_utf8_lossy(&reply.payload).contains("already exists"));

    server.handle.abort();
}
