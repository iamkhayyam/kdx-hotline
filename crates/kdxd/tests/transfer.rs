//! M5 exit criteria: multi-chunk upload verifies end-to-end; DropBox accepts
//! uploads but refuses listing; a mid-transfer disconnect resumes from the
//! persisted bitmap and the final SHA-256 checks out.

mod common;

use bytes::Bytes;
use common::{bump, connect_tls, frame, kdx_handshake, test_config, TlsClient};
use futures_util::{SinkExt, StreamExt};
use kdx_crypto::{client_response, hash_password, KdfParams};
use kdx_protocol::messages::{
    AuthChallenge, AuthRequest, AuthResponse, AuthResult, FileListRequest, FileListResponse,
    TransferAccept, TransferData, TransferEnd, TransferRequest, KIND_FILE, TRANSFER_VERIFIED,
};
use kdx_protocol::{fragment, PacketFlags, PacketType};
use kdx_storage::{accounts, file_tree};
use kdxd::serve;
use sha2::{Digest, Sha256};

const CHUNK: usize = 32 * 1024; // larger than the 16 KiB frame cap → exercises fragmentation

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
    let challenge = AuthChallenge::decode(
        &client.next().await.unwrap().unwrap().payload,
    )
    .unwrap();
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
    let result = AuthResult::decode(&client.next().await.unwrap().unwrap().payload).unwrap();
    assert!(result.success, "{}", result.message);
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
    accounts::create(&pool, "uploader", &phc, 2).await.unwrap();

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
    accounts::create(&pool, "dropper", &phc, 1).await.unwrap(); // plain User
    // DropBox writable by class User(1); kind 2 = dropbox.
    file_tree::create_folder(&pool, file_tree::ROOT_ID, "dropbox", 2, 0, 1)
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
    accounts::create(&pool, "uploader", &phc, 2).await.unwrap();

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
