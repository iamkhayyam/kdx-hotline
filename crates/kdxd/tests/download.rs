//! S7 exit criteria. Multi-chunk download byte-identical to source, with
//! chunks larger than the frame cap so the server fragments them. Disconnect
//! mid-download then resume, transferring only the missing chunks. DropBox
//! download refused. Throttle caps the observed rate.

mod common;

use std::time::Instant;

use common::{bump, connect_tls, frame, kdx_handshake, test_config, TlsClient};
use futures_util::{SinkExt, StreamExt};
use kdx_crypto::{client_response, hash_password, KdfParams};
use kdx_protocol::messages::{
    AuthChallenge, AuthRequest, AuthResponse, AuthResult, TransferAccept, TransferData,
    TransferEnd, TransferRequest, DIRECTION_DOWNLOAD, DIRECTION_UPLOAD, TRANSFER_VERIFIED,
};
use kdx_protocol::{fragment, PacketFlags, PacketType, Reassembler};
use kdx_storage::accounts;
use kdxd::serve;
use sha2::{Digest, Sha256};

const CHUNK: usize = 32 * 1024; // > 16KB frame cap → server fragments each chunk

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
    let challenge =
        AuthChallenge::decode(&client.next().await.unwrap().unwrap().payload).unwrap();
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

async fn send_fragmented(
    client: &mut TlsClient,
    seq: &mut u32,
    packet_type: PacketType,
    payload: bytes::Bytes,
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

/// Upload a blob so there's something to download back.
async fn upload(client: &mut TlsClient, seq: &mut u32, path: &str, name: &str, data: &[u8]) {
    let request = TransferRequest {
        direction: DIRECTION_UPLOAD,
        path: path.into(),
        name: name.into(),
        size: data.len() as u64,
        chunk_size: CHUNK as u32,
        sha256: Sha256::digest(data).into(),
        resume_id: [0u8; 16],
        have_bitmap: vec![],
    };
    client
        .send(frame(PacketType::FileTransferStart, bump(seq), request.encode()))
        .await
        .unwrap();
    let accept = TransferAccept::decode(&client.next().await.unwrap().unwrap().payload).unwrap();
    for (i, chunk) in data.chunks(CHUNK).enumerate() {
        let msg = TransferData {
            transfer_id: accept.transfer_id,
            chunk_index: i as u32,
            chunk_hash: Sha256::digest(chunk).into(),
            data: bytes::Bytes::copy_from_slice(chunk),
        };
        send_fragmented(client, seq, PacketType::FileTransferData, msg.encode()).await;
    }
    let end = TransferEnd::decode(&client.next().await.unwrap().unwrap().payload).unwrap();
    assert_eq!(end.status, TRANSFER_VERIFIED, "upload failed: {}", end.message);
}

/// Ask to download `path`/`name`, supplying `have_bitmap` (empty = fresh).
async fn request_download(
    client: &mut TlsClient,
    seq: &mut u32,
    path: &str,
    name: &str,
    have_bitmap: Vec<u8>,
) -> TransferAccept {
    let request = TransferRequest {
        direction: DIRECTION_DOWNLOAD,
        path: path.into(),
        name: name.into(),
        size: 0,
        chunk_size: CHUNK as u32,
        sha256: [0u8; 32],
        resume_id: [0u8; 16],
        have_bitmap,
    };
    client
        .send(frame(PacketType::FileTransferStart, bump(seq), request.encode()))
        .await
        .unwrap();
    let reply = client.next().await.unwrap().unwrap();
    assert_eq!(
        reply.header.packet_type,
        PacketType::FileTransferStart,
        "download not accepted: {:?}",
        String::from_utf8_lossy(&reply.payload)
    );
    TransferAccept::decode(&reply.payload).unwrap()
}

/// Receive the download stream: reassemble fragmented TransferData frames,
/// verify each chunk hash, write into `buf` at the chunk offset, and record
/// which chunk indices arrived. Stops at TransferEnd.
async fn receive_download(
    client: &mut TlsClient,
    accept: &TransferAccept,
    buf: &mut [u8],
    received: &mut Vec<u32>,
    stop_after: Option<usize>,
) -> bool {
    let mut reasm = Reassembler::default();
    loop {
        let raw = client.next().await.unwrap().unwrap();
        let Some(frame) = reasm.push(raw, 4 * 1024 * 1024).unwrap() else {
            continue; // mid-fragment
        };
        match frame.header.packet_type {
            PacketType::FileTransferData => {
                let data = TransferData::decode(&frame.payload).unwrap();
                assert_eq!(data.transfer_id, accept.transfer_id);
                let actual: [u8; 32] = Sha256::digest(&data.data).into();
                assert_eq!(actual, data.chunk_hash, "chunk {} hash", data.chunk_index);
                let offset = data.chunk_index as usize * accept.chunk_size as usize;
                buf[offset..offset + data.data.len()].copy_from_slice(&data.data);
                received.push(data.chunk_index);
                if let Some(n) = stop_after {
                    if received.len() >= n {
                        return false; // simulate mid-download disconnect
                    }
                }
            }
            PacketType::FileTransferEnd => {
                let end = TransferEnd::decode(&frame.payload).unwrap();
                assert_eq!(end.status, TRANSFER_VERIFIED, "{}", end.message);
                return true;
            }
            other => panic!("unexpected packet during download: {other:?}"),
        }
    }
}

fn bitmap_from(indices: &[u32], total: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; (total as usize).div_ceil(8)];
    for &i in indices {
        bytes[i as usize / 8] |= 1 << (i % 8);
    }
    bytes
}

fn test_blob(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 37 % 251) as u8).collect()
}

#[tokio::test]
async fn download_is_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();
    let pool = kdx_storage::connect(&dir.path().join("kdx.db")).await.unwrap();
    let phc = hash_password("pw").unwrap();
    accounts::create(&pool, "user", &phc, 2).await.unwrap();

    let mut client = connect_tls(server.local_addr).await;
    let mut seq = 0u32;
    kdx_handshake(&mut client, &mut seq).await;
    login(&mut client, &mut seq, "user", "pw").await;

    let data = test_blob(CHUNK * 3 + 777);
    upload(&mut client, &mut seq, "/", "grab.bin", &data).await;

    let accept = request_download(&mut client, &mut seq, "/", "grab.bin", vec![]).await;
    assert_eq!(accept.size, data.len() as u64);
    assert_eq!(accept.sha256, <[u8; 32]>::from(Sha256::digest(&data)));

    let mut buf = vec![0u8; data.len()];
    let mut received = Vec::new();
    let done = receive_download(&mut client, &accept, &mut buf, &mut received, None).await;
    assert!(done);
    assert_eq!(buf, data, "downloaded bytes differ from source");
    assert_eq!(received.len(), accept.total_chunks as usize);

    server.handle.abort();
}

#[tokio::test]
async fn download_resumes_after_disconnect() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(test_config(&dir)).await.unwrap();
    let pool = kdx_storage::connect(&dir.path().join("kdx.db")).await.unwrap();
    let phc = hash_password("pw").unwrap();
    accounts::create(&pool, "user", &phc, 2).await.unwrap();

    let data = test_blob(CHUNK * 4);

    // Seed the file via one connection.
    let mut client = connect_tls(server.local_addr).await;
    let mut seq = 0u32;
    kdx_handshake(&mut client, &mut seq).await;
    login(&mut client, &mut seq, "user", "pw").await;
    upload(&mut client, &mut seq, "/", "resume.bin", &data).await;

    // First download: grab 2 of 4 chunks then bail.
    let accept = request_download(&mut client, &mut seq, "/", "resume.bin", vec![]).await;
    let mut buf = vec![0u8; data.len()];
    let mut have = Vec::new();
    let done = receive_download(&mut client, &accept, &mut buf, &mut have, Some(2)).await;
    assert!(!done);
    assert_eq!(have.len(), 2);
    drop(client);

    // Reconnect and resume with our partial bitmap: server sends only the rest.
    let mut client = connect_tls(server.local_addr).await;
    let mut seq = 0u32;
    kdx_handshake(&mut client, &mut seq).await;
    login(&mut client, &mut seq, "user", "pw").await;
    let resume_bitmap = bitmap_from(&have, accept.total_chunks);
    let accept2 = request_download(&mut client, &mut seq, "/", "resume.bin", resume_bitmap).await;

    let mut fresh = Vec::new();
    let done = receive_download(&mut client, &accept2, &mut buf, &mut fresh, None).await;
    assert!(done);
    // Only the 2 missing chunks should have been streamed this time.
    assert_eq!(fresh.len(), 2, "server re-sent already-held chunks: {fresh:?}");
    assert!(fresh.iter().all(|i| !have.contains(i)));
    assert_eq!(buf, data);

    server.handle.abort();
}

#[tokio::test]
async fn dropbox_download_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    // Seed a dropbox and a file inside it before the server loads its tree.
    let pool = kdx_storage::connect(&dir.path().join("kdx.db")).await.unwrap();
    let phc = hash_password("pw").unwrap();
    accounts::create(&pool, "user", &phc, 2).await.unwrap();
    kdx_storage::file_tree::create_folder(&pool, kdx_storage::file_tree::ROOT_ID, "drop", 2, 0, 1, None)
        .await
        .unwrap();
    let server = serve(test_config(&dir)).await.unwrap();

    let mut client = connect_tls(server.local_addr).await;
    let mut seq = 0u32;
    kdx_handshake(&mut client, &mut seq).await;
    login(&mut client, &mut seq, "user", "pw").await;

    // Upload into the dropbox (allowed), then try to download it (refused).
    let data = test_blob(5000);
    upload(&mut client, &mut seq, "/drop", "secret.bin", &data).await;

    let request = TransferRequest {
        direction: DIRECTION_DOWNLOAD,
        path: "/drop".into(),
        name: "secret.bin".into(),
        size: 0,
        chunk_size: CHUNK as u32,
        sha256: [0u8; 32],
        resume_id: [0u8; 16],
        have_bitmap: vec![],
    };
    client
        .send(frame(PacketType::FileTransferStart, bump(&mut seq), request.encode()))
        .await
        .unwrap();
    let reply = client.next().await.unwrap().unwrap();
    assert_eq!(reply.header.packet_type, PacketType::Error);
    assert!(String::from_utf8_lossy(&reply.payload).contains("write-only"));

    server.handle.abort();
}

#[tokio::test]
async fn download_throttle_caps_rate() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(&dir);
    config.max_download_bytes_per_sec = 128 * 1024; // 128 KiB/s
    let server = serve(config).await.unwrap();
    let pool = kdx_storage::connect(&dir.path().join("kdx.db")).await.unwrap();
    let phc = hash_password("pw").unwrap();
    accounts::create(&pool, "user", &phc, 2).await.unwrap();

    let mut client = connect_tls(server.local_addr).await;
    let mut seq = 0u32;
    kdx_handshake(&mut client, &mut seq).await;
    login(&mut client, &mut seq, "user", "pw").await;

    let data = test_blob(256 * 1024); // 256 KiB → ~1s past the burst at 128 KiB/s
    upload(&mut client, &mut seq, "/", "slow.bin", &data).await;

    let accept = request_download(&mut client, &mut seq, "/", "slow.bin", vec![]).await;
    let mut buf = vec![0u8; data.len()];
    let mut received = Vec::new();
    let start = Instant::now();
    receive_download(&mut client, &accept, &mut buf, &mut received, None).await;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_millis(700),
        "download not throttled: {elapsed:?}"
    );
    assert_eq!(buf, data);

    server.handle.abort();
}
