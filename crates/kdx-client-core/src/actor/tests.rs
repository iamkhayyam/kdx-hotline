//! Actor-level tests against a scripted fake server over an in-memory
//! duplex pipe (no TLS). Tests that only exercise timers run with paused
//! time; tests that touch the filesystem run in real time (the blocking
//! pool would otherwise let a paused clock leap to the next timer).

use std::path::Path;

use kdx_protocol::messages::{FileEntry, KIND_FILE};
use kdx_protocol::DEFAULT_MAX_FRAME_PAYLOAD;
use tokio::io::DuplexStream;
use tokio::time::timeout;

use super::*;

const STEP: Duration = Duration::from_secs(5);

struct Harness {
    client: ClientHandle,
    events: mpsc::Receiver<Event>,
    srv: Framed<DuplexStream, KdxCodec>,
    reasm: Reassembler,
    seq: u32,
}

impl Harness {
    fn new() -> Self {
        Self::with_pipe(1024 * 1024)
    }

    fn with_pipe(buffer: usize) -> Self {
        let (client_io, server_io) = tokio::io::duplex(buffer);
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (ev_tx, ev_rx) = mpsc::channel(256);
        let opts = ActorOptions {
            server_id: "test.example:10700".into(),
            ..ActorOptions::default()
        };
        let actor = Actor::new(Framed::new(client_io, KdxCodec::default()), cmd_rx, ev_tx)
            .with_options(opts);
        let client = actor.spawn(cmd_tx);
        Harness {
            client,
            events: ev_rx,
            srv: Framed::new(server_io, KdxCodec::default()),
            reasm: Reassembler::default(),
            seq: 0,
        }
    }

    /// The next complete (reassembled) frame from the client.
    async fn recv(&mut self) -> KdxFrame {
        loop {
            let frame = timeout(STEP, self.srv.next())
                .await
                .expect("timed out waiting for a client frame")
                .expect("client closed the connection")
                .expect("bad client frame");
            if let Some(full) = self.reasm.push(frame, 8 * 1024 * 1024).unwrap() {
                return full;
            }
        }
    }

    /// The next non-Ping frame; Pings are answered as an honest server
    /// would, in order.
    async fn recv_request(&mut self) -> KdxFrame {
        loop {
            let frame = self.recv().await;
            if frame.header.packet_type == PacketType::Ping {
                self.send(PacketType::Pong, frame.payload).await;
                continue;
            }
            return frame;
        }
    }

    /// Expect the next non-Ping frame to be `ty`.
    async fn expect(&mut self, ty: PacketType) -> KdxFrame {
        let frame = self.recv_request().await;
        assert_eq!(frame.header.packet_type, ty, "unexpected client frame");
        frame
    }

    /// Expect a barrier Ping next and return its payload (unanswered).
    async fn expect_ping(&mut self) -> Bytes {
        let frame = self.recv().await;
        assert_eq!(frame.header.packet_type, PacketType::Ping);
        frame.payload
    }

    async fn send(&mut self, ty: PacketType, payload: Bytes) {
        let mut seq = self.seq;
        let frames = kdx_protocol::fragment(
            ty,
            PacketFlags::empty(),
            payload,
            DEFAULT_MAX_FRAME_PAYLOAD,
            || {
                let s = seq;
                seq = seq.wrapping_add(1);
                s
            },
        );
        self.seq = seq;
        for frame in frames {
            self.srv.send(frame).await.unwrap();
        }
    }

    async fn error(&mut self, text: &str) {
        self.send(PacketType::Error, Bytes::copy_from_slice(text.as_bytes()))
            .await;
    }

    async fn next_event(&mut self) -> Event {
        timeout(STEP, self.events.recv())
            .await
            .expect("timed out waiting for an event")
            .expect("event channel closed")
    }

    /// Wait for the terminal Disconnected event, skipping others.
    async fn disconnected(&mut self) -> String {
        loop {
            if let Event::Disconnected { reason } = self.next_event().await {
                return reason;
            }
        }
    }

    /// Prove the session still works: a listing round-trips.
    async fn assert_alive(&mut self) {
        let client = self.client.clone();
        let call = tokio::spawn(async move { client.list_files("/").await });
        let req = self.expect(PacketType::FileListRequest).await;
        let path = FileListRequest::decode(&req.payload).unwrap().path;
        self.send(PacketType::FileListResponse, listing(&path)).await;
        let listing = timeout(STEP, call).await.unwrap().unwrap().unwrap();
        assert_eq!(listing.path, path);
    }
}

fn listing(path: &str) -> Bytes {
    FileListResponse {
        path: path.to_string(),
        entries: vec![FileEntry {
            name: "a".into(),
            kind: KIND_FILE,
            size: 1,
        }],
    }
    .encode()
}

fn file_info(name: &str) -> Bytes {
    FileInfoResponse {
        name: name.into(),
        kind: KIND_FILE,
        size: 1,
        sha256: None,
        min_read_class: 0,
        min_write_class: 0,
        owner: None,
    }
    .encode()
}

fn accept(id: u8, chunk_size: u32, total: u32, size: u64, sha: [u8; 32], bitmap: Vec<u8>) -> Bytes {
    TransferAccept {
        transfer_id: [id; 16],
        chunk_size,
        total_chunks: total,
        size,
        sha256: sha,
        have_bitmap: bitmap,
    }
    .encode()
}

fn chunk(id: u8, index: u32, data: &[u8]) -> Bytes {
    TransferData {
        transfer_id: [id; 16],
        chunk_index: index,
        chunk_hash: Sha256::digest(data).into(),
        data: Bytes::copy_from_slice(data),
    }
    .encode()
}

fn end(id: u8, status: u8) -> Bytes {
    TransferEnd {
        transfer_id: [id; 16],
        status,
        message: if status == TRANSFER_VERIFIED { "verified" } else { "failed" }.into(),
    }
    .encode()
}

fn blob(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Every file in `dir` (to prove nothing was created).
fn files_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// ---- error correlation (CLIENT-8) ---------------------------------------

#[tokio::test]
async fn get_file_info_error_fails_only_that_call_and_the_next_one_lines_up() {
    let mut h = Harness::new();
    let client = h.client.clone();
    let missing = tokio::spawn(async move { client.get_file_info("/nope").await });
    h.expect(PacketType::FileInfoRequest).await;
    h.error("not found").await;
    let err = timeout(STEP, missing).await.unwrap().unwrap().unwrap_err();
    assert!(matches!(err, ClientError::Server(ref t) if t == "not found"), "{err:?}");

    let client = h.client.clone();
    let found = tokio::spawn(async move { client.get_file_info("/a").await });
    h.expect(PacketType::FileInfoRequest).await;
    h.send(PacketType::FileInfoResponse, file_info("a")).await;
    let info = timeout(STEP, found).await.unwrap().unwrap().unwrap();
    assert_eq!(info.name, "a");
}

#[tokio::test]
async fn an_error_fails_only_the_oldest_outstanding_request() {
    let mut h = Harness::new();
    let (c1, c2) = (h.client.clone(), h.client.clone());
    let list = tokio::spawn(async move { c1.list_files("/secret").await });
    h.expect(PacketType::FileListRequest).await;
    let info = tokio::spawn(async move { c2.get_file_info("/a").await });
    h.expect(PacketType::FileInfoRequest).await;

    h.error("missing FILE_LIST privilege").await;
    h.send(PacketType::FileInfoResponse, file_info("a")).await;
    assert!(timeout(STEP, list).await.unwrap().unwrap().is_err());
    assert_eq!(timeout(STEP, info).await.unwrap().unwrap().unwrap().name, "a");
}

#[tokio::test]
async fn a_fire_and_forget_error_does_not_fail_a_later_request() {
    let mut h = Harness::new();
    // PrivateSend has no reply; the server answers an offline recipient
    // with an Error — which must not be taken as the listing's answer.
    h.client.send_private("ghost", "hi").await.unwrap();
    let client = h.client.clone();
    let list = tokio::spawn(async move { client.list_files("/").await });

    h.expect(PacketType::PrivateSend).await;
    let token = h.expect_ping().await;
    h.expect(PacketType::FileListRequest).await;
    h.error("ghost is not online").await;
    h.send(PacketType::Pong, token).await;
    h.send(PacketType::FileListResponse, listing("/")).await;

    let listing = timeout(STEP, list).await.unwrap().unwrap().unwrap();
    assert_eq!(listing.path, "/");
    // The refusal still surfaces as an event.
    loop {
        if let Event::ServerError { text } = h.next_event().await {
            assert_eq!(text, "ghost is not online");
            break;
        }
    }
}

#[tokio::test]
async fn user_list_and_server_list_errors_are_delivered() {
    let mut h = Harness::new();
    let (c1, c2) = (h.client.clone(), h.client.clone());
    let users = tokio::spawn(async move { c1.list_users().await });
    h.expect(PacketType::PresenceListRequest).await;
    h.error("nope").await;
    assert!(timeout(STEP, users).await.unwrap().unwrap().is_err());
    let servers = tokio::spawn(async move { c2.list_servers("").await });
    h.expect(PacketType::TrackerListRequest).await;
    h.error("nope").await;
    assert!(timeout(STEP, servers).await.unwrap().unwrap().is_err());
    h.assert_alive().await;
}

#[tokio::test]
async fn ban_and_newsgroup_admin_replies_correlate_in_order() {
    let mut h = Harness::new();
    let (c1, c2, c3) = (h.client.clone(), h.client.clone(), h.client.clone());

    let remove = tokio::spawn(async move { c1.remove_ban("lamer").await });
    let req = h.expect(PacketType::BanRemove).await;
    assert_eq!(BanRemove::decode(&req.payload).unwrap().username, "lamer");
    let group = Uuid::from_bytes([3; 16]).to_string();
    let delete = tokio::spawn(async move { c2.delete_newsgroup(&group).await });
    let req = h.expect(PacketType::NewsgroupDelete).await;
    assert_eq!(NewsgroupDelete::decode(&req.payload).unwrap().id, [3; 16]);

    // The Error answers the older request (the unban) only.
    h.error("lamer is not banned").await;
    let groups = NewsgroupListResponse { groups: vec![] };
    h.send(PacketType::NewsgroupListResponse, groups.encode()).await;
    match timeout(STEP, remove).await.unwrap().unwrap() {
        Err(ClientError::Server(text)) => assert_eq!(text, "lamer is not banned"),
        other => panic!("expected the server's refusal, got {other:?}"),
    }
    assert!(timeout(STEP, delete).await.unwrap().unwrap().unwrap().is_empty());

    // A malformed id never reaches the wire (the listing below is next).
    let bad = h.client.update_newsgroup("not-a-uuid", "x", "", 0, 0).await;
    assert!(matches!(bad, Err(ClientError::InvalidInput(_))), "{bad:?}");
    let list = tokio::spawn(async move { c3.list_bans().await });
    h.expect(PacketType::BanListRequest).await;
    let reply = BanListResponse {
        total: 9,
        bans: vec![kdx_protocol::messages::BanEntry {
            username: "zero".into(),
            until: 1_900_000_000,
            reason: "flood".into(),
            banned_by: "mod".into(),
            banned_by_class: 2,
        }],
    };
    h.send(PacketType::BanListResponse, reply.encode()).await;
    let list = timeout(STEP, list).await.unwrap().unwrap().unwrap();
    assert_eq!((list.total, list.bans[0].username.as_str(), list.bans[0].banned_by_class), (9, "zero", 2));
    h.assert_alive().await;
}

#[tokio::test]
async fn a_reply_of_the_wrong_type_closes_the_connection() {
    let mut h = Harness::new();
    let client = h.client.clone();
    let info = tokio::spawn(async move { client.get_file_info("/a").await });
    h.expect(PacketType::FileInfoRequest).await;
    h.send(PacketType::FileListResponse, listing("/")).await;
    assert!(timeout(STEP, info).await.unwrap().unwrap().is_err());
    assert!(h.disconnected().await.contains("protocol"));
}

// ---- invitations (UI-2) ---------------------------------------------------

#[tokio::test]
async fn invite_to_chat_returns_the_private_room_and_reports_refusals() {
    let mut h = Harness::new();
    let user_list = |room: &str| {
        ChatUserList {
            room: room.into(),
            users: vec!["alice".into()],
        }
        .encode()
    };

    // A refusal after the server already created (and dropped) a room: the
    // stray member list must not be taken for the next invitation's room.
    let client = h.client.clone();
    let first = tokio::spawn(async move { client.invite_to_chat("ghost").await });
    h.expect(PacketType::ChatInvite).await;
    let token = h.expect_ping().await;
    h.error("ghost is not online").await;
    h.send(PacketType::ChatUserList, user_list("priv-stray")).await;
    h.send(PacketType::Pong, token).await;
    let err = timeout(STEP, first).await.unwrap().unwrap().unwrap_err();
    assert!(matches!(err, ClientError::Server(_)), "{err:?}");

    let client = h.client.clone();
    let second = tokio::spawn(async move { client.invite_to_chat("bob").await });
    h.expect(PacketType::ChatInvite).await;
    let token = h.expect_ping().await;
    h.send(PacketType::Info, Bytes::from_static(b"invited bob")).await;
    h.send(PacketType::ChatUserList, user_list("priv-real")).await;
    h.send(PacketType::Pong, token).await;
    assert_eq!(timeout(STEP, second).await.unwrap().unwrap().unwrap(), "priv-real");

    // A room we joined ourselves is never mistaken for an invite's room.
    // (The join resolves once its barrier comes back.)
    let client = h.client.clone();
    let join = tokio::spawn(async move { client.join("priv-joined").await });
    h.expect(PacketType::ChatJoin).await;
    h.send(PacketType::ChatUserList, user_list("priv-joined")).await;
    let token = h.expect_ping().await;
    h.send(PacketType::Pong, token).await;
    timeout(STEP, join).await.unwrap().unwrap().unwrap();
    let client = h.client.clone();
    let third = tokio::spawn(async move { client.invite_to_chat("carol").await });
    h.expect(PacketType::ChatInvite).await;
    let token = h.expect_ping().await;
    h.send(PacketType::Pong, token).await;
    h.send(PacketType::ChatUserList, user_list("priv-third")).await;
    assert_eq!(timeout(STEP, third).await.unwrap().unwrap().unwrap(), "priv-third");
}

// ---- joins (C-2) ------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn join_resolves_only_once_the_server_has_answered() {
    let mut h = Harness::new();
    let user_list = |room: &str| {
        ChatUserList {
            room: room.into(),
            users: vec!["bob".into()],
        }
        .encode()
    };

    // Refused (e.g. a private room that no longer exists): the caller gets
    // the server's reason, not a premature Ok.
    let client = h.client.clone();
    let refused = tokio::spawn(async move { client.join("priv-gone").await });
    h.expect(PacketType::ChatJoin).await;
    let token = h.expect_ping().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!refused.is_finished(), "join resolved before the server answered");
    h.error("you were not invited to that room").await;
    h.send(PacketType::Pong, token).await;
    let err = timeout(STEP, refused).await.unwrap().unwrap().unwrap_err();
    assert!(
        matches!(err, ClientError::Server(ref t) if t == "you were not invited to that room"),
        "{err:?}"
    );
    // Still surfaced as an event, as before.
    loop {
        if let Event::ServerError { text } = h.next_event().await {
            assert_eq!(text, "you were not invited to that room");
            break;
        }
    }

    // Admitted: Ok once the barrier comes back.
    let client = h.client.clone();
    let admitted = tokio::spawn(async move { client.join("lobby").await });
    h.expect(PacketType::ChatJoin).await;
    let token = h.expect_ping().await;
    h.send(PacketType::ChatUserList, user_list("lobby")).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!admitted.is_finished());
    h.send(PacketType::Pong, token).await;
    timeout(STEP, admitted).await.unwrap().unwrap().unwrap();

    // The refused room was not remembered as one of ours (a later invite's
    // room list is still recognised; only a joined room is excluded).
    let client = h.client.clone();
    let invite = tokio::spawn(async move { client.invite_to_chat("bob").await });
    h.expect(PacketType::ChatInvite).await;
    let token = h.expect_ping().await;
    h.send(PacketType::ChatUserList, user_list("priv-gone")).await;
    h.send(PacketType::Pong, token).await;
    assert_eq!(timeout(STEP, invite).await.unwrap().unwrap().unwrap(), "priv-gone");
    h.assert_alive().await;
}

#[tokio::test]
async fn a_join_cut_off_by_a_disconnect_fails() {
    let mut h = Harness::new();
    let client = h.client.clone();
    let join = tokio::spawn(async move { client.join("lobby").await });
    h.expect(PacketType::ChatJoin).await;
    h.expect_ping().await;
    h.client.disconnect().await;
    let result = timeout(STEP, join).await.unwrap().unwrap();
    assert!(matches!(result, Err(ClientError::Disconnected)), "{result:?}");
}

// ---- timeouts and liveness (CLIENT-7) -------------------------------------

#[tokio::test(start_paused = true)]
async fn an_unanswered_request_times_out_and_its_late_reply_is_discarded() {
    let mut h = Harness::new();
    let client = h.client.clone();
    let mut call = tokio::spawn(async move { client.list_files("/slow").await });
    h.expect(PacketType::FileListRequest).await;
    // Never reply (an in-order server can't answer later pings either).
    let mut pings = Vec::new();
    let result = loop {
        tokio::select! {
            r = &mut call => break r.unwrap(),
            frame = h.srv.next() => {
                let frame = frame.unwrap().unwrap();
                assert_eq!(frame.header.packet_type, PacketType::Ping);
                pings.push(frame.payload);
            }
        }
    };
    assert!(matches!(result, Err(ClientError::Timeout(_))), "{result:?}");
    // The late reply is absorbed by the abandoned request; the next one
    // lines up with its own answer.
    h.send(PacketType::FileListResponse, listing("/slow")).await;
    for token in pings {
        h.send(PacketType::Pong, token).await;
    }
    h.assert_alive().await;
}

#[tokio::test(start_paused = true)]
async fn a_silent_server_is_declared_dead() {
    let mut h = Harness::new();
    // Read (and ignore) whatever the client sends; never answer.
    let reason = loop {
        tokio::select! {
            ev = h.events.recv() => {
                if let Some(Event::Disconnected { reason }) = ev {
                    break reason;
                }
            }
            _ = h.srv.next() => {}
        }
    };
    assert!(reason.contains("stopped responding"), "{reason}");
}

#[tokio::test(start_paused = true)]
async fn login_waits_are_bounded() {
    let mut h = Harness::new();
    let client = h.client.clone();
    let login = tokio::spawn(async move { client.login("alice", "pw").await });
    h.expect(PacketType::AuthRequest).await;
    let result = timeout(Duration::from_secs(120), login).await.unwrap().unwrap();
    assert!(result.is_err(), "{result:?}");
}

#[tokio::test]
async fn disconnect_gets_through_while_an_upload_is_stuck_writing() {
    // A small pipe and a server that stops reading after the accept: the
    // actor ends up blocked writing chunks.
    let mut h = Harness::with_pipe(64 * 1024);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.bin");
    std::fs::write(&path, blob(2 * 1024 * 1024)).unwrap();

    let client = h.client.clone();
    let upload = tokio::spawn(async move { client.upload(path, "/").await });
    let req = h.expect(PacketType::FileTransferStart).await;
    let req = TransferRequest::decode(&req.payload).unwrap();
    let total = total_chunks(req.size, req.chunk_size);
    h.send(
        PacketType::FileTransferStart,
        accept(1, req.chunk_size, total, req.size, req.sha256, vec![]),
    )
    .await;
    // Stop reading; let the client fill the pipe.
    tokio::time::sleep(Duration::from_millis(200)).await;

    h.client.disconnect().await;
    let reason = timeout(STEP, h.disconnected()).await.unwrap();
    assert_eq!(reason, "disconnected");
    assert!(timeout(STEP, upload).await.unwrap().unwrap().is_err());
}

#[tokio::test]
async fn commands_are_serviced_during_an_upload() {
    let mut h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.bin");
    // Bigger than the in-flight window, so the upload pauses for acks.
    std::fs::write(&path, blob(6 * 1024 * 1024)).unwrap();

    let client = h.client.clone();
    let upload = tokio::spawn(async move { client.upload(path, "/").await });
    let req = h.expect(PacketType::FileTransferStart).await;
    let req = TransferRequest::decode(&req.payload).unwrap();
    let total = total_chunks(req.size, req.chunk_size);
    h.send(
        PacketType::FileTransferStart,
        accept(2, req.chunk_size, total, req.size, req.sha256, vec![]),
    )
    .await;
    // Don't acknowledge anything yet; a chat line still goes out.
    let client = h.client.clone();
    let chat = tokio::spawn(async move { client.send_chat("lobby", 0, "still here").await });
    let mut pings = Vec::new();
    let mut chunks = 0u32;
    loop {
        let frame = h.recv().await;
        match frame.header.packet_type {
            PacketType::Ping => pings.push(frame.payload),
            PacketType::FileTransferData => chunks += 1,
            PacketType::ChatMessage => break,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(chunks < total, "chat waited for the whole upload");
    timeout(STEP, chat).await.unwrap().unwrap().unwrap();

    // Now behave: ack everything and finish.
    for token in pings {
        h.send(PacketType::Pong, token).await;
    }
    while chunks < total {
        let frame = h.recv_request().await;
        if frame.header.packet_type == PacketType::FileTransferData {
            chunks += 1;
        }
    }
    h.send(PacketType::FileTransferEnd, end(2, TRANSFER_VERIFIED)).await;
    // Keep answering the trailing barriers until the upload resolves.
    let mut upload = upload;
    loop {
        tokio::select! {
            r = &mut upload => { r.unwrap().unwrap(); break; }
            f = h.recv() => {
                if f.header.packet_type == PacketType::Ping {
                    h.send(PacketType::Pong, f.payload).await;
                }
            }
        }
    }
}

// ---- uploads (CLIENT-10 / CLIENT-11) --------------------------------------

#[tokio::test]
async fn empty_upload_completes_when_the_server_ends_it() {
    let mut h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".gitkeep");
    std::fs::write(&path, b"").unwrap();
    let client = h.client.clone();
    let upload = tokio::spawn(async move { client.upload(path, "/").await });
    let req = h.expect(PacketType::FileTransferStart).await;
    let req = TransferRequest::decode(&req.payload).unwrap();
    assert_eq!(req.size, 0);
    h.send(
        PacketType::FileTransferStart,
        accept(3, req.chunk_size, 0, 0, req.sha256, vec![]),
    )
    .await;
    h.send(PacketType::FileTransferEnd, end(3, TRANSFER_VERIFIED)).await;
    timeout(STEP, upload).await.unwrap().unwrap().unwrap();
    h.assert_alive().await;
}

#[cfg(unix)]
#[tokio::test]
async fn uploading_a_device_or_directory_fails_fast() {
    let h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    for path in [PathBuf::from("/dev/zero"), dir.path().to_path_buf()] {
        let result = timeout(Duration::from_secs(2), h.client.upload(path, "/"))
            .await
            .expect("must not hang");
        assert!(matches!(result, Err(ClientError::InvalidInput(_))), "{result:?}");
    }
}

#[tokio::test]
async fn a_file_changed_mid_upload_is_rejected() {
    let mut h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("growing.log");
    std::fs::write(&path, blob(6 * 1024 * 1024)).unwrap();
    let client = h.client.clone();
    let upload = tokio::spawn({
        let path = path.clone();
        async move { client.upload(path, "/").await }
    });
    let req = h.expect(PacketType::FileTransferStart).await;
    let req = TransferRequest::decode(&req.payload).unwrap();
    let total = total_chunks(req.size, req.chunk_size);
    h.send(
        PacketType::FileTransferStart,
        accept(4, req.chunk_size, total, req.size, req.sha256, vec![]),
    )
    .await;
    // Let the first window go out unacknowledged, then change the file.
    let mut pings = Vec::new();
    while pings.len() < 8 {
        let frame = h.recv().await;
        if frame.header.packet_type == PacketType::Ping {
            pings.push(frame.payload);
        }
    }
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"more")
        .unwrap();
    for token in pings {
        h.send(PacketType::Pong, token).await;
    }
    let mut upload = upload;
    let result = loop {
        tokio::select! {
            r = &mut upload => break r.unwrap(),
            f = h.recv() => {
                if f.header.packet_type == PacketType::Ping {
                    h.send(PacketType::Pong, f.payload).await;
                }
            }
        }
    };
    let err = result.unwrap_err();
    assert!(err.to_string().contains("changed"), "{err:?}");
}

// ---- downloads (CLIENT-4 / 5 / 6 / 9, UI-10) -------------------------------

/// Start a download into `dir/out.bin`, returning the call and the request.
async fn start_download(
    h: &mut Harness,
    dir: &Path,
    expected: Option<u64>,
) -> (JoinHandle<Result<(), ClientError>>, TransferRequest) {
    let client = h.client.clone();
    let local = dir.join("out.bin");
    let call = tokio::spawn(async move {
        match expected {
            Some(size) => client.download_expecting("/files/out.bin", local, size).await,
            None => client.download("/files/out.bin", local).await,
        }
    });
    let req = h.expect(PacketType::FileTransferStart).await;
    (call, TransferRequest::decode(&req.payload).unwrap())
}

#[tokio::test]
async fn hostile_download_accepts_are_rejected_without_creating_files() {
    let mut h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let cases: Vec<(&str, Option<u64>, Bytes)> = vec![
        // 512 MiB bitmap bomb.
        ("bitmap bomb", None, accept(9, 32768, u32::MAX, 1, [0; 32], vec![])),
        // Exabyte sparse file with nothing to send.
        ("exabyte", None, accept(9, 32768, 0, 1 << 60, [0; 32], vec![])),
        ("2^50", None, accept(9, 262144, 0, 1 << 50, [0; 32], vec![])),
        // Absurd chunk size.
        ("chunk size", None, accept(9, u32::MAX, 1, 1, [0; 32], vec![])),
        // Echoed bitmap longer than the chunk count.
        ("bitmap length", None, accept(9, 32768, 1, 10, [0; 32], vec![0; 64])),
        // Not the file the listing showed.
        ("size mismatch", Some(10), accept(9, 32768, 1, 11, [0; 32], vec![])),
    ];
    for (what, expected, frame) in cases {
        let (call, _) = start_download(&mut h, dir.path(), expected).await;
        h.send(PacketType::FileTransferStart, frame).await;
        let result = timeout(STEP, call).await.unwrap().unwrap();
        assert!(matches!(result, Err(ClientError::Transfer(_))), "{what}: {result:?}");
        assert!(files_in(dir.path()).is_empty(), "{what}: created {:?}", files_in(dir.path()));
        // The client tells the server it's abandoning the transfer.
        h.expect(PacketType::FileTransferEnd).await;
    }
    h.assert_alive().await;
}

#[tokio::test]
async fn transfer_end_before_accept_is_an_error_not_a_panic() {
    let mut h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let (call, _) = start_download(&mut h, dir.path(), None).await;
    h.send(PacketType::FileTransferEnd, end(5, TRANSFER_VERIFIED)).await;
    let result = timeout(STEP, call).await.unwrap().unwrap();
    assert!(matches!(result, Err(ClientError::Transfer(_))), "{result:?}");
    // The actor survived and the session still lines up.
    h.assert_alive().await;
    assert!(files_in(dir.path()).is_empty());
}

#[tokio::test]
async fn malformed_chunks_fail_the_download_without_writing_past_the_size() {
    let mut h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let data = blob(40_000); // 2 chunks at 32 KiB
    let (call, req) = start_download(&mut h, dir.path(), None).await;
    h.send(
        PacketType::FileTransferStart,
        accept(6, req.chunk_size, 2, data.len() as u64, sha(&data), vec![]),
    )
    .await;
    // Chunk 1 is the short tail; send it far too long.
    h.send(PacketType::FileTransferData, chunk(6, 1, &blob(100_000))).await;
    let result = timeout(STEP, call).await.unwrap().unwrap();
    assert!(matches!(result, Err(ClientError::Transfer(_))), "{result:?}");
    let data_file = dir.path().join("out.bin.kdxdata");
    let len = std::fs::metadata(&data_file).map(|m| m.len()).unwrap_or(0);
    assert!(len <= data.len() as u64, "wrote past the advertised size");
    assert!(!dir.path().join("out.bin").exists());
}

#[tokio::test]
async fn a_download_completes_with_throttled_capped_progress() {
    let mut h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let (call, req) = start_download(&mut h, dir.path(), None).await;
    assert_eq!(req.have_bitmap, Vec::<u8>::new(), "fresh download sends no bitmap");
    let chunk_size = req.chunk_size;
    let data = blob(chunk_size as usize * 200 + 7); // 201 chunks
    let total = total_chunks(data.len() as u64, chunk_size);
    h.send(
        PacketType::FileTransferStart,
        accept(7, chunk_size, total, data.len() as u64, sha(&data), vec![]),
    )
    .await;
    for (i, piece) in data.chunks(chunk_size as usize).enumerate() {
        h.send(PacketType::FileTransferData, chunk(7, i as u32, piece)).await;
    }
    h.send(PacketType::FileTransferEnd, end(7, TRANSFER_VERIFIED)).await;
    timeout(STEP, call).await.unwrap().unwrap().unwrap();
    assert_eq!(std::fs::read(dir.path().join("out.bin")).unwrap(), data);
    assert_eq!(files_in(dir.path()), vec!["out.bin".to_string()], "no sidecar or data file left");

    let mut progress = 0;
    let mut last_done = 0;
    while let Ok(ev) = h.events.try_recv() {
        if let Event::TransferProgress {
            done,
            total: t,
            bitmap,
            bitmap_bits,
            ..
        } = ev
        {
            progress += 1;
            last_done = done;
            assert_eq!(t, total);
            assert!(bitmap_bits <= 1024 && bitmap.len() <= 128);
        }
    }
    assert_eq!(last_done, total, "a final progress event reports completion");
    assert!(progress < total as usize / 2, "{progress} progress events for {total} chunks");
}

fn write_sidecar(dir: &Path, size: u64, sha256: [u8; 32], bitmap: Vec<u8>) {
    let local = dir.join("out.bin");
    Sidecar {
        server: "test.example:10700".into(),
        remote: "/files/out.bin".into(),
        transfer_id: [1; 16],
        size,
        chunk_size: 32768,
        sha256,
        bitmap,
    }
    .write(&local)
    .unwrap();
    std::fs::write(data_path_for(&local), vec![0xAA; size as usize]).unwrap();
}

#[tokio::test]
async fn a_stale_sidecar_for_a_changed_file_recovers_in_a_second_round() {
    let mut h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let data = blob(32768 * 3);
    // A sidecar from an older version of the file claims chunks 0 and 1.
    write_sidecar(dir.path(), data.len() as u64, [7; 32], vec![0b011]);

    let (call, req) = start_download(&mut h, dir.path(), None).await;
    assert_eq!(req.have_bitmap, vec![0b011], "resume is attempted");
    // Like today's server, trust the client's bitmap: echo it and send only
    // chunk 2 — but the file (hash) is different now.
    h.send(
        PacketType::FileTransferStart,
        accept(8, 32768, 3, data.len() as u64, sha(&data), vec![0b011]),
    )
    .await;
    h.send(PacketType::FileTransferData, chunk(8, 2, &data[65536..])).await;
    h.send(PacketType::FileTransferEnd, end(8, TRANSFER_VERIFIED)).await;

    // The client asks again for exactly what it lacks.
    let again = h.expect(PacketType::FileTransferStart).await;
    let again = TransferRequest::decode(&again.payload).unwrap();
    assert_eq!(again.have_bitmap, vec![0b100]);
    h.send(
        PacketType::FileTransferStart,
        accept(8, 32768, 3, data.len() as u64, sha(&data), vec![0b100]),
    )
    .await;
    h.send(PacketType::FileTransferData, chunk(8, 0, &data[..32768])).await;
    h.send(PacketType::FileTransferData, chunk(8, 1, &data[32768..65536])).await;
    h.send(PacketType::FileTransferEnd, end(8, TRANSFER_VERIFIED)).await;

    timeout(STEP, call).await.unwrap().unwrap().unwrap();
    assert_eq!(std::fs::read(dir.path().join("out.bin")).unwrap(), data);
    assert_eq!(files_in(dir.path()), vec!["out.bin".to_string()]);
}

#[tokio::test]
async fn a_sidecar_from_another_server_is_ignored() {
    let mut h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("out.bin");
    Sidecar {
        server: "elsewhere.example:10700".into(),
        remote: "/files/out.bin".into(),
        transfer_id: [1; 16],
        size: 10,
        chunk_size: 32768,
        sha256: [0; 32],
        bitmap: vec![1],
    }
    .write(&local)
    .unwrap();
    std::fs::write(data_path_for(&local), [0u8; 10]).unwrap();
    let (call, req) = start_download(&mut h, dir.path(), None).await;
    assert!(req.have_bitmap.is_empty());
    assert_eq!(req.resume_id, [0; 16]);
    h.error("not found").await;
    assert!(timeout(STEP, call).await.unwrap().unwrap().is_err());
}

#[tokio::test]
async fn a_whole_file_hash_mismatch_discards_the_partial_download() {
    let mut h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let data = blob(1000);
    let (call, req) = start_download(&mut h, dir.path(), None).await;
    // The server lies about the whole-file hash.
    h.send(
        PacketType::FileTransferStart,
        accept(10, req.chunk_size, 1, 1000, [3; 32], vec![]),
    )
    .await;
    h.send(PacketType::FileTransferData, chunk(10, 0, &data)).await;
    h.send(PacketType::FileTransferEnd, end(10, TRANSFER_VERIFIED)).await;
    let err = timeout(STEP, call).await.unwrap().unwrap().unwrap_err();
    assert!(err.to_string().contains("mismatch"), "{err:?}");
    assert!(files_in(dir.path()).is_empty(), "left {:?}", files_in(dir.path()));

    // The retry starts from scratch.
    let (_call, req) = start_download(&mut h, dir.path(), None).await;
    assert!(req.have_bitmap.is_empty());
}

#[tokio::test]
async fn a_cancelled_download_keeps_resume_state_and_resumes() {
    let mut h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let data = blob(32768 * 2);
    let (call, req) = start_download(&mut h, dir.path(), None).await;
    h.send(
        PacketType::FileTransferStart,
        accept(11, req.chunk_size, 2, data.len() as u64, sha(&data), vec![]),
    )
    .await;
    h.send(PacketType::FileTransferData, chunk(11, 0, &data[..32768])).await;
    h.assert_alive().await; // chunk 0 is processed
    assert!(h.client.cancel_transfer().await.unwrap());
    let err = timeout(STEP, call).await.unwrap().unwrap().unwrap_err();
    assert!(err.to_string().contains("cancelled"), "{err:?}");
    let sidecar = Sidecar::read(&dir.path().join("out.bin")).expect("resume state kept");
    assert_eq!(sidecar.bitmap, vec![0b01]);
    assert!(!h.client.cancel_transfer().await.unwrap());
    // The server is told the client abandoned the transfer.
    h.expect(PacketType::FileTransferEnd).await;

    // The resumed download only asks for what's missing.
    let (call, req) = start_download(&mut h, dir.path(), None).await;
    assert_eq!(req.have_bitmap, vec![0b01]);
    // The abandoned transfer's late end is not taken for this one's.
    h.send(PacketType::FileTransferEnd, end(11, TRANSFER_VERIFIED)).await;
    h.send(
        PacketType::FileTransferStart,
        accept(12, req.chunk_size, 2, data.len() as u64, sha(&data), vec![0b01]),
    )
    .await;
    h.send(PacketType::FileTransferData, chunk(12, 1, &data[32768..])).await;
    h.send(PacketType::FileTransferEnd, end(12, TRANSFER_VERIFIED)).await;
    timeout(STEP, call).await.unwrap().unwrap().unwrap();
    assert_eq!(std::fs::read(dir.path().join("out.bin")).unwrap(), data);
    assert_eq!(files_in(dir.path()), vec!["out.bin".to_string()]);
}

// ---- sending (CLIENT-12 / PROTO-1) -----------------------------------------

#[tokio::test]
async fn large_requests_are_fragmented_and_oversized_ones_fail_alone() {
    let mut h = Harness::new();
    let text = "x".repeat(40_000);
    h.client.send_chat("lobby", 0, &text).await.unwrap();
    let frame = h.expect(PacketType::ChatMessage).await;
    assert_eq!(ChatSend::decode(&frame.payload).unwrap().text, text);

    // Too long for the wire's u16 length: refused locally, session intact.
    let huge = "y".repeat(70_000);
    let err = h.client.send_chat("lobby", 0, &huge).await.unwrap_err();
    assert!(matches!(err, ClientError::InvalidInput(_)), "{err:?}");
    h.assert_alive().await;
}

/// P-2: the server caps reassembled control messages at 64 KiB (and drops
/// the connection for anything bigger), well below the 4 MiB the client
/// used to allow. A string that fits the wire's u16 length but makes the
/// message too big is refused locally; nothing reaches the server.
#[tokio::test]
async fn requests_over_the_servers_per_type_cap_fail_alone() {
    let mut h = Harness::new();
    let text = "z".repeat(65_530);
    let err = h.client.send_chat("lobby", 0, &text).await.unwrap_err();
    assert!(matches!(err, ClientError::InvalidInput(_)), "{err:?}");
    let err = h.client.send_private("bob", &text).await.unwrap_err();
    assert!(matches!(err, ClientError::InvalidInput(_)), "{err:?}");
    let (name, desc) = ("n".repeat(40_000), "d".repeat(40_000));
    let err = h.client.update_server_settings(&name, &desc, "", 0).await.unwrap_err();
    assert!(matches!(err, ClientError::InvalidInput(_)), "{err:?}");
    // The next request is the first thing the server sees.
    h.assert_alive().await;
}

// ---- upload aborts (P-5) -----------------------------------------------------

/// Start an upload of `len` bytes and accept it as transfer `id`; returns
/// the call, the chunk count and the barrier tokens of the chunks sent
/// before the window filled (none of them acknowledged).
async fn upload_with_unacked_window(
    h: &mut Harness,
    dir: &Path,
    id: u8,
    len: usize,
) -> (JoinHandle<Result<(), ClientError>>, u32, Vec<Bytes>) {
    let path = dir.join("big.bin");
    std::fs::write(&path, blob(len)).unwrap();
    let client = h.client.clone();
    let upload = tokio::spawn(async move { client.upload(path, "/").await });
    let req = h.expect(PacketType::FileTransferStart).await;
    let req = TransferRequest::decode(&req.payload).unwrap();
    let total = total_chunks(req.size, req.chunk_size);
    h.send(
        PacketType::FileTransferStart,
        accept(id, req.chunk_size, total, req.size, req.sha256, vec![]),
    )
    .await;
    // The client sends chunks until its in-flight window is full.
    let window = (UPLOAD_WINDOW_BYTES / req.chunk_size as u64) as usize;
    let mut pings = Vec::new();
    while pings.len() < window {
        let frame = h.recv().await;
        if frame.header.packet_type == PacketType::Ping {
            pings.push(frame.payload);
        }
    }
    (upload, total, pings)
}

/// Count the ServerError events queued so far.
fn server_errors(h: &mut Harness) -> usize {
    let mut n = 0;
    while let Ok(ev) = h.events.try_recv() {
        if matches!(ev, Event::ServerError { .. }) {
            n += 1;
        }
    }
    n
}

#[tokio::test]
async fn a_server_aborted_upload_does_not_flood_errors() {
    let mut h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let (upload, _, pings) = upload_with_unacked_window(&mut h, dir.path(), 21, 6 << 20).await;
    assert!(pings.len() > 2);
    // The server gives up on the upload, then refuses every chunk that was
    // already on its way.
    h.send(PacketType::FileTransferEnd, end(21, TRANSFER_ABORTED)).await;
    for token in pings {
        h.error("no active transfer").await;
        h.send(PacketType::Pong, token).await;
    }
    let err = timeout(STEP, upload).await.unwrap().unwrap().unwrap_err();
    assert!(matches!(err, ClientError::Transfer(_)), "{err:?}");
    h.assert_alive().await;
    assert_eq!(server_errors(&mut h), 0, "the abort is reported by the upload itself");
}

#[tokio::test]
async fn refused_upload_chunks_raise_one_error() {
    let mut h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let (upload, _, pings) = upload_with_unacked_window(&mut h, dir.path(), 22, 6 << 20).await;
    let in_flight = pings.len();
    assert!(in_flight > 2);
    for token in pings {
        h.error("storage failure").await;
        h.send(PacketType::Pong, token).await;
    }
    let err = timeout(STEP, upload).await.unwrap().unwrap().unwrap_err();
    assert!(err.to_string().contains("storage failure"), "{err:?}");
    // The client tells the server it abandoned the transfer.
    h.expect(PacketType::FileTransferEnd).await;
    h.assert_alive().await;
    assert_eq!(server_errors(&mut h), 1, "{in_flight} refused chunks");
}

// ---- supervision (CLIENT-6) -------------------------------------------------

#[tokio::test]
async fn a_panicking_actor_still_reports_disconnected() {
    let (client_io, _server_io) = tokio::io::duplex(1024);
    let (cmd_tx, cmd_rx) = mpsc::channel(4);
    let (ev_tx, mut ev_rx) = mpsc::channel(4);
    let mut actor = Actor::new(Framed::new(client_io, KdxCodec::default()), cmd_rx, ev_tx);
    // Force a panic inside the actor task: a zero keepalive period makes
    // `interval_at` panic as soon as `run` starts.
    actor.opts.keepalive = Duration::ZERO;
    let _client = actor.spawn(cmd_tx);
    let ev = timeout(STEP, ev_rx.recv()).await.unwrap().unwrap();
    assert_eq!(
        ev,
        Event::Disconnected {
            reason: "internal error".into()
        }
    );
}

use std::io::Write as _;

use crate::transfer::total_chunks;
