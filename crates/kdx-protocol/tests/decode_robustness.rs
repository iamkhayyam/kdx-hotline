//! Decoder robustness: every payload decoder in `kdx_protocol::messages` is
//! fed every prefix of a valid encoding, mutations of it, and a few thousand
//! seeded pseudo-random byte strings. No input may panic (a panicking decoder
//! kills the connection or client actor task that called it).
//!
//! For the message types this crate's encoders fully own, anything that
//! decodes must also re-encode to the identical bytes: the wire format has
//! exactly one encoding per value, so non-canonical inputs (flag bytes other
//! than 0/1, unknown transfer directions, trailing bytes, ...) are rejected
//! rather than silently normalized.

use std::panic::{catch_unwind, AssertUnwindSafe};

use bytes::Bytes;
use kdx_protocol::messages::*;

/// Deterministic xorshift64 generator; no external RNG dependency.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    /// A byte biased toward the values length prefixes, counts and flags
    /// are most sensitive to.
    fn byte(&mut self) -> u8 {
        match self.below(8) {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 0xFF,
            _ => self.next() as u8,
        }
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }
}

const RANDOM_INPUTS: usize = 2_000;
const MUTATIONS_PER_SEED: usize = 1_000;

/// Decode `input`; on success return the re-encoding when the type's
/// encoding is canonical, or `None` to skip that check.
type Probe = fn(&[u8]) -> Result<Option<Bytes>, ()>;

/// Every prefix of each seed, mutated seeds, and random byte strings.
fn inputs(seeds: &[Bytes], rng: &mut XorShift) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for seed in seeds {
        for len in 0..=seed.len() {
            out.push(seed[..len].to_vec());
        }
        for _ in 0..MUTATIONS_PER_SEED {
            let mut m = seed.to_vec();
            for _ in 0..1 + rng.below(3) {
                match rng.below(4) {
                    0 if !m.is_empty() => {
                        let i = rng.below(m.len());
                        m[i] = rng.byte();
                    }
                    1 if !m.is_empty() => {
                        let i = rng.below(m.len());
                        m.truncate(i);
                    }
                    2 => {
                        let i = rng.below(m.len() + 1);
                        let b = rng.byte();
                        m.insert(i, b);
                    }
                    _ => {
                        let n = 1 + rng.below(8);
                        let extra = rng.bytes(n);
                        m.extend_from_slice(&extra);
                    }
                }
            }
            out.push(m);
        }
    }
    for _ in 0..RANDOM_INPUTS {
        let len = if rng.below(10) == 0 {
            rng.below(1024)
        } else {
            rng.below(64)
        };
        out.push(rng.bytes(len));
    }
    out
}

fn exercise(name: &str, seeds: Vec<Bytes>, probe: Probe, rng: &mut XorShift) -> Vec<String> {
    let mut failures = Vec::new();
    // Every seed is a valid encoding and must decode.
    for seed in &seeds {
        match catch_unwind(|| probe(seed)) {
            Ok(Ok(_)) => {}
            _ => failures.push(format!("{name}: valid seed {seed:02X?} rejected")),
        }
    }
    for input in inputs(&seeds, rng) {
        match catch_unwind(AssertUnwindSafe(|| probe(&input))) {
            Err(_) => {
                failures.push(format!("{name}: decode panicked on {input:02X?}"));
                break;
            }
            Ok(Ok(Some(reencoded))) if reencoded[..] != input[..] => {
                failures.push(format!(
                    "{name}: accepted non-canonical {input:02X?} (re-encodes to {:02X?})",
                    &reencoded[..]
                ));
                break;
            }
            Ok(_) => {}
        }
    }
    failures
}

/// `canonical!(T)`: decode, and on success re-encode for the canonical check.
macro_rules! canonical {
    ($t:ty) => {
        (|b: &[u8]| <$t>::decode(b).map(|m| Some(m.encode())).map_err(|_| ())) as Probe
    };
}

/// `decode_only!(T)`: decode and only check that it does not panic.
macro_rules! decode_only {
    ($t:ty) => {
        (|b: &[u8]| <$t>::decode(b).map(|_| None).map_err(|_| ())) as Probe
    };
}

fn presence_entry(username: &str) -> PresenceEntry {
    PresenceEntry {
        username: username.into(),
        class: 2,
        login_at: 1_751_600_000,
        idle_secs: 42,
        address: "10.0.0.5:52341".into(),
        name: "Phraq".into(),
        description: "visiting".into(),
    }
}

fn news_post(id: u8, parent: u8) -> NewsPost {
    NewsPost {
        id: [id; 16],
        newsgroup_id: [9; 16],
        parent_id: [parent; 16],
        author: "phraq".into(),
        subject: "subj".into(),
        body: "body é".into(),
        timestamp: 1_751_600_000,
    }
}

fn role(name: &str) -> RoleInfo {
    RoleInfo {
        id: [7; 16],
        name: name.into(),
        privileges: 0xAB,
        rank: -3,
        color: "#e11b1b".into(),
    }
}

/// `(name, seeds, probe)` for every payload type with a decoder.
fn cases() -> Vec<(&'static str, Vec<Bytes>, Probe)> {
    vec![
        // ---- account.rs
        (
            "AccountCreate",
            vec![AccountCreate {
                username: "acidburn".into(),
                password: "hacktheplanet".into(),
                base_class: 2,
                granted: 8,
                revoked: 64,
            }
            .encode()],
            canonical!(AccountCreate),
        ),
        (
            "AccountUpdate",
            vec![AccountUpdate {
                username: "phraq".into(),
                base_class: 1,
                granted: 0xDEAD_BEEF,
                revoked: 0,
            }
            .encode()],
            canonical!(AccountUpdate),
        ),
        (
            "AccountListRequest",
            vec![AccountListRequest.encode()],
            canonical!(AccountListRequest),
        ),
        (
            "AccountListResponse",
            vec![
                AccountListResponse { accounts: vec![] }.encode(),
                AccountListResponse {
                    accounts: vec![
                        AccountSummary {
                            username: "admin".into(),
                            base_class: 3,
                            granted: 0,
                            revoked: 0,
                        },
                        AccountSummary {
                            username: "guest".into(),
                            base_class: 0,
                            granted: 1,
                            revoked: 2,
                        },
                    ],
                }
                .encode(),
            ],
            canonical!(AccountListResponse),
        ),
        // ---- admin.rs
        (
            "AdminDisconnect",
            vec![AdminDisconnect {
                username: "lamer".into(),
                reason: "flood".into(),
                ban_secs: 3600,
            }
            .encode()],
            canonical!(AdminDisconnect),
        ),
        (
            "ServerSettingsRequest",
            vec![ServerSettingsRequest.encode()],
            canonical!(ServerSettingsRequest),
        ),
        (
            "ServerSettingsResponse",
            vec![ServerSettingsResponse {
                name: "Underground".into(),
                description: "warez".into(),
                greeting: "hi".into(),
                max_users: 256,
                port: 10700,
                max_upload_bytes_per_sec: 0,
                max_download_bytes_per_sec: 1_000_000,
            }
            .encode()],
            canonical!(ServerSettingsResponse),
        ),
        (
            "ServerSettingsUpdate",
            vec![ServerSettingsUpdate {
                name: "n".into(),
                description: "d".into(),
                greeting: "g".into(),
                max_users: 10,
            }
            .encode()],
            canonical!(ServerSettingsUpdate),
        ),
        (
            "AdminBroadcast",
            vec![AdminBroadcast { text: "restart".into() }.encode()],
            canonical!(AdminBroadcast),
        ),
        (
            "AdminShutdown",
            vec![AdminShutdown { message: "bye".into() }.encode()],
            canonical!(AdminShutdown),
        ),
        (
            "HistoryListRequest",
            vec![HistoryListRequest { limit: 50 }.encode()],
            canonical!(HistoryListRequest),
        ),
        (
            "HistoryListResponse",
            vec![HistoryListResponse {
                entries: vec![
                    HistoryEntry {
                        timestamp: 1,
                        actor: "sysop".into(),
                        action: "kicked".into(),
                        detail: "target=lamer".into(),
                    },
                    HistoryEntry {
                        timestamp: 2,
                        actor: String::new(),
                        action: "server_started".into(),
                        detail: String::new(),
                    },
                ],
            }
            .encode()],
            canonical!(HistoryListResponse),
        ),
        (
            "IpRuleListRequest",
            vec![IpRuleListRequest.encode()],
            canonical!(IpRuleListRequest),
        ),
        (
            "IpRuleListResponse",
            vec![IpRuleListResponse {
                rules: vec![IpRuleEntry {
                    id: "aaaa".into(),
                    position: 10,
                    action: "deny".into(),
                    cidr: "1.2.3.0/24".into(),
                    note: "spam".into(),
                    created_by: "sysop".into(),
                    created_at: 1_700_000_000,
                }],
            }
            .encode()],
            canonical!(IpRuleListResponse),
        ),
        (
            "IpRuleCreate",
            vec![IpRuleCreate {
                position: 42,
                action: "deny".into(),
                cidr: "10.0.0.0/8".into(),
                note: String::new(),
            }
            .encode()],
            canonical!(IpRuleCreate),
        ),
        (
            "IpRuleDelete",
            vec![IpRuleDelete { id: "uuid".into() }.encode()],
            canonical!(IpRuleDelete),
        ),
        (
            "ConnectionListRequest",
            vec![ConnectionListRequest.encode()],
            canonical!(ConnectionListRequest),
        ),
        (
            "ConnectionListResponse",
            vec![ConnectionListResponse {
                connections: vec![presence_entry("a"), presence_entry("b")],
            }
            .encode()],
            canonical!(ConnectionListResponse),
        ),
        // ---- auth.rs (decode only: owned by the auth redesign)
        (
            "AuthRequest",
            vec![Bytes::from_static(&[0, 5, b'p', b'h', b'r', b'a', b'q'])],
            decode_only!(AuthRequest),
        ),
        (
            "AuthChallenge",
            vec![{
                let mut b = vec![7u8; 32]; // challenge
                b.extend_from_slice(&19_456u32.to_be_bytes());
                b.extend_from_slice(&2u32.to_be_bytes());
                b.extend_from_slice(&1u32.to_be_bytes());
                b.extend_from_slice(&16u16.to_be_bytes());
                b.extend_from_slice(&[3u8; 16]); // salt
                Bytes::from(b)
            }],
            decode_only!(AuthChallenge),
        ),
        (
            "AuthResponse",
            vec![Bytes::from(vec![9u8; 32])],
            decode_only!(AuthResponse),
        ),
        (
            "AuthResult",
            vec![{
                let mut b = vec![1u8];
                b.extend_from_slice(&[3u8; 16]);
                b.push(2);
                b.extend_from_slice(&[0, 2, b'h', b'i']);
                Bytes::from(b)
            }],
            decode_only!(AuthResult),
        ),
        // ---- handshake.rs (decode only)
        (
            "HandshakeInit",
            vec![Bytes::from_static(&[1, 0, 0b1010])],
            decode_only!(HandshakeInit),
        ),
        (
            "HandshakeResp",
            vec![Bytes::from_static(&[1, 0, 0])],
            decode_only!(HandshakeResp),
        ),
        // ---- chat.rs
        (
            "ChatSend",
            vec![ChatSend {
                room: "lobby".into(),
                flags: CHAT_ACTION,
                text: "waves".into(),
            }
            .encode()],
            canonical!(ChatSend),
        ),
        (
            "ChatEvent",
            vec![ChatEvent {
                room: "lobby".into(),
                sender: "phraq".into(),
                timestamp: 1_751_600_000,
                flags: 0,
                text: "hello".into(),
            }
            .encode()],
            canonical!(ChatEvent),
        ),
        (
            "ChatJoin",
            vec![ChatJoin { room: "lobby".into() }.encode()],
            canonical!(ChatJoin),
        ),
        (
            "ChatLeave",
            vec![ChatLeave { room: "lobby".into() }.encode()],
            canonical!(ChatLeave),
        ),
        (
            "ChatUserList",
            vec![ChatUserList {
                room: "lobby".into(),
                users: vec!["a".into(), "bb".into(), String::new()],
            }
            .encode()],
            canonical!(ChatUserList),
        ),
        (
            "ChatTopic",
            vec![ChatTopic {
                room: "lobby".into(),
                topic: "digital freedom".into(),
            }
            .encode()],
            canonical!(ChatTopic),
        ),
        (
            "ChatInvite",
            vec![ChatInvite { to: "acidburn".into() }.encode()],
            canonical!(ChatInvite),
        ),
        (
            "ChatInvited",
            vec![ChatInvited {
                from: "phraq".into(),
                room: "priv-1".into(),
            }
            .encode()],
            canonical!(ChatInvited),
        ),
        (
            "ChatRoomFlags",
            vec![
                ChatRoomFlags {
                    room: "green".into(),
                    min_class_join: 2,
                    interview_mode: true,
                }
                .encode(),
                ChatRoomFlags {
                    room: String::new(),
                    min_class_join: 0,
                    interview_mode: false,
                }
                .encode(),
            ],
            canonical!(ChatRoomFlags),
        ),
        // ---- file.rs
        (
            "FileListRequest",
            vec![FileListRequest { path: "/pub".into() }.encode()],
            canonical!(FileListRequest),
        ),
        (
            "FileListResponse",
            vec![FileListResponse {
                path: "/".into(),
                entries: vec![
                    FileEntry {
                        name: "docs".into(),
                        kind: KIND_DIR,
                        size: 0,
                    },
                    FileEntry {
                        name: "kdx.iso".into(),
                        kind: KIND_FILE,
                        size: 123_456_789,
                    },
                ],
            }
            .encode()],
            canonical!(FileListResponse),
        ),
        (
            "FileCreateFolder",
            vec![
                FileCreateFolder {
                    path: "/pub".into(),
                    name: "drop".into(),
                    kind: KIND_DROPBOX,
                    min_read_class: 0,
                    min_write_class: 1,
                    owner: Some("bob".into()),
                }
                .encode(),
                FileCreateFolder {
                    path: "/".into(),
                    name: "d".into(),
                    kind: KIND_DIR,
                    min_read_class: 0,
                    min_write_class: 0,
                    owner: None,
                }
                .encode(),
            ],
            canonical!(FileCreateFolder),
        ),
        (
            "FileInfoRequest",
            vec![FileInfoRequest { path: "/pub/a".into() }.encode()],
            canonical!(FileInfoRequest),
        ),
        (
            "FileInfoResponse",
            vec![
                FileInfoResponse {
                    name: "a.txt".into(),
                    kind: KIND_FILE,
                    size: 1234,
                    sha256: Some([7; 32]),
                    min_read_class: 0,
                    min_write_class: 2,
                    owner: Some("bob".into()),
                }
                .encode(),
                FileInfoResponse {
                    name: "dir".into(),
                    kind: KIND_DIR,
                    size: 0,
                    sha256: None,
                    min_read_class: 1,
                    min_write_class: 3,
                    owner: None,
                }
                .encode(),
            ],
            canonical!(FileInfoResponse),
        ),
        (
            "FileDelete",
            vec![FileDelete { path: "/pub/x".into() }.encode()],
            canonical!(FileDelete),
        ),
        (
            "FileGenerateCatalog",
            vec![FileGenerateCatalog.encode()],
            canonical!(FileGenerateCatalog),
        ),
        (
            "FileCatalogGenerated",
            vec![FileCatalogGenerated { count: 42 }.encode()],
            canonical!(FileCatalogGenerated),
        ),
        (
            "FileSearchRequest",
            vec![FileSearchRequest { query: "readme".into() }.encode()],
            canonical!(FileSearchRequest),
        ),
        (
            "FileSearchResponse",
            vec![FileSearchResponse {
                entries: vec![FileSearchEntry {
                    path: "/pub/readme.txt".into(),
                    name: "readme.txt".into(),
                    kind: KIND_FILE,
                    size: 10,
                }],
            }
            .encode()],
            canonical!(FileSearchResponse),
        ),
        (
            "FileMove",
            vec![FileMove {
                path: "/a".into(),
                dest_path: "/b".into(),
            }
            .encode()],
            canonical!(FileMove),
        ),
        (
            "FileAlias",
            vec![FileAlias {
                source_path: "/a".into(),
                dest_path: "/b".into(),
            }
            .encode()],
            canonical!(FileAlias),
        ),
        (
            "TransferRequest",
            vec![
                TransferRequest {
                    direction: DIRECTION_UPLOAD,
                    path: "/in".into(),
                    name: "f.bin".into(),
                    size: 1 << 20,
                    chunk_size: 32 * 1024,
                    sha256: [5; 32],
                    resume_id: [0; 16],
                    have_bitmap: vec![],
                }
                .encode(),
                TransferRequest {
                    direction: DIRECTION_DOWNLOAD,
                    path: "/pub".into(),
                    name: "big.iso".into(),
                    size: 0,
                    chunk_size: 32 * 1024,
                    sha256: [0; 32],
                    resume_id: [7; 16],
                    have_bitmap: vec![0x0F, 0xF0],
                }
                .encode(),
            ],
            canonical!(TransferRequest),
        ),
        (
            "TransferAccept",
            vec![TransferAccept {
                transfer_id: [9; 16],
                chunk_size: 32 * 1024,
                total_chunks: 32,
                size: 1 << 20,
                sha256: [5; 32],
                have_bitmap: vec![0xAA, 0x55],
            }
            .encode()],
            canonical!(TransferAccept),
        ),
        (
            "TransferData",
            vec![TransferData {
                transfer_id: [9; 16],
                chunk_index: 7,
                chunk_hash: [3; 32],
                data: Bytes::from_static(b"chunk bytes"),
            }
            .encode()],
            canonical!(TransferData),
        ),
        (
            "TransferEnd",
            vec![TransferEnd {
                transfer_id: [9; 16],
                status: TRANSFER_VERIFIED,
                message: "ok".into(),
            }
            .encode()],
            canonical!(TransferEnd),
        ),
        // ---- news.rs
        (
            "NewsgroupListRequest",
            vec![NewsgroupListRequest.encode()],
            canonical!(NewsgroupListRequest),
        ),
        (
            "NewsgroupListResponse",
            vec![NewsgroupListResponse {
                groups: vec![NewsgroupInfo {
                    id: [1; 16],
                    name: "general".into(),
                    description: "misc".into(),
                    min_read_class: 0,
                    min_post_class: 1,
                }],
            }
            .encode()],
            canonical!(NewsgroupListResponse),
        ),
        (
            "NewsThreadListRequest",
            vec![NewsThreadListRequest { newsgroup_id: [7; 16] }.encode()],
            canonical!(NewsThreadListRequest),
        ),
        (
            "NewsThreadListResponse",
            vec![NewsThreadListResponse {
                newsgroup_id: [9; 16],
                posts: vec![news_post(1, 0), news_post(2, 1)],
            }
            .encode()],
            canonical!(NewsThreadListResponse),
        ),
        (
            "NewsPostCreate",
            vec![NewsPostCreate {
                newsgroup_id: [7; 16],
                parent_id: [0; 16],
                subject: "topic".into(),
                body: "text".into(),
            }
            .encode()],
            canonical!(NewsPostCreate),
        ),
        (
            "NewsPostDelete",
            vec![NewsPostDelete { post_id: [3; 16] }.encode()],
            canonical!(NewsPostDelete),
        ),
        (
            "NewsgroupCreate",
            vec![NewsgroupCreate {
                name: "general".into(),
                description: "chatter".into(),
                min_read_class: 0,
                min_post_class: 2,
            }
            .encode()],
            canonical!(NewsgroupCreate),
        ),
        // ---- presence.rs
        (
            "PresenceListRequest",
            vec![PresenceListRequest.encode()],
            canonical!(PresenceListRequest),
        ),
        (
            "PresenceListResponse",
            vec![PresenceListResponse {
                users: vec![presence_entry("phraq"), presence_entry("acidburn")],
            }
            .encode()],
            canonical!(PresenceListResponse),
        ),
        (
            "PresenceChange",
            vec![
                PresenceChange {
                    entry: presence_entry("phraq"),
                    online: true,
                }
                .encode(),
                PresenceChange {
                    entry: presence_entry("x"),
                    online: false,
                }
                .encode(),
            ],
            canonical!(PresenceChange),
        ),
        (
            "SetIdentity",
            vec![SetIdentity {
                name: "Captain".into(),
                description: "just visiting".into(),
            }
            .encode()],
            canonical!(SetIdentity),
        ),
        (
            "UserInfoRequest",
            vec![UserInfoRequest { username: "phraq".into() }.encode()],
            canonical!(UserInfoRequest),
        ),
        (
            "UserInfoResponse",
            vec![UserInfoResponse {
                entry: presence_entry("phraq"),
            }
            .encode()],
            canonical!(UserInfoResponse),
        ),
        // ---- private.rs
        (
            "PrivateSend",
            vec![PrivateSend {
                to: "acidburn".into(),
                text: "hi".into(),
            }
            .encode()],
            canonical!(PrivateSend),
        ),
        (
            "PrivateMessage",
            vec![PrivateMessage {
                from: "phraq".into(),
                to: "acidburn".into(),
                timestamp: 1_751_600_000,
                text: "the drop is live".into(),
            }
            .encode()],
            canonical!(PrivateMessage),
        ),
        // ---- roles.rs
        (
            "RoleListRequest",
            vec![RoleListRequest.encode()],
            canonical!(RoleListRequest),
        ),
        (
            "RoleListResponse",
            vec![RoleListResponse {
                roles: vec![role("Moderator"), role("")],
            }
            .encode()],
            canonical!(RoleListResponse),
        ),
        (
            "RoleCreate",
            vec![RoleCreate {
                name: "Mod".into(),
                privileges: 0xFF,
                rank: 5,
                color: "#3df56e".into(),
            }
            .encode()],
            canonical!(RoleCreate),
        ),
        (
            "RoleUpdate",
            vec![RoleUpdate {
                id: [1; 16],
                name: "Mod".into(),
                privileges: 0xAB,
                rank: -1,
                color: String::new(),
            }
            .encode()],
            canonical!(RoleUpdate),
        ),
        (
            "RoleDelete",
            vec![RoleDelete { id: [2; 16] }.encode()],
            canonical!(RoleDelete),
        ),
        (
            "RoleAssign",
            vec![RoleAssign {
                username: "phraq".into(),
                role_id: [3; 16],
            }
            .encode()],
            canonical!(RoleAssign),
        ),
        (
            "RoleUnassign",
            vec![RoleUnassign {
                username: "phraq".into(),
                role_id: [3; 16],
            }
            .encode()],
            canonical!(RoleUnassign),
        ),
        (
            "AccountRolesRequest",
            vec![AccountRolesRequest { username: "phraq".into() }.encode()],
            canonical!(AccountRolesRequest),
        ),
        (
            "AccountRolesResponse",
            vec![AccountRolesResponse {
                username: "phraq".into(),
                role_ids: vec![[3; 16], [4; 16]],
            }
            .encode()],
            canonical!(AccountRolesResponse),
        ),
        // ---- tracker.rs
        (
            "TrackerListRequest",
            vec![TrackerListRequest { filter: "under".into() }.encode()],
            canonical!(TrackerListRequest),
        ),
        (
            "TrackerListResponse",
            vec![TrackerListResponse {
                servers: vec![TrackerServer {
                    name: "The Underground".into(),
                    host: "kdx.example.net".into(),
                    port: 10700,
                    users: 7,
                    max_users: 100,
                    description: "warez".into(),
                }],
            }
            .encode()],
            canonical!(TrackerListResponse),
        ),
    ]
}

#[test]
fn no_decoder_panics_and_accepted_inputs_are_canonical() {
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    let mut failures = Vec::new();
    let cases = cases();
    for (name, seeds, probe) in cases {
        failures.extend(exercise(name, seeds, probe, &mut rng));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Names of every type with a `pub fn decode(` in src/messages/*.rs, found by
/// scanning the source for the enclosing `impl Name {` block.
fn decoders_in_source() -> Vec<String> {
    let sources = [
        include_str!("../src/messages/account.rs"),
        include_str!("../src/messages/admin.rs"),
        include_str!("../src/messages/auth.rs"),
        include_str!("../src/messages/chat.rs"),
        include_str!("../src/messages/file.rs"),
        include_str!("../src/messages/handshake.rs"),
        include_str!("../src/messages/news.rs"),
        include_str!("../src/messages/presence.rs"),
        include_str!("../src/messages/private.rs"),
        include_str!("../src/messages/roles.rs"),
        include_str!("../src/messages/tracker.rs"),
    ];
    let mut names = Vec::new();
    for src in sources {
        let mut current_impl = None;
        for line in src.lines() {
            if let Some(rest) = line.strip_prefix("impl ") {
                current_impl = rest.strip_suffix(" {").map(str::to_owned);
            } else if line.trim_start().starts_with("pub fn decode(") {
                names.extend(current_impl.clone());
            }
        }
    }
    names
}

#[test]
fn every_decoder_is_covered() {
    let covered: Vec<&str> = cases().iter().map(|(n, _, _)| *n).collect();
    let mut deduped = covered.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(deduped.len(), covered.len(), "duplicate case names");

    let in_source = decoders_in_source();
    assert!(in_source.len() >= 75, "source scan found only {in_source:?}");
    let missing: Vec<&String> = in_source
        .iter()
        .filter(|n| !covered.contains(&n.as_str()))
        .collect();
    assert!(missing.is_empty(), "add these decoders to cases(): {missing:?}");
}
