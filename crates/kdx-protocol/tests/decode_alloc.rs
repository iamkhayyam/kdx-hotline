//! List decoders must not pre-allocate from an attacker-chosen count: a tiny
//! payload claiming 65,535 or 4 billion entries used to reserve up to 8 MiB
//! (`NewsThreadListResponse`) before failing on the first missing entry.
//!
//! This test binary installs a global allocator that records the largest
//! single allocation, so it holds exactly one test to keep the measurement
//! free of interference from concurrently running tests.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use kdx_protocol::messages::*;

struct LargestAllocation;

static LARGEST: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for LargestAllocation {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LARGEST.fetch_max(new_size, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: LargestAllocation = LargestAllocation;

/// Decodes a payload, reporting only whether it was accepted.
type Probe = fn(&[u8]) -> bool;

/// Largest single allocation made while running `decode` on `payload`, and
/// whether it decoded.
fn largest_allocation(payload: &[u8], decode: Probe) -> (usize, bool) {
    LARGEST.store(0, Ordering::SeqCst);
    let ok = decode(payload);
    (LARGEST.load(Ordering::SeqCst), ok)
}

macro_rules! probe {
    ($t:ty) => {
        (|b: &[u8]| <$t>::decode(b).is_ok()) as Probe
    };
}

const U16_MAX: &[u8] = &[0xFF, 0xFF];
const U32_MAX: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF];
const EMPTY_STR: &[u8] = &[0, 0];

#[test]
fn hostile_counts_do_not_drive_preallocation() {
    // Each payload is well-formed up to its count field, which claims the
    // maximum, and then ends (or carries a few stray bytes).
    let cases: Vec<(&str, Vec<u8>, Probe)> = vec![
        (
            "NewsThreadListResponse",
            [&[9u8; 16][..], U32_MAX].concat(),
            probe!(NewsThreadListResponse),
        ),
        ("NewsgroupListResponse", U32_MAX.to_vec(), probe!(NewsgroupListResponse)),
        ("FileSearchResponse", U32_MAX.to_vec(), probe!(FileSearchResponse)),
        ("TrackerListResponse", U32_MAX.to_vec(), probe!(TrackerListResponse)),
        ("HistoryListResponse", U32_MAX.to_vec(), probe!(HistoryListResponse)),
        ("IpRuleListResponse", U32_MAX.to_vec(), probe!(IpRuleListResponse)),
        ("AccountListResponse", U32_MAX.to_vec(), probe!(AccountListResponse)),
        ("PresenceListResponse", U16_MAX.to_vec(), probe!(PresenceListResponse)),
        ("ConnectionListResponse", U16_MAX.to_vec(), probe!(ConnectionListResponse)),
        ("RoleListResponse", U16_MAX.to_vec(), probe!(RoleListResponse)),
        ("ChatUserList", [EMPTY_STR, U16_MAX].concat(), probe!(ChatUserList)),
        ("FileListResponse", [EMPTY_STR, U16_MAX].concat(), probe!(FileListResponse)),
        (
            "AccountRolesResponse",
            [EMPTY_STR, U16_MAX, &[0u8; 15]].concat(),
            probe!(AccountRolesResponse),
        ),
    ];

    // Generous bound: the payloads above are at most 21 bytes, so nothing
    // legitimate needs more than a few hundred bytes to reject them.
    const LIMIT: usize = 4 * 1024;
    let mut failures = Vec::new();
    for (name, payload, decode) in cases {
        let (largest, ok) = largest_allocation(&payload, decode);
        assert!(!ok, "{name}: hostile payload {payload:02X?} decoded");
        if largest > LIMIT {
            failures.push(format!("{name}: allocated {largest} bytes"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));

    // Sanity check that the tracker works: a legitimate large list still
    // decodes and grows past the pre-allocation cap.
    let big = FileListResponse {
        path: "/".into(),
        entries: (0..5_000u64)
            .map(|i| FileEntry {
                name: format!("f{i}"),
                kind: KIND_FILE,
                size: i,
            })
            .collect(),
    }
    .encode();
    let (largest, ok) = largest_allocation(&big, probe!(FileListResponse));
    assert!(ok);
    assert!(largest > LIMIT, "allocation tracking is not observing decodes");
}
