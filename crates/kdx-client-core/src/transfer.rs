//! Client-side transfer helpers: chunk math, geometry validation, the
//! received-chunk bitmap, the `.kdxpart` resume sidecar and the blocking
//! file work (hashing) that runs on the blocking pool. The upload/download
//! state machines that use these live in the connection actor (they need the
//! socket).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use base64::Engine;
use bitvec::prelude::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::ClientError;

/// Default chunk size the client requests (32 KiB, matching the server).
pub const DEFAULT_CHUNK_SIZE: u32 = 32 * 1024;
/// Smallest chunk size any KDX server may use (mirrors the server's range).
pub const MIN_CHUNK_SIZE: u32 = 4 * 1024;
/// Largest chunk size any KDX server may use (mirrors the server's range).
pub const MAX_CHUNK_SIZE: u32 = 256 * 1024;
/// Hard cap on a single transfer's size (the server's `MAX_FILE_SIZE`).
/// A server announcing a bigger download is refused before any file exists.
pub const MAX_TRANSFER_SIZE: u64 = 16 * 1024 * 1024 * 1024;
/// Most chunks a transfer may have: keeps every bitmap within the wire's
/// u16 length prefix (65,535 bytes).
pub const MAX_TOTAL_CHUNKS: u32 = 524_280;
/// Chunk count the client aims to stay under when it picks a chunk size, so
/// bitmaps stay small (8 KiB) even for the largest files.
const TARGET_TOTAL_CHUNKS: u32 = 65_536;

pub type ChunkBitmap = BitVec<u8, Lsb0>;

/// Number of chunks a file of `size` splits into at `chunk_size`.
pub fn total_chunks(size: u64, chunk_size: u32) -> u32 {
    if size == 0 || chunk_size == 0 {
        0
    } else {
        size.div_ceil(chunk_size as u64).min(u32::MAX as u64) as u32
    }
}

/// Byte length of chunk `index` given the total size.
pub fn chunk_len(size: u64, chunk_size: u32, index: u32, total: u32) -> usize {
    if total == 0 || index >= total {
        return 0;
    }
    if index == total - 1 {
        let rem = (size % chunk_size as u64) as usize;
        if rem == 0 {
            chunk_size as usize
        } else {
            rem
        }
    } else {
        chunk_size as usize
    }
}

/// Bytes needed for a bitmap of `total` chunks.
pub fn bitmap_bytes(total: u32) -> usize {
    (total as usize).div_ceil(8)
}

/// Pick a chunk size for a file of `size` bytes: the default, doubled until
/// the chunk count is modest, never above the protocol maximum.
pub fn choose_chunk_size(size: u64) -> u32 {
    let mut chunk = DEFAULT_CHUNK_SIZE;
    while chunk < MAX_CHUNK_SIZE && total_chunks(size, chunk) > TARGET_TOTAL_CHUNKS {
        chunk *= 2;
    }
    chunk
}

/// Check a server's `TransferAccept` geometry before the client allocates or
/// creates anything from it. `requested_chunk` is what we asked for: for an
/// upload the server must use it; for a download it may pick a larger one.
pub fn validate_geometry(
    upload: bool,
    requested_chunk: u32,
    chunk_size: u32,
    total: u32,
    size: u64,
    echo_bitmap_len: usize,
) -> Result<(), String> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(format!("server chose an invalid chunk size ({chunk_size})"));
    }
    if upload && chunk_size != requested_chunk {
        return Err("server changed the upload chunk size".into());
    }
    if !upload && chunk_size < requested_chunk {
        return Err("server chose a smaller chunk size than requested".into());
    }
    if size > MAX_TRANSFER_SIZE {
        return Err(format!("server announced an oversized file ({size} bytes)"));
    }
    if total != total_chunks(size, chunk_size) {
        return Err("server's chunk count does not match the file size".into());
    }
    if total > MAX_TOTAL_CHUNKS {
        return Err("server announced too many chunks".into());
    }
    if echo_bitmap_len > bitmap_bytes(total) {
        return Err("server's chunk bitmap is longer than the chunk count".into());
    }
    Ok(())
}

/// Downsample a chunk bitmap to at most `max_bits` bits for progress events:
/// bit `i` covers a contiguous group of chunks and is set only when every
/// chunk in the group is done. Returns the bytes and the number of bits.
pub fn progress_bitmap(have: &BitSlice<u8, Lsb0>, max_bits: usize) -> (Vec<u8>, u32) {
    let total = have.len();
    if total <= max_bits {
        let mut bits = have.to_bitvec();
        bits.set_uninitialized(false);
        return (bits.into_vec(), total as u32);
    }
    let group = total.div_ceil(max_bits);
    let buckets = total.div_ceil(group);
    let mut out: ChunkBitmap = BitVec::repeat(false, buckets);
    for (i, chunk) in have.chunks(group).enumerate() {
        if chunk.all() {
            out.set(i, true);
        }
    }
    (out.into_vec(), buckets as u32)
}

/// Where a download's bytes accumulate until verified. A distinctive suffix
/// so a user's own `name.part` is never opened, truncated or renamed.
pub fn data_path_for(local: &Path) -> PathBuf {
    let mut s = local.as_os_str().to_owned();
    s.push(".kdxdata");
    PathBuf::from(s)
}

/// A resume sidecar written next to a partially-downloaded file. Records the
/// download's identity (server, remote path, size, hash, geometry) so a
/// resume is only attempted against the same file, plus which chunks are
/// already on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sidecar {
    /// `host:port` of the server the partial download came from.
    pub server: String,
    /// The remote `/dir/name` path that was being downloaded.
    pub remote: String,
    pub transfer_id: [u8; 16],
    pub size: u64,
    pub chunk_size: u32,
    pub sha256: [u8; 32],
    pub bitmap: Vec<u8>,
}

const SIDECAR_VERSION: &str = "2";
/// Upper bound on a sidecar file we are willing to read (a 64 KiB bitmap in
/// base64 plus a few short lines).
const MAX_SIDECAR_BYTES: u64 = 256 * 1024;

impl Sidecar {
    pub fn path_for(local: &Path) -> PathBuf {
        let mut s = local.as_os_str().to_owned();
        s.push(".kdxpart");
        PathBuf::from(s)
    }

    fn encode(&self) -> String {
        let b64 = base64::engine::general_purpose::STANDARD;
        format!(
            "version={}\nserver={}\nremote={}\nid={}\nsize={}\nchunk_size={}\nsha256={}\nbitmap={}\n",
            SIDECAR_VERSION,
            b64.encode(self.server.as_bytes()),
            b64.encode(self.remote.as_bytes()),
            Uuid::from_bytes(self.transfer_id),
            self.size,
            self.chunk_size,
            b64.encode(self.sha256),
            b64.encode(&self.bitmap),
        )
    }

    /// Strictly parse a sidecar. Anything malformed, from an older version,
    /// or geometrically inconsistent yields `None` (start fresh).
    fn decode(text: &str) -> Option<Sidecar> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut fields: std::collections::HashMap<&str, &str> = Default::default();
        for line in text.lines() {
            let (k, v) = line.split_once('=')?;
            if fields.insert(k, v).is_some() {
                return None; // duplicate key
            }
        }
        if fields.len() != 8 || *fields.get("version")? != SIDECAR_VERSION {
            return None;
        }
        let server = String::from_utf8(b64.decode(fields.get("server")?).ok()?).ok()?;
        let remote = String::from_utf8(b64.decode(fields.get("remote")?).ok()?).ok()?;
        let transfer_id = *Uuid::parse_str(fields.get("id")?).ok()?.as_bytes();
        let size: u64 = fields.get("size")?.parse().ok()?;
        let chunk_size: u32 = fields.get("chunk_size")?.parse().ok()?;
        let sha256: [u8; 32] = b64.decode(fields.get("sha256")?).ok()?.try_into().ok()?;
        let bitmap = b64.decode(fields.get("bitmap")?).ok()?;
        let sc = Sidecar {
            server,
            remote,
            transfer_id,
            size,
            chunk_size,
            sha256,
            bitmap,
        };
        sc.is_consistent().then_some(sc)
    }

    /// Geometry sanity: a sidecar is only usable if it describes a valid
    /// transfer whose bitmap fits its chunk count.
    fn is_consistent(&self) -> bool {
        let total = total_chunks(self.size, self.chunk_size);
        (MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&self.chunk_size)
            && self.size <= MAX_TRANSFER_SIZE
            && total <= MAX_TOTAL_CHUNKS
            && self.bitmap.len() == bitmap_bytes(total)
    }

    /// Atomically replace the sidecar: write a temp file, fsync, rename.
    /// Blocking; call from `spawn_blocking`.
    pub fn write(&self, local: &Path) -> std::io::Result<()> {
        write_atomic(&Self::path_for(local), self.encode().as_bytes())
    }

    /// Read the sidecar for `local`, if one exists and parses. Blocking.
    pub fn read(local: &Path) -> Option<Sidecar> {
        let path = Self::path_for(local);
        let file = std::fs::File::open(path).ok()?;
        let mut text = String::new();
        file.take(MAX_SIDECAR_BYTES).read_to_string(&mut text).ok()?;
        Self::decode(&text)
    }
}

/// Write `bytes` to `path` via a sibling temp file, fsync and rename, so a
/// crash leaves either the old or the new contents, never a torn file.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("path has no file name"))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".tmp-{}", Uuid::new_v4().simple()));
    let tmp = match dir {
        Some(d) => d.join(tmp_name),
        None => PathBuf::from(tmp_name),
    };
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result?;
    #[cfg(unix)]
    if let Some(d) = dir {
        // Persist the rename itself; best effort.
        if let Ok(dir) = std::fs::File::open(d) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// A local file prepared for upload: stat'ed, size-checked and hashed.
pub(crate) struct PreparedUpload {
    pub file: std::fs::File,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub sha256: [u8; 32],
}

const HASH_BUF: usize = 256 * 1024;

/// Stat, open and stream-hash a file for upload. Blocking; run it on the
/// blocking pool. Refuses anything but a regular file within the size cap
/// (a FIFO or device would otherwise block or never end), and detects the
/// file changing while it is hashed.
pub(crate) fn prepare_upload(
    path: &Path,
    cancel: &Arc<AtomicBool>,
) -> Result<PreparedUpload, ClientError> {
    // Stat the path before opening it: opening a FIFO blocks.
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Err(ClientError::InvalidInput("not a regular file".into()));
    }
    if meta.len() > MAX_TRANSFER_SIZE {
        return Err(ClientError::InvalidInput("file is too large to upload".into()));
    }
    let mut file = std::fs::File::open(path)?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(ClientError::InvalidInput("not a regular file".into()));
    }
    let size = before.len();
    if size > MAX_TRANSFER_SIZE {
        return Err(ClientError::InvalidInput("file is too large to upload".into()));
    }
    let modified = before.modified().ok();

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUF];
    let mut remaining = size;
    while remaining > 0 {
        if cancel.load(Ordering::Relaxed) {
            return Err(ClientError::Transfer("cancelled".into()));
        }
        let want = remaining.min(HASH_BUF as u64) as usize;
        let n = file.read(&mut buf[..want])?;
        if n == 0 {
            return Err(ClientError::Transfer("local file changed during upload".into()));
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    let after = file.metadata()?;
    if after.len() != size || after.modified().ok() != modified {
        return Err(ClientError::Transfer("local file changed during upload".into()));
    }
    Ok(PreparedUpload {
        file,
        size,
        modified,
        sha256: hasher.finalize().into(),
    })
}

/// Hash exactly the first `size` bytes of a finished download's data file,
/// trimming any excess beyond `size` first. Blocking and cancellable.
pub(crate) fn hash_download(
    path: &Path,
    size: u64,
    cancel: &Arc<AtomicBool>,
) -> Result<[u8; 32], ClientError> {
    let mut file = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    let len = file.metadata()?.len();
    if len < size {
        return Err(ClientError::Transfer("downloaded file is incomplete".into()));
    }
    if len > size {
        file.set_len(size)?;
    }
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUF];
    let mut remaining = size;
    while remaining > 0 {
        if cancel.load(Ordering::Relaxed) {
            return Err(ClientError::Transfer("cancelled".into()));
        }
        let want = remaining.min(HASH_BUF as u64) as usize;
        let n = file.read(&mut buf[..want])?;
        if n == 0 {
            return Err(ClientError::Transfer("downloaded file is incomplete".into()));
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_math() {
        assert_eq!(total_chunks(0, 100), 0);
        assert_eq!(total_chunks(100, 100), 1);
        assert_eq!(total_chunks(101, 100), 2);
        assert_eq!(chunk_len(250, 100, 0, 3), 100);
        assert_eq!(chunk_len(250, 100, 2, 3), 50);
        assert_eq!(chunk_len(300, 100, 2, 3), 100); // exact multiple
        assert_eq!(chunk_len(300, 100, 3, 3), 0); // out of range
    }

    #[test]
    fn chunk_size_grows_for_big_files() {
        assert_eq!(choose_chunk_size(0), DEFAULT_CHUNK_SIZE);
        assert_eq!(choose_chunk_size(1 << 30), DEFAULT_CHUNK_SIZE);
        let big = choose_chunk_size(MAX_TRANSFER_SIZE);
        assert_eq!(big, MAX_CHUNK_SIZE);
        assert!(total_chunks(MAX_TRANSFER_SIZE, big) <= TARGET_TOTAL_CHUNKS);
    }

    #[test]
    fn geometry_validation_rejects_hostile_accepts() {
        let ok = |chunk, total, size, bm| validate_geometry(false, 32768, chunk, total, size, bm);
        assert!(ok(32768, 4, 100_000, 1).is_ok());
        assert!(ok(32768, 0, 0, 0).is_ok());
        // Larger server-chosen chunk size is fine for downloads.
        assert!(ok(65536, 2, 100_000, 0).is_ok());
        // Bitmap bomb: total_chunks inconsistent with size.
        assert!(ok(32768, u32::MAX, 1, 0).is_err());
        // Exabyte sparse file.
        assert!(ok(32768, 0, 1 << 60, 0).is_err());
        assert!(ok(MAX_CHUNK_SIZE, total_chunks(1 << 50, MAX_CHUNK_SIZE), 1 << 50, 0).is_err());
        // Chunk size out of range or smaller than requested.
        assert!(ok(u32::MAX, 1, 1, 0).is_err());
        assert!(ok(4096, 25, 100_000, 0).is_err());
        // Echoed bitmap longer than the chunk count.
        assert!(ok(32768, 4, 100_000, 2).is_err());
        // Uploads must keep our chunk size.
        assert!(validate_geometry(true, 32768, 65536, 2, 100_000, 0).is_err());
    }

    #[test]
    fn progress_bitmap_is_capped() {
        let mut have: ChunkBitmap = BitVec::repeat(false, 10);
        have.set(1, true);
        let (bytes, bits) = progress_bitmap(&have, 1024);
        assert_eq!((bytes, bits), (vec![0b10, 0], 10));

        let mut have: ChunkBitmap = BitVec::repeat(true, 100_000);
        have.set(5, false);
        let (bytes, bits) = progress_bitmap(&have, 1024);
        assert!(bits <= 1024);
        assert_eq!(bytes.len(), (bits as usize).div_ceil(8));
        // The first bucket holds the missing chunk; the rest are complete.
        let out = ChunkBitmap::from_vec(bytes);
        assert!(!out[0]);
        assert!(out[1..bits as usize].all());
    }

    fn sample() -> Sidecar {
        Sidecar {
            server: "host.example:10700".into(),
            remote: "/dir/file=with\nodd chars".into(),
            transfer_id: [7u8; 16],
            size: 12345,
            chunk_size: 32 * 1024,
            sha256: [9u8; 32],
            bitmap: vec![0b0000_0001],
        }
    }

    #[test]
    fn sidecar_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("file.bin");
        let sc = sample();
        sc.write(&local).unwrap();
        assert_eq!(Sidecar::read(&local).unwrap(), sc);
        // No temp files are left behind.
        let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(names.len(), 1);
        std::fs::remove_file(Sidecar::path_for(&local)).unwrap();
        assert!(Sidecar::read(&local).is_none());
    }

    #[test]
    fn sidecar_rejects_legacy_and_inconsistent_files() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("file.bin");
        // A v1 sidecar (no identity) is not trusted.
        std::fs::write(
            Sidecar::path_for(&local),
            "id=07070707-0707-0707-0707-070707070707\nsize=12345\nchunk_size=32768\n\
             sha256=CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=\nbitmap=AQ==\n",
        )
        .unwrap();
        assert!(Sidecar::read(&local).is_none());
        // A bitmap that doesn't fit the geometry is not trusted.
        let mut sc = sample();
        sc.bitmap = vec![0xFF; 100];
        sc.write(&local).unwrap();
        assert!(Sidecar::read(&local).is_none());
    }
}
