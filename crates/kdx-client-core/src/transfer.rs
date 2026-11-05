//! Client-side transfer helpers: chunk math, geometry validation, the
//! received-chunk bitmap, the `.kdxpart` resume sidecar, where a partial
//! download lives, and the blocking file work (hashing, publishing the
//! verified file, sweeping stale partials) that runs on the blocking pool.
//! The upload/download state machines that use these live in the connection
//! actor (they need the socket).
//!
//! # Partial downloads
//!
//! A download's bytes and its resume sidecar live in the client's own data
//! directory (`<data_dir>/transfers/<id>.kdxdata` and `<id>.kdxpart`), never
//! beside the destination: a sandboxed app (the macOS App Sandbox) may only
//! write the one file its save dialog returned, not that file's siblings.
//! `<id>` is derived from the server, the remote path and the destination,
//! so asking for the same file to the same place again resumes it, across
//! reconnects and restarts. Only once the whole file's hash verifies is it
//! moved to the destination (see [`publish_download`]).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::Engine;
use bitvec::prelude::*;
use sha2::{Digest, Sha256};
use tracing::{debug, warn};
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

/// Directory under `ClientConfig::data_dir` that holds partial downloads.
pub const TRANSFERS_DIR: &str = "transfers";
/// Suffix of a partial download's bytes.
const DATA_SUFFIX: &str = ".kdxdata";
/// Suffix of a partial download's resume sidecar.
const SIDECAR_SUFFIX: &str = ".kdxpart";
/// Hex digits in a partial download's id (128 bits of SHA-256).
const PARTIAL_ID_HEX: usize = 32;

/// Where one download keeps its in-progress state, inside the transfers
/// directory (never beside the destination).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialPaths {
    /// The bytes received so far (written at their chunk offsets).
    pub data: PathBuf,
    /// The resume sidecar.
    pub sidecar: PathBuf,
}

impl PartialPaths {
    /// The partial-download files for downloading `remote` from `server`
    /// (`host:port`) to `destination`, in `transfers_dir`.
    pub fn new(transfers_dir: &Path, server: &str, remote: &str, destination: &Path) -> Self {
        let id = partial_id(server, remote, destination);
        Self {
            data: transfers_dir.join(format!("{id}{DATA_SUFFIX}")),
            sidecar: transfers_dir.join(format!("{id}{SIDECAR_SUFFIX}")),
        }
    }
}

/// A stable, file-name-safe id for one (server, remote file, destination)
/// download: the first 128 bits of a SHA-256 over the length-prefixed
/// fields, in lowercase hex. Stable across runs, so a restarted client finds
/// its partial again when asked for the same file to the same place.
pub fn partial_id(server: &str, remote: &str, destination: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"kdx-partial-download-v1");
    for field in [
        server.as_bytes(),
        remote.as_bytes(),
        destination.as_os_str().as_encoded_bytes(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    let digest = hasher.finalize();
    digest[..PARTIAL_ID_HEX / 2]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Create the transfers directory (owner-only on Unix: partial downloads
/// are nobody else's business). Blocking.
pub(crate) fn create_transfers_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// The bytes of a path as stored in a sidecar.
fn path_bytes(path: &Path) -> &[u8] {
    path.as_os_str().as_encoded_bytes()
}

/// A path back from sidecar bytes. Any byte string on Unix; elsewhere only
/// UTF-8 (anything else just means "no usable resume state").
fn path_from_bytes(bytes: Vec<u8>) -> Option<PathBuf> {
    match String::from_utf8(bytes) {
        Ok(s) => Some(PathBuf::from(s)),
        #[cfg(unix)]
        Err(e) => {
            use std::os::unix::ffi::OsStringExt;
            Some(PathBuf::from(std::ffi::OsString::from_vec(e.into_bytes())))
        }
        #[cfg(not(unix))]
        Err(_) => None,
    }
}

/// A partial download's resume sidecar, kept in the transfers directory.
/// Records the download's identity (server, remote path, destination, size,
/// hash, geometry) so a resume is only attempted for the same file to the
/// same place, plus which chunks are already on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sidecar {
    /// `host:port` of the server the partial download came from.
    pub server: String,
    /// The remote `/dir/name` path that was being downloaded.
    pub remote: String,
    /// Where the verified file goes.
    pub destination: PathBuf,
    pub transfer_id: [u8; 16],
    pub size: u64,
    pub chunk_size: u32,
    pub sha256: [u8; 32],
    pub bitmap: Vec<u8>,
}

/// Version 3 moved partials into the data directory and added the
/// destination; older (beside-the-file) sidecars are never read.
const SIDECAR_VERSION: &str = "3";
/// Fields in a version-3 sidecar.
const SIDECAR_FIELDS: usize = 9;
/// Upper bound on a sidecar file we are willing to read (a 64 KiB bitmap in
/// base64 plus a few short lines).
const MAX_SIDECAR_BYTES: u64 = 256 * 1024;

impl Sidecar {
    fn encode(&self) -> String {
        let b64 = base64::engine::general_purpose::STANDARD;
        format!(
            "version={}\nserver={}\nremote={}\ndestination={}\nid={}\nsize={}\nchunk_size={}\nsha256={}\nbitmap={}\n",
            SIDECAR_VERSION,
            b64.encode(self.server.as_bytes()),
            b64.encode(self.remote.as_bytes()),
            b64.encode(path_bytes(&self.destination)),
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
        if fields.len() != SIDECAR_FIELDS || *fields.get("version")? != SIDECAR_VERSION {
            return None;
        }
        let server = String::from_utf8(b64.decode(fields.get("server")?).ok()?).ok()?;
        let remote = String::from_utf8(b64.decode(fields.get("remote")?).ok()?).ok()?;
        let destination = path_from_bytes(b64.decode(fields.get("destination")?).ok()?)?;
        let transfer_id = *Uuid::parse_str(fields.get("id")?).ok()?.as_bytes();
        let size: u64 = fields.get("size")?.parse().ok()?;
        let chunk_size: u32 = fields.get("chunk_size")?.parse().ok()?;
        let sha256: [u8; 32] = b64.decode(fields.get("sha256")?).ok()?.try_into().ok()?;
        let bitmap = b64.decode(fields.get("bitmap")?).ok()?;
        let sc = Sidecar {
            server,
            remote,
            destination,
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

    /// Atomically replace the sidecar at `path`: write a temp file, fsync,
    /// rename. Blocking; call from `spawn_blocking`.
    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        write_atomic(path, self.encode().as_bytes())
    }

    /// Read the sidecar at `path`, if one exists and parses. Blocking.
    pub fn read(path: &Path) -> Option<Sidecar> {
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
    sync_parent(path);
    Ok(())
}

/// Persist a rename/creation in `path`'s directory. Best effort (and a
/// no-op where directories can't be opened: Windows, or a sandbox that
/// grants only the file itself).
fn sync_parent(path: &Path) {
    #[cfg(unix)]
    if let Some(d) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if let Ok(dir) = std::fs::File::open(d) {
            let _ = dir.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
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

/// How a verified download reaches its destination. Only tests pick
/// anything but `Auto`, to force the fallbacks a real cross-filesystem or
/// sandboxed destination would take.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Publish {
    /// Rename; copy when that fails (another filesystem, or a sandbox that
    /// refuses the rename).
    #[default]
    Auto,
    /// Skip the rename: copy as if the destination were on another
    /// filesystem (via a temp file beside it when one may be created).
    #[cfg_attr(not(test), allow(dead_code))] // test hook
    ForceCopy,
    /// Skip the rename and the temp file: copy straight into the
    /// destination, as when only the chosen file itself may be written.
    ForceInPlace,
}

/// Move a verified download (`data`, exactly `size` bytes hashing to
/// `sha256`) to `destination`. Blocking and cancellable.
///
/// A rename when both are on one filesystem: atomic, and nothing is ever
/// created beside the destination. Otherwise (or if the rename is refused)
/// the bytes are copied — re-hashed on the way, so nothing but the verified
/// contents is ever published — and fsynced:
///
/// 1. into a temp file beside the destination, which is then renamed over
///    it (atomic replace, as before);
/// 2. if no such temp file may be created (the macOS App Sandbox grants a
///    save dialog's file, not its directory), straight into the destination
///    — not atomic, so a copy that fails removes the incomplete file; the
///    verified partial stays in the transfers directory for a retry.
///
/// The partial data file is removed once the destination holds the file.
pub(crate) fn publish_download(
    data: &Path,
    destination: &Path,
    size: u64,
    sha256: &[u8; 32],
    mode: Publish,
    cancel: &Arc<AtomicBool>,
) -> Result<(), ClientError> {
    if mode == Publish::Auto {
        match std::fs::rename(data, destination) {
            Ok(()) => {
                sync_parent(destination);
                return Ok(());
            }
            // Typically EXDEV (another filesystem); anything else the copy
            // will run into again and report.
            Err(e) => debug!("could not move the download into place ({e}); copying it"),
        }
    }
    copy_into_place(data, destination, size, sha256, mode != Publish::ForceInPlace, cancel)?;
    if let Err(e) = std::fs::remove_file(data) {
        warn!("could not remove a finished download's partial file: {e}");
    }
    Ok(())
}

/// The copying half of [`publish_download`].
fn copy_into_place(
    data: &Path,
    destination: &Path,
    size: u64,
    sha256: &[u8; 32],
    via_temp: bool,
    cancel: &Arc<AtomicBool>,
) -> Result<(), ClientError> {
    let mut source = std::fs::File::open(data)?;
    if via_temp {
        match create_temp_beside(destination) {
            Ok((tmp, mut file)) => {
                let result = copy_verified(&mut source, &mut file, size, sha256, cancel)
                    .and_then(|()| {
                        drop(file);
                        std::fs::rename(&tmp, destination).map_err(ClientError::Io)
                    });
                if result.is_err() {
                    let _ = std::fs::remove_file(&tmp);
                }
                result?;
                sync_parent(destination);
                return Ok(());
            }
            Err(e) => debug!("no temp file beside the destination ({e}); writing it in place"),
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(destination)?;
    let result = copy_verified(&mut source, &mut file, size, sha256, cancel);
    if result.is_err() {
        // Never leave a torn file looking like the download.
        drop(file);
        let _ = std::fs::remove_file(destination);
    }
    result?;
    sync_parent(destination);
    Ok(())
}

/// A new, uniquely named hidden file in `destination`'s directory. The name
/// has a fixed length (40 bytes), so it fits wherever the destination's own
/// name does.
fn create_temp_beside(destination: &Path) -> std::io::Result<(PathBuf, std::fs::File)> {
    let name = format!(".{}.kdxtmp", Uuid::new_v4().simple());
    let tmp = match destination.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(dir) => dir.join(name),
        None => PathBuf::from(name),
    };
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    Ok((tmp, file))
}

/// Copy exactly `size` bytes from `source` to `dest`, hashing them, then
/// fsync. Fails (without touching anything else) if the bytes don't hash
/// to `sha256` — the partial changed after it was verified.
fn copy_verified(
    source: &mut std::fs::File,
    dest: &mut std::fs::File,
    size: u64,
    sha256: &[u8; 32],
    cancel: &Arc<AtomicBool>,
) -> Result<(), ClientError> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUF];
    let mut remaining = size;
    while remaining > 0 {
        if cancel.load(Ordering::Relaxed) {
            return Err(ClientError::Transfer("cancelled".into()));
        }
        let want = remaining.min(HASH_BUF as u64) as usize;
        let n = source.read(&mut buf[..want])?;
        if n == 0 {
            return Err(ClientError::Transfer("downloaded file is incomplete".into()));
        }
        hasher.update(&buf[..n]);
        dest.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    if <[u8; 32]>::from(hasher.finalize()) != *sha256 {
        return Err(ClientError::Transfer(
            "downloaded file changed before it could be saved".into(),
        ));
    }
    dest.sync_all()?;
    Ok(())
}

/// Delete partial downloads in `dir` (the transfers directory) that nothing
/// has touched for `max_age`: a partial's data file, sidecar and any
/// leftover sidecar temp file go together, and only once the newest of them
/// is older than `max_age` (an active download rewrites its sidecar every
/// few seconds). Only files named like ours are considered. A missing
/// directory is fine. Returns how many partials were removed. Blocking.
pub(crate) fn sweep_stale_partials(
    dir: &Path,
    max_age: Duration,
    now: SystemTime,
) -> std::io::Result<usize> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    // id → (newest modification time, files)
    let mut groups: std::collections::HashMap<String, (SystemTime, Vec<PathBuf>)> =
        Default::default();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(id) = name.to_str().and_then(partial_file_id) else {
            continue;
        };
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let modified = meta.modified().unwrap_or(now);
        let group = groups
            .entry(id.to_string())
            .or_insert((SystemTime::UNIX_EPOCH, Vec::new()));
        group.0 = group.0.max(modified);
        group.1.push(entry.path());
    }
    let mut removed = 0;
    for (newest, files) in groups.into_values() {
        // A modification time in the future (clock change) counts as fresh.
        let stale = now.duration_since(newest).is_ok_and(|age| age > max_age);
        if stale {
            for file in &files {
                if let Err(e) = std::fs::remove_file(file) {
                    warn!("could not remove a stale partial download: {e}");
                }
            }
            removed += 1;
        }
    }
    Ok(removed)
}

/// The id of a file belonging to a partial download — `<id>.kdxdata`,
/// `<id>.kdxpart`, or a sidecar's temp file `.<id>.kdxpart.tmp-<uuid>` —
/// or `None` for anything else.
fn partial_file_id(name: &str) -> Option<&str> {
    let is_id = |s: &str| {
        s.len() == PARTIAL_ID_HEX && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    if let Some(rest) = name.strip_prefix('.') {
        let (id, tail) = rest.split_at_checked(PARTIAL_ID_HEX)?;
        let uuid = tail.strip_prefix(SIDECAR_SUFFIX)?.strip_prefix(".tmp-")?;
        return (is_id(id) && uuid.len() == 32 && uuid.bytes().all(|b| b.is_ascii_hexdigit()))
            .then_some(id);
    }
    let id = name
        .strip_suffix(DATA_SUFFIX)
        .or_else(|| name.strip_suffix(SIDECAR_SUFFIX))?;
    is_id(id).then_some(id)
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
            destination: PathBuf::from("/Users/me/Downloads/file=with\nodd chars é.bin"),
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
        let path = dir.path().join("x.kdxpart");
        let sc = sample();
        sc.write(&path).unwrap();
        assert_eq!(Sidecar::read(&path).unwrap(), sc);
        // No temp files are left behind.
        let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(names.len(), 1);
        std::fs::remove_file(&path).unwrap();
        assert!(Sidecar::read(&path).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_keeps_a_non_utf8_destination() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.kdxpart");
        let mut sc = sample();
        sc.destination = PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/\xff\xfe.bin"));
        sc.write(&path).unwrap();
        assert_eq!(Sidecar::read(&path).unwrap(), sc);
    }

    #[test]
    fn sidecar_rejects_legacy_and_inconsistent_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.kdxpart");
        // A v1 sidecar (no identity) is not trusted.
        std::fs::write(
            &path,
            "id=07070707-0707-0707-0707-070707070707\nsize=12345\nchunk_size=32768\n\
             sha256=CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=\nbitmap=AQ==\n",
        )
        .unwrap();
        assert!(Sidecar::read(&path).is_none());
        // Nor is a v2 one (from when partials lived beside the destination).
        let v2: String = sample()
            .encode()
            .replace("version=3", "version=2")
            .lines()
            .filter(|l| !l.starts_with("destination="))
            .map(|l| format!("{l}\n"))
            .collect();
        std::fs::write(&path, v2).unwrap();
        assert!(Sidecar::read(&path).is_none());
        // A bitmap that doesn't fit the geometry is not trusted.
        let mut sc = sample();
        sc.bitmap = vec![0xFF; 100];
        sc.write(&path).unwrap();
        assert!(Sidecar::read(&path).is_none());
    }

    #[test]
    fn partial_ids_are_stable_and_distinct() {
        let dir = Path::new("/data/transfers");
        let a = PartialPaths::new(dir, "h:1", "/x/f", Path::new("/dl/f"));
        assert_eq!(a, PartialPaths::new(dir, "h:1", "/x/f", Path::new("/dl/f")));
        assert_eq!(a.data.parent(), Some(dir));
        assert_eq!(a.sidecar.parent(), Some(dir));
        let id = partial_id("h:1", "/x/f", Path::new("/dl/f"));
        assert_eq!(id.len(), PARTIAL_ID_HEX);
        assert_eq!(a.data.file_name().unwrap(), format!("{id}.kdxdata").as_str());
        assert_eq!(a.sidecar.file_name().unwrap(), format!("{id}.kdxpart").as_str());
        assert_eq!(partial_file_id(&format!("{id}.kdxdata")), Some(id.as_str()));
        // Any field changing (or a field boundary shifting) changes the id.
        for other in [
            partial_id("h:2", "/x/f", Path::new("/dl/f")),
            partial_id("h:1", "/x/g", Path::new("/dl/f")),
            partial_id("h:1", "/x/f", Path::new("/dl/g")),
            partial_id("h:1/x", "/f", Path::new("/dl/f")),
        ] {
            assert_ne!(other, id);
        }
        // Pinned (cross-checked with an independent SHA-256): a client
        // update must not silently orphan every partial.
        assert_eq!(
            partial_id("kdx.example:10700", "/files/a.bin", Path::new("/home/u/a.bin")),
            "18ee7edc831db0810bd8bcdd8f3fdf22"
        );
    }

    fn not_cancelled() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    /// A verified partial in `<dir>/transfers`.
    fn verified_partial(dir: &Path, data: &[u8]) -> PathBuf {
        let transfers = dir.join(TRANSFERS_DIR);
        create_transfers_dir(&transfers).unwrap();
        let partial = transfers.join(format!("{}.kdxdata", "a".repeat(32)));
        std::fs::write(&partial, data).unwrap();
        partial
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn publishing_renames_or_copies_and_removes_the_partial() {
        let data = b"verified bytes".to_vec();
        let sha: [u8; 32] = Sha256::digest(&data).into();
        for mode in [Publish::Auto, Publish::ForceCopy, Publish::ForceInPlace] {
            let state = tempfile::tempdir().unwrap();
            let dest_dir = tempfile::tempdir().unwrap();
            let partial = verified_partial(state.path(), &data);
            let dest = dest_dir.path().join("out.bin");
            // The user chose to replace an existing file.
            std::fs::write(&dest, b"old contents, longer than the new ones").unwrap();
            publish_download(&partial, &dest, data.len() as u64, &sha, mode, &not_cancelled())
                .unwrap();
            assert_eq!(std::fs::read(&dest).unwrap(), data, "{mode:?}");
            assert_eq!(names(dest_dir.path()), vec!["out.bin"], "{mode:?}: no temp file left");
            assert!(!partial.exists(), "{mode:?}: partial removed");
        }
    }

    #[test]
    fn a_copy_publishes_only_the_verified_bytes() {
        let data = b"verified bytes".to_vec();
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let len = data.len() as u64;
        for mode in [Publish::ForceCopy, Publish::ForceInPlace] {
            let state = tempfile::tempdir().unwrap();
            let dest_dir = tempfile::tempdir().unwrap();
            let partial = verified_partial(state.path(), &data);
            let dest = dest_dir.path().join("out.bin");
            // The partial no longer matches the hash it was verified against.
            let err = publish_download(&partial, &dest, len, &[0; 32], mode, &not_cancelled())
                .unwrap_err();
            assert!(err.to_string().contains("changed"), "{mode:?}: {err:?}");
            assert!(names(dest_dir.path()).is_empty(), "{mode:?}: nothing published");
            assert!(partial.exists(), "{mode:?}: the caller decides about the partial");
            // Nor fewer bytes than were announced.
            let err = publish_download(&partial, &dest, len + 1, &sha, mode, &not_cancelled())
                .unwrap_err();
            assert!(err.to_string().contains("incomplete"), "{mode:?}: {err:?}");
            assert!(names(dest_dir.path()).is_empty());
            // A cancelled copy leaves nothing behind either.
            let cancel = Arc::new(AtomicBool::new(true));
            assert!(publish_download(&partial, &dest, len, &sha, mode, &cancel).is_err());
            assert!(names(dest_dir.path()).is_empty());
        }
    }

    /// A real cross-filesystem publish where the machine has one (tmpfs on
    /// /dev/shm beside a disk-backed temp dir): the rename fails with EXDEV
    /// and the copy takes over.
    #[cfg(target_os = "linux")]
    #[test]
    fn publishing_across_filesystems_copies() {
        use std::os::unix::fs::MetadataExt;
        let Ok(other_fs) = tempfile::tempdir_in("/dev/shm") else {
            eprintln!("no /dev/shm; skipping");
            return;
        };
        let state = tempfile::tempdir().unwrap();
        let dev = |p: &Path| std::fs::metadata(p).unwrap().dev();
        if dev(other_fs.path()) == dev(state.path()) {
            eprintln!("/dev/shm shares the temp dir's filesystem; skipping");
            return;
        }
        let data = vec![0x5A; 300_000];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let partial = verified_partial(state.path(), &data);
        let dest = other_fs.path().join("out.bin");
        let len = data.len() as u64;
        publish_download(&partial, &dest, len, &sha, Publish::Auto, &not_cancelled()).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), data);
        assert_eq!(names(other_fs.path()), vec!["out.bin"]);
        assert!(!partial.exists());
    }

    fn set_age(path: &Path, now: SystemTime, by: Duration) {
        let file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        file.set_modified(now - by).unwrap();
    }

    #[test]
    fn stale_partials_are_swept_together_and_nothing_else_is() {
        let dir = tempfile::tempdir().unwrap();
        let transfers = dir.path().join(TRANSFERS_DIR);
        create_transfers_dir(&transfers).unwrap();
        let now = SystemTime::now();
        let day = Duration::from_secs(24 * 60 * 60);
        let max_age = 7 * day;
        let make = |name: String, old: Duration| {
            let p = transfers.join(name);
            std::fs::write(&p, b"x").unwrap();
            set_age(&p, now, old);
        };
        let (stale, fresh, mixed, orphan) =
            ("0".repeat(32), "1".repeat(32), "2".repeat(32), "3".repeat(32));
        make(format!("{stale}.kdxdata"), 8 * day);
        make(format!("{stale}.kdxpart"), 8 * day);
        make(format!(".{stale}.kdxpart.tmp-{}", "f".repeat(32)), 9 * day);
        make(format!("{fresh}.kdxdata"), day);
        make(format!("{fresh}.kdxpart"), day);
        // Old data, but its sidecar was just rewritten: still in use.
        make(format!("{mixed}.kdxdata"), 30 * day);
        make(format!("{mixed}.kdxpart"), Duration::ZERO);
        make(format!("{orphan}.kdxpart"), 8 * day);
        // Not ours: never touched, however old.
        let foreign = [
            "notes.txt".to_string(),
            format!("{}.kdxdata", "A".repeat(32)),
            "short.kdxdata".to_string(),
            format!(".{stale}.kdxpart.tmp-x"),
        ];
        for name in &foreign {
            make(name.clone(), 100 * day);
        }
        std::fs::create_dir(transfers.join(format!("{}.kdxdata", "4".repeat(32)))).unwrap();

        assert_eq!(sweep_stale_partials(&transfers, max_age, now).unwrap(), 2);
        let mut want = vec![
            format!("{fresh}.kdxdata"),
            format!("{fresh}.kdxpart"),
            format!("{mixed}.kdxdata"),
            format!("{mixed}.kdxpart"),
            format!("{}.kdxdata", "4".repeat(32)),
        ];
        want.extend(foreign);
        want.sort();
        assert_eq!(names(&transfers), want);
        // A missing directory is not an error.
        assert_eq!(sweep_stale_partials(&dir.path().join("nope"), max_age, now).unwrap(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn the_transfers_dir_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let transfers = dir.path().join("data").join(TRANSFERS_DIR);
        create_transfers_dir(&transfers).unwrap();
        create_transfers_dir(&transfers).unwrap(); // idempotent
        let mode = std::fs::metadata(&transfers).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}
