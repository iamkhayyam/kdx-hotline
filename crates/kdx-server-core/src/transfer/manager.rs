//! Server-side upload handling with resume.
//!
//! An upload's durable state is a `transfer_state` row (destination, sizes,
//! expected hash, received-chunk bitmap) plus a temp file of the bytes so
//! far. The bitmap is persisted in batches (every
//! [`TransferLimits::bitmap_flush_chunks`] new chunks or
//! [`TransferLimits::bitmap_flush_interval`], and whenever a connection lets
//! go of the upload), so a crash loses at most one batch; on resume the
//! client is told exactly which chunks the server holds and sends only the
//! rest. Chunks are hash-checked individually on receipt and the whole file
//! is hash-verified before it enters the file tree.
//!
//! Live transfers are tracked in memory: a transfer id can be held by one
//! connection at a time, a destination name by one upload at a time, and
//! accounts and the server as a whole have concurrency caps. Every
//! [`ActiveUpload`] / [`ActiveDownload`](super::ActiveDownload) carries a
//! claim that is released when it is dropped. A sweeper (at startup and every
//! few minutes) deletes uploads abandoned for longer than
//! [`TransferLimits::stale_after`] and partial files no upload owns.
//!
//! Finishing an upload takes three steps that can't share one transaction:
//! file the entry in the tree, rename `<id>.part` to the blob `<id>`, delete
//! the transfer row. Whatever prefix of that survives a crash is repaired:
//! a resume of an upload whose entry is already filed goes on to finish it,
//! and at startup (before the sweeper runs) entries whose bytes are still a
//! partial file get them moved into place.
//!
//! Blobs no entry references (left by crashes before that repair existed,
//! or by a rename that outlived a database rollback) are moved into a
//! quarantine directory, [`QUARANTINE_DIR`], at startup — after the repair —
//! and daily; they are deleted once they have sat there for
//! [`TransferLimits::orphan_retention`].
//!
//! An upload into a folder its sender can't list (a drop box they don't
//! own) never learns whether its name was taken: it is stored under a free
//! variant of the name instead (see [`UploadDest::blind`]).

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitvec::prelude::*;
use kdx_storage::file_tree;
use kdx_storage::transfer_state::{self, TransferRow};
use kdx_storage::SqlitePool;
use sha2::{Digest, Sha256};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::throttle::{reserve_shared, wait_until, SharedBucket, TokenBucket};
use crate::auth::Session;
use crate::files::tree::{free_name, locate_blob};
use crate::files::{FileTree, Node, NodeKind, TreeError, UploadDest};

/// Chunk sizes a client may request.
pub const MIN_CHUNK: u32 = 4 * 1024;
pub const MAX_CHUNK: u32 = 256 * 1024;
/// Largest accepted file (sanity cap; adjust when real deployments need it).
pub const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024;
/// Most chunks a single transfer may span. Keeps a received-chunk bitmap at
/// or under 65,535 bytes, so it fits the wire format's u16 length and bounds
/// per-transfer memory and the `transfer_state` row. At the stock 32 KiB
/// chunk size that is just under 16 GiB.
pub const MAX_TOTAL_CHUNKS: u32 = 524_280;

/// How often the background sweeper looks for abandoned uploads.
const SWEEP_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Every this many sweeps (once a day) the sweeper also looks for orphaned
/// blobs.
const ORPHAN_SWEEP_EVERY: u32 = 144;

/// Directory inside `files_root` that orphaned blobs are moved into, as
/// `<uuid>.<unix seconds when quarantined>`. To restore one, move it back
/// to `files_root/<uuid>`.
pub const QUARANTINE_DIR: &str = ".orphaned";

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error(transparent)]
    Tree(#[from] TreeError),
    #[error("storage error: {0}")]
    Storage(#[from] kdx_storage::StorageError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid chunk size")]
    BadChunkSize,
    #[error("file too large")]
    TooLarge,
    #[error("unknown or foreign transfer id")]
    UnknownTransfer,
    #[error("resume parameters do not match the original transfer")]
    ResumeMismatch,
    #[error("chunk index out of range")]
    BadChunkIndex,
    #[error("chunk hash mismatch")]
    ChunkHashMismatch,
    #[error("chunk length does not match its position")]
    BadChunkLength,
    #[error("final file hash mismatch")]
    FileHashMismatch,
    #[error("that transfer is already in progress on another connection")]
    Busy,
    #[error("too many transfers in progress for this account")]
    TooManyTransfers,
    #[error("the server is handling too many transfers; try again later")]
    ServerBusy,
    #[error("not enough free space on the server")]
    InsufficientSpace,
}

impl TransferError {
    /// A server-side failure (database, disk) rather than something about
    /// the request. These are worth a log line, and their text must not
    /// reach the client.
    pub fn is_internal(&self) -> bool {
        matches!(
            self,
            TransferError::Storage(_)
                | TransferError::Io(_)
                | TransferError::Tree(TreeError::Storage(_) | TreeError::CorruptKind(_))
        )
    }

    /// Text safe to send to the client: internal failures become a generic
    /// message (log the error itself server-side).
    pub fn client_message(&self) -> String {
        if self.is_internal() {
            "internal server error".into()
        } else {
            self.to_string()
        }
    }
}

/// Server-wide transfer services: where files land and how fast transfers
/// may flow.
pub struct TransferConfig {
    /// Completed files are stored here as `<uuid>` blobs; partials as
    /// `<uuid>.part`. Created (mode 0700 on Unix) if missing and made
    /// absolute, so stored paths survive a change of working directory.
    pub files_root: PathBuf,
    /// Upload throttle per account (shared by all its uploads), bytes/sec.
    /// 0 = unlimited.
    pub max_upload_bytes_per_sec: u64,
    /// Download throttle per account (shared by all its downloads),
    /// bytes/sec. 0 = unlimited.
    pub max_download_bytes_per_sec: u64,
}

/// Caps on live and unfinished transfers. `Default` is what `kdxd` runs with.
#[derive(Debug, Clone)]
pub struct TransferLimits {
    /// Uploads one account may run at once, across all its connections.
    pub max_uploads_per_account: usize,
    /// Downloads one account may run at once, across all its connections.
    pub max_downloads_per_account: usize,
    /// Uploads plus downloads in progress server-wide.
    pub max_concurrent_transfers: usize,
    /// Unfinished (resumable) uploads one account may keep. Starting another
    /// discards the account's least recently used idle one.
    pub max_open_uploads_per_account: usize,
    /// Bytes that live uploads may still write, summed server-wide.
    pub max_reserved_bytes: u64,
    /// Free space to leave on the files volume beyond what live uploads may
    /// still write.
    pub min_free_space: u64,
    /// An unfinished upload untouched for this long is deleted.
    pub stale_after: Duration,
    /// Persist an upload's bitmap after this many newly received chunks...
    pub bitmap_flush_chunks: u32,
    /// ...or once this long has passed since the last save.
    pub bitmap_flush_interval: Duration,
    /// A blob moved into [`QUARANTINE_DIR`] is deleted by a later sweep
    /// once it has been there this long. `None` keeps quarantined blobs
    /// until someone removes them.
    pub orphan_retention: Option<Duration>,
}

/// Default for [`TransferLimits::orphan_retention`]: 30 days.
pub const DEFAULT_ORPHAN_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

impl Default for TransferLimits {
    fn default() -> Self {
        Self {
            max_uploads_per_account: 2,
            max_downloads_per_account: 4,
            max_concurrent_transfers: 64,
            max_open_uploads_per_account: 4,
            max_reserved_bytes: 64 * GIB,
            min_free_space: 256 * MIB,
            stale_after: Duration::from_secs(24 * 60 * 60),
            bitmap_flush_chunks: 256,
            bitmap_flush_interval: Duration::from_secs(1),
            orphan_retention: Some(DEFAULT_ORPHAN_RETENTION),
        }
    }
}

/// What one orphan-blob sweep did (see [`TransferManager::sweep_orphan_blobs`]).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OrphanSweep {
    /// Blobs moved into quarantine.
    pub quarantined: usize,
    /// Quarantined blobs deleted after their retention period.
    pub purged: usize,
}

pub struct TransferManager {
    shared: Arc<Shared>,
}

/// State shared between the manager, its sweeper task and the claims held by
/// live transfers.
struct Shared {
    pool: SqlitePool,
    /// Absolute.
    files_root: PathBuf,
    upload_rate: u64,
    download_rate: u64,
    limits: TransferLimits,
    live: Mutex<Live>,
}

#[derive(Default)]
struct Live {
    /// Transfer ids held right now: by a live upload, or by the sweeper while
    /// it deletes one. Anyone else asking for a held id gets `Busy`.
    held: HashSet<Uuid>,
    /// Names claimed by live uploads, per destination folder id.
    destinations: HashMap<String, HashSet<String>>,
    /// Live (uploads, downloads) per account id.
    per_account: HashMap<String, (usize, usize)>,
    /// Live uploads plus downloads.
    total: usize,
    /// Bytes live uploads may still write.
    reserved_bytes: u64,
    /// Per-account (upload, download) throttles. They outlive individual
    /// transfers, so reconnecting doesn't buy a fresh burst; the sweeper
    /// forgets idle ones (long since refilled).
    buckets: HashMap<String, (SharedBucket, SharedBucket)>,
}

enum ClaimKind {
    Upload {
        account_id: String,
        id: Uuid,
        /// (folder id, name) reserved for this upload; `None` for an upload
        /// already filed, whose entry holds the name.
        destination: Option<(String, String)>,
        bytes: u64,
    },
    Download {
        account_id: String,
    },
    /// The sweeper holding an id while it deletes it.
    Hold { id: Uuid },
}

/// Releases a transfer's place in [`Live`] when dropped.
pub(crate) struct Claim {
    shared: Arc<Shared>,
    kind: ClaimKind,
}

impl Drop for Claim {
    fn drop(&mut self) {
        let mut live = self.shared.live();
        match &self.kind {
            ClaimKind::Upload {
                account_id,
                id,
                destination,
                bytes,
            } => {
                live.held.remove(id);
                if let Some((parent, name)) = destination {
                    live.release_name(parent, name);
                }
                live.reserved_bytes = live.reserved_bytes.saturating_sub(*bytes);
                live.release_slot(account_id, |counts| &mut counts.0);
            }
            ClaimKind::Download { account_id } => {
                live.release_slot(account_id, |counts| &mut counts.1);
            }
            ClaimKind::Hold { id } => {
                live.held.remove(id);
            }
        }
    }
}

impl Live {
    fn is_reserved(&self, parent_id: &str, name: &str) -> bool {
        self.destinations
            .get(parent_id)
            .is_some_and(|names| names.contains(name))
    }

    fn reserve_name(&mut self, parent_id: &str, name: &str) {
        self.destinations
            .entry(parent_id.to_owned())
            .or_default()
            .insert(name.to_owned());
    }

    fn release_name(&mut self, parent_id: &str, name: &str) {
        if let Some(names) = self.destinations.get_mut(parent_id) {
            names.remove(name);
            if names.is_empty() {
                self.destinations.remove(parent_id);
            }
        }
    }

    fn release_slot(
        &mut self,
        account_id: &str,
        field: impl Fn(&mut (usize, usize)) -> &mut usize,
    ) {
        self.total = self.total.saturating_sub(1);
        if let Some(counts) = self.per_account.get_mut(account_id) {
            let n = field(counts);
            *n = n.saturating_sub(1);
            if *counts == (0, 0) {
                self.per_account.remove(account_id);
            }
        }
    }

    fn buckets_for(
        &mut self,
        account_id: &str,
        upload_rate: u64,
        download_rate: u64,
    ) -> &(SharedBucket, SharedBucket) {
        self.buckets
            .entry(account_id.to_owned())
            .or_insert_with(|| (TokenBucket::shared(upload_rate), TokenBucket::shared(download_rate)))
    }
}

/// One live upload, owned by its connection task. Dropping it saves its
/// progress (in the background) and then frees its slot, its transfer id
/// and its destination name.
pub struct ActiveUpload {
    id: Uuid,
    account_id: String,
    parent_id: String,
    name: String,
    /// The sender can't list the destination folder, so a taken name must
    /// never be refused (see [`UploadDest::blind`]): `name` is a free
    /// variant of the requested one, and `finish` picks another should it
    /// be taken by then.
    blind: bool,
    size: u64,
    chunk_size: u32,
    total_chunks: u32,
    expected_sha256: [u8; 32],
    bitmap: BitVec<u8, Lsb0>,
    /// Set bits in `bitmap`.
    received: u32,
    /// Chunks received since the bitmap was last saved.
    unsaved: u32,
    last_save: Instant,
    temp_path: PathBuf,
    /// `None` only once `finish` has taken it.
    file: Option<File>,
    throttle: SharedBucket,
    pool: SqlitePool,
    /// Taken by `Drop`.
    claim: Option<Claim>,
}

/// What the connection sends back in `TransferAccept`.
pub struct AcceptInfo {
    pub transfer_id: [u8; 16],
    pub chunk_size: u32,
    pub total_chunks: u32,
    pub size: u64,
    pub sha256: [u8; 32],
    pub have_bitmap: Vec<u8>,
}

/// Which name a new upload claim reserves in its destination folder.
enum Destination<'a> {
    /// Exactly `name`: `Exists` if another live upload holds it.
    Exact { parent: &'a str, name: &'a str },
    /// The first variant of `name` (see [`free_name`]), at most `budget`
    /// bytes long, that neither the tree (`taken`) nor another live upload
    /// holds.
    Free {
        parent: &'a str,
        name: &'a str,
        budget: usize,
        taken: &'a dyn Fn(&str) -> bool,
    },
    /// Nothing: the upload is already filed, and its entry holds the name.
    Filed,
}

/// Chunk count for `size` bytes, in u64 so absurd sizes can't wrap before
/// they are compared with [`MAX_TOTAL_CHUNKS`].
pub(crate) fn chunk_count(size: u64, chunk_size: u32) -> u64 {
    size.div_ceil(u64::from(chunk_size.max(1)))
}

/// Validate an upload's shape and return its chunk count.
fn check_upload_shape(size: u64, chunk_size: u32) -> Result<u32, TransferError> {
    if !(MIN_CHUNK..=MAX_CHUNK).contains(&chunk_size) {
        return Err(TransferError::BadChunkSize);
    }
    if size > MAX_FILE_SIZE {
        return Err(TransferError::TooLarge);
    }
    let chunks = chunk_count(size, chunk_size);
    if chunks > u64::from(MAX_TOTAL_CHUNKS) {
        // Too many chunks for one bitmap: the client must use bigger ones.
        return Err(TransferError::BadChunkSize);
    }
    Ok(chunks as u32)
}

impl TransferManager {
    pub async fn new(pool: SqlitePool, config: TransferConfig) -> Result<Self, TransferError> {
        Self::with_limits(pool, config, TransferLimits::default()).await
    }

    /// Like [`new`](Self::new) with explicit caps. Prepares `files_root`,
    /// sweeps leftovers from earlier runs, and starts the periodic sweeper.
    pub async fn with_limits(
        pool: SqlitePool,
        config: TransferConfig,
        limits: TransferLimits,
    ) -> Result<Self, TransferError> {
        let files_root = prepare_files_root(&config.files_root).await?;
        let shared = Arc::new(Shared {
            pool,
            files_root,
            upload_rate: config.max_upload_bytes_per_sec,
            download_rate: config.max_download_bytes_per_sec,
            limits,
            live: Mutex::new(Live::default()),
        });
        // Uploads a crash interrupted mid-finish are completed first, so the
        // sweep below doesn't mistake their partial files for orphans.
        shared.recover_interrupted_finishes().await;
        // Nothing is live yet, so whatever is stale or orphaned goes now.
        let removed = shared.sweep(shared.limits.stale_after).await;
        if removed > 0 {
            info!(removed, "discarded abandoned uploads");
        }
        // Blobs no entry references, last: the repair above has put back
        // whatever an interrupted finish left, so none of it looks orphaned.
        shared.sweep_orphan_blobs(SystemTime::now()).await.log();
        tokio::spawn(sweep_periodically(Arc::downgrade(&shared)));
        Ok(Self { shared })
    }

    /// Move blobs in `files_root` that no file entry references and no
    /// upload owns into [`QUARANTINE_DIR`], and delete quarantined blobs
    /// older than [`TransferLimits::orphan_retention`]. Runs on its own at
    /// startup and once a day. Conservative: only regular files named
    /// exactly like a blob (a lowercase hyphenated UUID) are candidates,
    /// symlinks are never followed, nothing outside `files_root` is
    /// touched, and if the file tree or the upload state can't be read
    /// nothing is moved.
    pub async fn sweep_orphan_blobs(&self) -> OrphanSweep {
        self.shared.sweep_orphan_blobs(SystemTime::now()).await
    }

    /// Configured download throttle in bytes/sec (0 = unlimited).
    pub(crate) fn download_rate(&self) -> u64 {
        self.shared.download_rate
    }

    /// Configured upload throttle in bytes/sec (0 = unlimited).
    pub(crate) fn upload_rate(&self) -> u64 {
        self.shared.upload_rate
    }

    /// The (absolute) directory blobs and partial uploads live in.
    pub fn files_root(&self) -> &Path {
        &self.shared.files_root
    }

    pub fn limits(&self) -> &TransferLimits {
        &self.shared.limits
    }

    /// Whether some connection (or the sweeper) currently holds transfer `id`.
    pub fn is_live(&self, id: Uuid) -> bool {
        self.shared.live().held.contains(&id)
    }

    /// Delete unfinished uploads untouched for `older_than` (and partial
    /// files no upload owns). Live transfers are left alone. Returns how many
    /// uploads / files were removed. Runs on its own periodically.
    pub async fn sweep_stale(&self, older_than: Duration) -> usize {
        self.shared.sweep(older_than).await
    }

    /// Begin (or resume) an upload into `path`/`name` for `session`.
    #[allow(clippy::too_many_arguments)] // mirrors the TransferRequest wire fields
    pub async fn begin_upload(
        &self,
        tree: &FileTree,
        session: &Session,
        path: &str,
        name: &str,
        size: u64,
        chunk_size: u32,
        sha256: [u8; 32],
        resume_id: Option<Uuid>,
    ) -> Result<(ActiveUpload, AcceptInfo), TransferError> {
        if let Some(resume_id) = resume_id {
            return self
                .resume_upload(tree, session, resume_id, size, chunk_size, sha256)
                .await;
        }

        let chunks = check_upload_shape(size, chunk_size)?;
        let dest = tree.prepare_upload(path, name, session).await?;

        let id = Uuid::new_v4();
        // Claim before touching the disk: the caps apply, the name is
        // reserved against other uploads, and the sweeper won't mistake the
        // new `.part` for an orphan. A blind upload whose name is taken (or
        // reserved) gets a free variant of it here, and the reply below
        // is the same either way.
        let (claim, throttle, name) = self
            .claim_into(tree, &session.account_id, id, &dest, name, size)
            .await?;
        self.shared.make_room_for(&session.account_id).await?;

        let temp_path = self.shared.files_root.join(format!("{id}.part"));
        let file = create_part(&temp_path, size).await?;
        let parent = dest.parent;
        let row = TransferRow {
            id: id.to_string(),
            account_id: session.account_id.clone(),
            parent_id: parent.id.clone(),
            name: name.clone(),
            size: size as i64,
            chunk_size: i64::from(chunk_size),
            sha256: sha256.to_vec(),
            bitmap: vec![0u8; (chunks as usize).div_ceil(8)],
            temp_path: temp_path.display().to_string(),
        };
        if let Err(e) = transfer_state::create(&self.shared.pool, &row).await {
            drop(file);
            remove_quietly(&temp_path).await;
            return Err(e.into());
        }
        debug!(%id, %name, size, blind = dest.blind, "upload started");

        let accept = AcceptInfo {
            transfer_id: *id.as_bytes(),
            chunk_size,
            total_chunks: chunks,
            size,
            sha256,
            have_bitmap: Vec::new(),
        };
        let upload = ActiveUpload {
            id,
            account_id: session.account_id.clone(),
            parent_id: parent.id,
            name,
            blind: dest.blind,
            size,
            chunk_size,
            total_chunks: chunks,
            expected_sha256: sha256,
            bitmap: bitvec![u8, Lsb0; 0; chunks as usize],
            received: 0,
            unsaved: 0,
            last_save: Instant::now(),
            temp_path,
            file: Some(file),
            throttle,
            pool: self.shared.pool.clone(),
            claim: Some(claim),
        };
        Ok((upload, accept))
    }

    async fn resume_upload(
        &self,
        tree: &FileTree,
        session: &Session,
        resume_id: Uuid,
        size: u64,
        chunk_size: u32,
        sha256: [u8; 32],
    ) -> Result<(ActiveUpload, AcceptInfo), TransferError> {
        let row = transfer_state::get(&self.shared.pool, &resume_id.to_string())
            .await?
            .ok_or(TransferError::UnknownTransfer)?;
        // Resumes must come from the same account and describe the same file.
        if row.account_id != session.account_id {
            return Err(TransferError::UnknownTransfer);
        }
        if row.size as u64 != size
            || row.chunk_size as u64 != u64::from(chunk_size)
            || row.sha256 != sha256
        {
            return Err(TransferError::ResumeMismatch);
        }
        let chunks = match check_upload_shape(size, chunk_size) {
            Ok(chunks) => chunks,
            Err(e) => {
                // A row from before the current caps: it can never complete.
                if let Some(_hold) = self.shared.hold(resume_id) {
                    self.shared.discard(&row.id, &row.temp_path).await;
                }
                return Err(e);
            }
        };

        let mut bitmap = BitVec::<u8, Lsb0>::from_vec(row.bitmap.clone());
        bitmap.resize(chunks as usize, false);
        let received = bitmap.count_ones() as u32;
        let remaining = size.saturating_sub(u64::from(received) * u64::from(chunk_size));

        // An upload whose entry an interrupted `finish` already filed (the
        // bytes are still the partial file) resumes straight into finishing:
        // it passed every check when it was filed. Anything else
        // re-validates its destination exactly as a fresh upload would,
        // wherever that folder is now: since the upload began the account
        // may have lost write access, or the folder may be gone or the name
        // taken. Such an upload can never be filed, so it is discarded. (A
        // blind upload's name is never "taken": it moves on to a free
        // variant instead.)
        let filed = tree
            .find_child(&row.parent_id, |node| is_filed_upload(node, &row.id, &row.sha256))
            .await
            .is_some();
        let dest = if filed {
            None
        } else {
            match tree.prepare_upload_into(&row.parent_id, &row.name, session).await {
                Ok(dest) => Some(dest),
                Err(e) => {
                    // Hold it first: if another connection has this
                    // transfer, leave it (and its row) alone.
                    let Some(_hold) = self.shared.hold(resume_id) else {
                        return Err(TransferError::Busy);
                    };
                    debug!(id = %resume_id, error = %e, "resume refused; discarding upload");
                    self.shared.discard(&row.id, &row.temp_path).await;
                    return Err(e.into());
                }
            }
        };
        // `Busy` if another connection holds this transfer.
        let (claim, throttle, name) = match &dest {
            Some(dest) => {
                self.claim_into(tree, &session.account_id, resume_id, dest, &row.name, remaining)
                    .await?
            }
            None => {
                let (claim, throttle, _) = self.shared.claim_upload(
                    &session.account_id,
                    resume_id,
                    Destination::Filed,
                    remaining,
                )?;
                (claim, throttle, row.name.clone())
            }
        };
        if name != row.name {
            // A blind upload's name was taken while it was paused: it is now
            // headed for a free variant, which the row records too.
            debug!(id = %resume_id, from = %row.name, to = %name, "resumed upload renamed");
            if let Err(e) = transfer_state::set_name(&self.shared.pool, &row.id, &name).await {
                warn!(id = %resume_id, error = %e, "could not record a resumed upload's new name");
            }
        }

        let temp_path = self.shared.locate(&row.temp_path).await;
        let file = match open_part(&temp_path, size).await {
            Ok(file) => file,
            Err(e) => {
                warn!(id = %resume_id, error = %e, "partial upload unusable; discarding it");
                self.shared.discard(&row.id, &row.temp_path).await;
                return Err(e.into());
            }
        };
        if let Err(e) = transfer_state::touch(&self.shared.pool, &row.id).await {
            warn!(id = %resume_id, error = %e, "could not refresh upload expiry");
        }
        debug!(%resume_id, have = received, total = chunks, "upload resumed");

        let accept = AcceptInfo {
            transfer_id: *resume_id.as_bytes(),
            chunk_size,
            total_chunks: chunks,
            size,
            sha256,
            have_bitmap: bitmap.clone().into_vec(),
        };
        let upload = ActiveUpload {
            id: resume_id,
            account_id: row.account_id,
            parent_id: row.parent_id,
            name,
            blind: dest.as_ref().is_some_and(|dest| dest.blind),
            size,
            chunk_size,
            total_chunks: chunks,
            expected_sha256: sha256,
            bitmap,
            received,
            unsaved: 0,
            last_save: Instant::now(),
            temp_path,
            file: Some(file),
            throttle,
            pool: self.shared.pool.clone(),
            claim: Some(claim),
        };
        Ok((upload, accept))
    }

    /// Claim an upload slot for transfer `id` headed for `name` in `dest`'s
    /// folder, reserving the name against other uploads: exactly `name`
    /// (`Exists` if another upload holds it), or for a blind upload the
    /// first free variant of it — picked and reserved in one step, while
    /// nothing can be filed in the folder, so concurrent blind uploads of
    /// one name get distinct names. Returns the name reserved.
    async fn claim_into(
        &self,
        tree: &FileTree,
        account_id: &str,
        id: Uuid,
        dest: &UploadDest,
        name: &str,
        bytes: u64,
    ) -> Result<(Claim, SharedBucket, String), TransferError> {
        let parent = dest.parent.id.as_str();
        let (claim, throttle, reserved) = if dest.blind {
            tree.with_entry_names(parent, |taken| {
                let destination = Destination::Free {
                    parent,
                    name,
                    budget: dest.name_budget,
                    taken,
                };
                self.shared.claim_upload(account_id, id, destination, bytes)
            })
            .await?
        } else {
            let destination = Destination::Exact { parent, name };
            self.shared.claim_upload(account_id, id, destination, bytes)?
        };
        Ok((claim, throttle, reserved.unwrap_or_else(|| name.to_owned())))
    }

    /// Accept one chunk: throttle, verify its hash, write it at its offset,
    /// and save the bitmap when a batch is due. Returns `true` when every
    /// chunk has arrived.
    pub async fn write_chunk(
        &self,
        upload: &mut ActiveUpload,
        chunk_index: u32,
        chunk_hash: &[u8; 32],
        data: &[u8],
    ) -> Result<bool, TransferError> {
        // Charge every chunk the client sends, accepted or not: rejected
        // chunks cost hashing too, and must not bypass the rate limit.
        wait_until(reserve_shared(&upload.throttle, data.len())).await;

        if chunk_index >= upload.total_chunks {
            return Err(TransferError::BadChunkIndex);
        }
        let expected_len = upload.expected_chunk_len(chunk_index);
        if data.len() != expected_len {
            return Err(TransferError::BadChunkLength);
        }
        let actual: [u8; 32] = Sha256::digest(data).into();
        if &actual != chunk_hash {
            return Err(TransferError::ChunkHashMismatch);
        }

        let index = chunk_index as usize;
        if upload.bitmap[index] {
            // Already have it (a resend): nothing to write.
            return Ok(upload.is_complete());
        }
        let offset = u64::from(chunk_index) * u64::from(upload.chunk_size);
        let file = upload.file.as_mut().expect("file present until finish");
        file.seek(SeekFrom::Start(offset)).await?;
        file.write_all(data).await?;
        // Surface a failed write on this chunk, before it is marked received.
        file.flush().await?;

        upload.bitmap.set(index, true);
        upload.received += 1;
        upload.unsaved += 1;
        let limits = &self.shared.limits;
        if !upload.is_complete()
            && (upload.unsaved >= limits.bitmap_flush_chunks
                || upload.last_save.elapsed() >= limits.bitmap_flush_interval)
        {
            upload.save_bitmap().await?;
        }
        Ok(upload.is_complete())
    }

    /// Verify the whole file and promote it into the tree. Consumes the
    /// upload. A failure about the upload itself destroys the partial
    /// state: on a hash mismatch the client's source differs from what it
    /// announced, and if the destination is gone or its name was taken the
    /// file has nowhere to go — either way the client must start over. A
    /// server-side failure after verification (the database busy, the
    /// bytes impossible to move into place) keeps the verified upload
    /// resumable instead; resuming it finishes it.
    pub async fn finish(
        &self,
        tree: &FileTree,
        mut upload: ActiveUpload,
    ) -> Result<(), TransferError> {
        let id = upload.id;
        // The hash pass below can take minutes for a big file; save progress
        // first so a crash meanwhile resumes straight into finishing.
        if upload.unsaved > 0 {
            if let Err(e) = upload.save_bitmap().await {
                warn!(%id, error = %e, "could not save upload progress before verifying");
            }
        }
        let file = upload.file.take().expect("file present until finish");
        let actual = match hash_file(file).await {
            Ok(hash) => hash,
            Err(e) => {
                self.discard_upload(&mut upload).await;
                return Err(e.into());
            }
        };
        if actual != upload.expected_sha256 {
            self.discard_upload(&mut upload).await;
            return Err(TransferError::FileHashMismatch);
        }

        // File it in the tree first: a name taken or a folder deleted since
        // the upload began is caught here, while the bytes are still a
        // disposable partial rather than an unreferenced blob. (A blind
        // upload whose name was taken is filed under a free variant.)
        let final_path = self.shared.files_root.join(id.to_string());
        let stored = final_path.display().to_string();
        let id_str = id.to_string();
        let sha = upload.expected_sha256;
        let added = match tree
            .find_child(&upload.parent_id, |node| is_filed_upload(node, &id_str, &sha))
            .await
        {
            // Filed by an earlier `finish` of this very upload that never
            // got to move the bytes (a crash, or a failed rename whose undo
            // failed too): complete that job. Nobody else files this blob:
            // this upload's id is held until it is done.
            Some(node) => Ok(node),
            None if upload.blind => {
                let parent = upload.parent_id.as_str();
                let reserved = |name: &str| self.shared.live().is_reserved(parent, name);
                tree.add_file_renaming(parent, &upload.name, upload.size, &sha, &stored, &reserved)
                    .await
            }
            None => {
                tree.add_file(&upload.parent_id, &upload.name, upload.size, &sha, &stored)
                    .await
            }
        };
        let node = match added {
            Ok(node) => node,
            Err(e @ TreeError::Storage(_)) => {
                // The database is busy or unreachable: nothing about the
                // upload is wrong, so keep it (verified, every chunk
                // present) for the client to resume.
                warn!(%id, error = %e, "verified upload could not be filed yet; keeping it resumable");
                self.release(upload).await;
                return Err(e.into());
            }
            Err(e) => {
                debug!(%id, error = %e, "verified upload could not be filed; discarding it");
                self.discard_upload(&mut upload).await;
                return Err(e.into());
            }
        };
        if let Err(e) = tokio::fs::rename(&upload.temp_path, &final_path).await {
            error!(
                %id,
                error = %e,
                path = %final_path.display(),
                "upload was filed but its bytes could not be moved into place; keeping it resumable"
            );
            // Withdraw the entry so the tree doesn't list a file without
            // bytes. Should that fail too, the resume (or the next startup)
            // moves the bytes into place instead.
            if let Err(undo) = tree.remove_file_node(&node.id).await {
                error!(%id, error = %undo, "could not withdraw the entry of an upload without bytes");
            }
            self.release(upload).await;
            return Err(e.into());
        }
        // The entry is committed; make the rename that backs it durable too.
        sync_dir(&self.shared.files_root).await;
        if let Err(e) = transfer_state::delete(&self.shared.pool, &id.to_string()).await {
            // Harmless: the sweeper drops the stale row later.
            warn!(%id, error = %e, "could not delete finished upload's state");
        }
        debug!(%id, name = %node.name, "upload verified and filed");
        Ok(())
    }

    /// Destroy an upload's durable state and partial bytes.
    pub async fn abort(&self, mut upload: ActiveUpload) {
        self.discard_upload(&mut upload).await;
    }

    /// Let go of a live upload but keep it resumable: save its progress,
    /// then free its slot (e.g. the client ended the transfer early).
    pub async fn release(&self, mut upload: ActiveUpload) {
        if upload.unsaved > 0 {
            if let Err(e) = upload.save_bitmap().await {
                warn!(id = %upload.id, error = %e, "could not save upload progress");
                upload.unsaved = 0;
            }
        }
    }

    async fn discard_upload(&self, upload: &mut ActiveUpload) {
        upload.unsaved = 0; // nothing left worth saving on drop
        upload.file = None;
        self.shared
            .discard(&upload.id.to_string(), &upload.temp_path.display().to_string())
            .await;
    }

    /// Claim a download slot for `account_id`; the claim and throttle go
    /// into the `ActiveDownload`.
    pub(crate) fn claim_download(
        &self,
        account_id: &str,
    ) -> Result<(Claim, SharedBucket), TransferError> {
        self.shared.claim_download(account_id)
    }

    /// Where a stored blob / partial path points now (see [`Shared::locate`]).
    pub(crate) async fn locate(&self, stored: &str) -> PathBuf {
        self.shared.locate(stored).await
    }
}

impl Shared {
    fn live(&self) -> MutexGuard<'_, Live> {
        self.live.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Claim an upload slot for transfer `id`, reserving the name
    /// `destination` calls for. Returns the claim, the account's upload
    /// throttle, and the name reserved (`None` for [`Destination::Filed`]).
    fn claim_upload(
        self: &Arc<Self>,
        account_id: &str,
        id: Uuid,
        destination: Destination<'_>,
        bytes: u64,
    ) -> Result<(Claim, SharedBucket, Option<String>), TransferError> {
        let available = available_space(&self.files_root);
        let mut live = self.live();
        if live.held.contains(&id) {
            return Err(TransferError::Busy);
        }
        let uploads = live.per_account.get(account_id).map_or(0, |c| c.0);
        if uploads >= self.limits.max_uploads_per_account {
            return Err(TransferError::TooManyTransfers);
        }
        if live.total >= self.limits.max_concurrent_transfers {
            return Err(TransferError::ServerBusy);
        }
        let destination = match destination {
            Destination::Exact { parent, name } => {
                if live.is_reserved(parent, name) {
                    // Another upload is already headed for this name.
                    return Err(TransferError::Tree(TreeError::Exists));
                }
                Some((parent.to_owned(), name.to_owned()))
            }
            Destination::Free {
                parent,
                name,
                budget,
                taken,
            } => {
                let free = free_name(name, budget, |c| taken(c) || live.is_reserved(parent, c))
                    // Unreachable for a budget `prepare_upload` accepts.
                    .ok_or(TransferError::Tree(TreeError::InvalidPath("path is too long")))?;
                Some((parent.to_owned(), free))
            }
            Destination::Filed => None,
        };
        let reserved = live.reserved_bytes.saturating_add(bytes);
        if reserved > self.limits.max_reserved_bytes {
            return Err(TransferError::InsufficientSpace);
        }
        if let Some(available) = available {
            if available < reserved.saturating_add(self.limits.min_free_space) {
                return Err(TransferError::InsufficientSpace);
            }
        }

        live.held.insert(id);
        if let Some((parent, name)) = &destination {
            live.reserve_name(parent, name);
        }
        live.reserved_bytes = reserved;
        live.per_account.entry(account_id.to_owned()).or_default().0 += 1;
        live.total += 1;
        let bucket = live
            .buckets_for(account_id, self.upload_rate, self.download_rate)
            .0
            .clone();
        let name = destination.as_ref().map(|(_, name)| name.clone());
        let claim = Claim {
            shared: self.clone(),
            kind: ClaimKind::Upload {
                account_id: account_id.to_owned(),
                id,
                destination,
                bytes,
            },
        };
        Ok((claim, bucket, name))
    }

    fn claim_download(
        self: &Arc<Self>,
        account_id: &str,
    ) -> Result<(Claim, SharedBucket), TransferError> {
        let mut live = self.live();
        let downloads = live.per_account.get(account_id).map_or(0, |c| c.1);
        if downloads >= self.limits.max_downloads_per_account {
            return Err(TransferError::TooManyTransfers);
        }
        if live.total >= self.limits.max_concurrent_transfers {
            return Err(TransferError::ServerBusy);
        }
        live.per_account.entry(account_id.to_owned()).or_default().1 += 1;
        live.total += 1;
        let bucket = live
            .buckets_for(account_id, self.upload_rate, self.download_rate)
            .1
            .clone();
        let claim = Claim {
            shared: self.clone(),
            kind: ClaimKind::Download {
                account_id: account_id.to_owned(),
            },
        };
        Ok((claim, bucket))
    }

    /// Hold transfer `id` so nobody resumes it while it's being deleted.
    /// `None` if someone already holds it.
    fn hold(self: &Arc<Self>, id: Uuid) -> Option<Claim> {
        let mut live = self.live();
        if !live.held.insert(id) {
            return None;
        }
        Some(Claim {
            shared: self.clone(),
            kind: ClaimKind::Hold { id },
        })
    }

    /// Delete a transfer row and its partial file. Callers hold the id.
    async fn discard(&self, id: &str, temp_path: &str) {
        if let Err(e) = transfer_state::delete(&self.pool, id).await {
            warn!(%id, error = %e, "could not delete upload state");
        }
        remove_quietly(&self.locate(temp_path).await).await;
    }

    /// Resolve a path stored in the database. Rows written before
    /// `files_root` was made absolute hold paths relative to whatever
    /// directory kdxd ran in back then; blobs and partials always live
    /// directly in `files_root`, so fall back to looking there by name.
    async fn locate(&self, stored: &str) -> PathBuf {
        locate_blob(&self.files_root, stored).await
    }

    /// Repair what a crash or power loss in the middle of `finish` left
    /// behind (see the module docs), before anything is swept:
    /// - an entry is filed but its bytes are still `<id>.part` (whether or
    ///   not the row survived): move them into place, drop the row;
    /// - an entry is filed and its bytes are in place, but the row
    ///   survived: drop the row;
    /// - the entry was lost but the rename survived (a row whose partial is
    ///   missing, a blob `<id>` no entry names): turn the blob back into the
    ///   partial, so the client's resume files it again.
    async fn recover_interrupted_finishes(&self) {
        let nodes = match file_tree::all(&self.pool).await {
            Ok(nodes) => nodes,
            Err(e) => {
                warn!(error = %e, "upload recovery: cannot read the file tree");
                return;
            }
        };
        // Blobs are named after the upload that produced them: upload id ->
        // stored path of the entry it was filed as.
        let file_kind = i64::from(NodeKind::File.as_u8());
        let filed: HashMap<String, String> = nodes
            .into_iter()
            .filter(|n| n.kind == file_kind)
            .filter_map(|n| {
                let stored = n.storage_path?;
                let blob = Path::new(&stored).file_name()?.to_str()?.to_owned();
                Some((blob, stored))
            })
            .collect();
        let rows = match transfer_state::list_stale(&self.pool, 0).await {
            Ok(rows) => rows,
            Err(e) => {
                warn!(error = %e, "upload recovery: cannot list uploads");
                return;
            }
        };

        let mut with_rows = HashSet::new();
        for row in rows {
            let Ok(id) = Uuid::parse_str(&row.id) else {
                continue;
            };
            with_rows.insert(id);
            let part = self.locate(&row.temp_path).await;
            if let Some(stored) = filed.get(&row.id) {
                if self.move_into_place(id, &part, stored).await {
                    if let Err(e) = transfer_state::delete(&self.pool, &row.id).await {
                        warn!(%id, error = %e, "upload recovery: could not delete a finished upload's state");
                    }
                }
                continue;
            }
            let blob = self.files_root.join(id.to_string());
            if !exists(&part).await && exists(&blob).await {
                match tokio::fs::rename(&blob, &part).await {
                    Ok(()) => {
                        sync_dir(&self.files_root).await;
                        info!(%id, "upload recovery: an unfiled upload's bytes are resumable again");
                    }
                    Err(e) => error!(
                        %id,
                        error = %e,
                        "upload recovery: could not restore an unfiled upload's partial file"
                    ),
                }
            }
        }

        // Partial files whose row is already gone but whose entry is filed.
        let mut dir = match tokio::fs::read_dir(&self.files_root).await {
            Ok(dir) => dir,
            Err(e) => {
                warn!(error = %e, "upload recovery: cannot list files_root");
                return;
            }
        };
        while let Ok(Some(entry)) = dir.next_entry().await {
            let name = entry.file_name();
            let Some(id) = name
                .to_str()
                .and_then(|n| n.strip_suffix(".part"))
                .and_then(|n| Uuid::parse_str(n).ok())
            else {
                continue;
            };
            if with_rows.contains(&id) {
                continue;
            }
            if let Some(stored) = filed.get(&id.to_string()) {
                self.move_into_place(id, &entry.path(), stored).await;
            }
        }
    }

    /// Make sure filed upload `id`'s bytes are where its entry (`stored`)
    /// points, renaming its partial file `part` there if they are not.
    /// Returns whether they are in place afterwards.
    async fn move_into_place(&self, id: Uuid, part: &Path, stored: &str) -> bool {
        let blob = self.locate(stored).await;
        if exists(&blob).await {
            return true; // a leftover partial, if any, is an orphan now
        }
        if !exists(part).await {
            warn!(%id, path = %blob.display(), "upload recovery: a filed upload's bytes are missing");
            return false;
        }
        match tokio::fs::rename(part, &blob).await {
            Ok(()) => {
                sync_dir(&self.files_root).await;
                info!(%id, "upload recovery: an interrupted upload was finished");
                true
            }
            Err(e) => {
                error!(
                    %id,
                    error = %e,
                    path = %blob.display(),
                    "upload recovery: could not move a filed upload's bytes into place"
                );
                false
            }
        }
    }

    /// Keep an account under `max_open_uploads_per_account` unfinished
    /// uploads (counting the one about to be created) by discarding its
    /// least recently used idle ones.
    async fn make_room_for(self: &Arc<Self>, account_id: &str) -> Result<(), TransferError> {
        let cap = self.limits.max_open_uploads_per_account.max(1);
        let rows = transfer_state::list_for_account(&self.pool, account_id).await?;
        let mut excess = (rows.len() + 1).saturating_sub(cap);
        for row in rows {
            if excess == 0 {
                break;
            }
            let Ok(id) = Uuid::parse_str(&row.id) else {
                continue;
            };
            let Some(_hold) = self.hold(id) else {
                continue; // live on some connection
            };
            debug!(%id, account_id, "discarding the account's oldest unfinished upload");
            self.discard(&row.id, &row.temp_path).await;
            excess -= 1;
        }
        if excess > 0 {
            return Err(TransferError::TooManyTransfers);
        }
        Ok(())
    }

    async fn sweep(self: &Arc<Self>, older_than: Duration) -> usize {
        let mut removed = 0;
        match transfer_state::list_stale(&self.pool, older_than.as_secs()).await {
            Ok(rows) => {
                for row in rows {
                    // An unparsable id can't be live; delete it regardless.
                    let _hold = match Uuid::parse_str(&row.id) {
                        Ok(id) => match self.hold(id) {
                            Some(hold) => Some(hold),
                            None => continue, // live: leave it
                        },
                        Err(_) => None,
                    };
                    self.discard(&row.id, &row.temp_path).await;
                    removed += 1;
                }
            }
            Err(e) => warn!(error = %e, "upload sweep: listing stale uploads failed"),
        }
        removed += self.sweep_orphan_parts().await;
        // Forget throttles no transfer is using; they have long refilled.
        self.live().buckets.retain(|_, (up, down)| {
            Arc::strong_count(up) > 1 || Arc::strong_count(down) > 1
        });
        removed
    }

    /// Remove `<uuid>.part` files that no upload row owns (left behind by a
    /// crash, or by older versions when pre-sizing failed).
    async fn sweep_orphan_parts(self: &Arc<Self>) -> usize {
        let mut dir = match tokio::fs::read_dir(&self.files_root).await {
            Ok(dir) => dir,
            Err(e) => {
                warn!(error = %e, "upload sweep: cannot list files_root");
                return 0;
            }
        };
        let mut removed = 0;
        while let Ok(Some(entry)) = dir.next_entry().await {
            let name = entry.file_name();
            let Some(id) = name
                .to_str()
                .and_then(|n| n.strip_suffix(".part"))
                .and_then(|n| Uuid::parse_str(n).ok())
            else {
                continue;
            };
            // Held means live (being created, written or finished).
            let Some(_hold) = self.hold(id) else {
                continue;
            };
            match transfer_state::get(&self.pool, &id.to_string()).await {
                Ok(None) => {
                    if tokio::fs::remove_file(entry.path()).await.is_ok() {
                        removed += 1;
                    }
                }
                Ok(Some(_)) => {}
                Err(e) => {
                    warn!(error = %e, "upload sweep: lookup failed");
                    break;
                }
            }
        }
        removed
    }

    /// See [`TransferManager::sweep_orphan_blobs`]; `now` dates the
    /// quarantine and measures retention.
    async fn sweep_orphan_blobs(self: &Arc<Self>, now: SystemTime) -> OrphanSweep {
        let now = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let quarantined = self.quarantine_orphan_blobs(now).await;
        let purged = match self.limits.orphan_retention {
            Some(retention) => self.purge_quarantine(now, retention).await,
            None => 0,
        };
        OrphanSweep {
            quarantined,
            purged,
        }
    }

    /// Move every blob in `files_root` that no file entry references and
    /// no upload owns into the quarantine directory, stamped with `now`
    /// (unix seconds). Returns how many were moved.
    async fn quarantine_orphan_blobs(self: &Arc<Self>, now: u64) -> usize {
        // Candidates: regular files (a symlink is judged as itself, never
        // followed) named exactly like a blob. Anything else isn't ours.
        let mut dir = match tokio::fs::read_dir(&self.files_root).await {
            Ok(dir) => dir,
            Err(e) => {
                warn!(error = %e, "orphan sweep: cannot list files_root");
                return 0;
            }
        };
        let mut candidates = Vec::new();
        loop {
            let entry = match dir.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(e) => {
                    warn!(error = %e, "orphan sweep: cannot list files_root");
                    return 0;
                }
            };
            let Some(id) = blob_id(&entry.file_name()) else {
                continue;
            };
            if entry.file_type().await.is_ok_and(|t| t.is_file()) {
                candidates.push(id);
            }
        }
        if candidates.is_empty() {
            return 0;
        }

        // Hold each id: one held already belongs to a live upload (perhaps
        // being filed right now) and is left alone, and none of the others
        // can be filed until the sweep is done. Only then read what the
        // tree references — so an upload filed after the listing above is
        // seen — and which uploads are unfinished.
        let mut holds = Vec::with_capacity(candidates.len());
        candidates.retain(|id| match self.hold(*id) {
            Some(hold) => {
                holds.push(hold);
                true
            }
            None => false,
        });
        let Some(referenced) = self.referenced_blobs().await else {
            return 0;
        };
        let unfinished: HashSet<String> = match transfer_state::all_ids(&self.pool).await {
            Ok(ids) => ids.into_iter().collect(),
            Err(e) => {
                warn!(error = %e, "orphan sweep: cannot list unfinished uploads");
                return 0;
            }
        };
        let orphans: Vec<String> = candidates
            .iter()
            .map(Uuid::to_string)
            .filter(|name| !referenced.contains(name) && !unfinished.contains(name))
            .collect();
        if orphans.is_empty() {
            return 0;
        }

        let Some(quarantine) = self.quarantine_dir(true).await else {
            return 0;
        };
        let mut moved = 0;
        for name in orphans {
            let from = self.files_root.join(&name);
            // Still a regular file right before the move.
            if !tokio::fs::symlink_metadata(&from)
                .await
                .is_ok_and(|meta| meta.file_type().is_file())
            {
                continue;
            }
            let to = quarantine.join(format!("{name}.{now}"));
            if tokio::fs::symlink_metadata(&to).await.is_ok() {
                warn!(blob = %name, to = %to.display(), "orphan sweep: quarantine name in use; leaving the blob in place");
                continue;
            }
            match tokio::fs::rename(&from, &to).await {
                Ok(()) => {
                    warn!(
                        blob = %name,
                        to = %to.display(),
                        "quarantined a blob that no file entry references"
                    );
                    moved += 1;
                }
                Err(e) => {
                    warn!(blob = %name, error = %e, "orphan sweep: could not quarantine a blob");
                }
            }
        }
        if moved > 0 {
            sync_dir(&self.files_root).await;
            sync_dir(&quarantine).await;
        }
        drop(holds);
        moved
    }

    /// The blob names file entries refer to: the last component of every
    /// stored path (downloads fall back to `files_root/<that name>`, see
    /// [`locate_blob`]), plus, for a stored path elsewhere that resolves
    /// into `files_root` (through a symlink, say), the name it resolves
    /// to. `None` if the tree can't be read.
    async fn referenced_blobs(&self) -> Option<HashSet<String>> {
        let nodes = match file_tree::all(&self.pool).await {
            Ok(nodes) => nodes,
            Err(e) => {
                warn!(error = %e, "orphan sweep: cannot read the file tree");
                return None;
            }
        };
        let mut names = HashSet::new();
        let file_name = |path: &Path| path.file_name()?.to_str().map(str::to_owned);
        for stored in nodes.into_iter().filter_map(|node| node.storage_path) {
            let path = Path::new(&stored);
            names.extend(file_name(path));
            if path.parent() == Some(self.files_root.as_path()) {
                continue;
            }
            if let Ok(real) = tokio::fs::canonicalize(path).await {
                if real.parent() == Some(self.files_root.as_path()) {
                    names.extend(file_name(&real));
                }
            }
        }
        Some(names)
    }

    /// Delete quarantined blobs stamped at least `retention` before `now`
    /// (unix seconds). Entries not named like a quarantined blob, and
    /// anything but regular files, are left alone. Returns how many went.
    async fn purge_quarantine(&self, now: u64, retention: Duration) -> usize {
        let Some(quarantine) = self.quarantine_dir(false).await else {
            return 0;
        };
        let mut dir = match tokio::fs::read_dir(&quarantine).await {
            Ok(dir) => dir,
            Err(e) => {
                warn!(error = %e, "orphan sweep: cannot list the quarantine");
                return 0;
            }
        };
        let mut purged = 0;
        loop {
            let entry = match dir.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(e) => {
                    warn!(error = %e, "orphan sweep: cannot list the quarantine");
                    break;
                }
            };
            let Some(stamp) = quarantined_at(&entry.file_name()) else {
                continue;
            };
            if now.saturating_sub(stamp) < retention.as_secs() {
                continue;
            }
            if !entry.file_type().await.is_ok_and(|t| t.is_file()) {
                continue;
            }
            let path = entry.path();
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {
                    info!(path = %path.display(), "deleted a quarantined orphan blob past its retention");
                    purged += 1;
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "orphan sweep: could not delete a quarantined blob");
                }
            }
        }
        purged
    }

    /// `files_root/QUARANTINE_DIR`, if it is a real directory (not a
    /// symlink); created (owner-only on Unix) when `create` and missing.
    async fn quarantine_dir(&self, create: bool) -> Option<PathBuf> {
        let dir = self.files_root.join(QUARANTINE_DIR);
        let is_real_dir = |meta: &std::fs::Metadata| meta.file_type().is_dir();
        match tokio::fs::symlink_metadata(&dir).await {
            Ok(meta) if is_real_dir(&meta) => return Some(dir),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !create {
                    return None;
                }
            }
            Ok(_) => {
                warn!(path = %dir.display(), "orphan sweep: the quarantine is not a directory; leaving orphans in place");
                return None;
            }
            Err(e) => {
                warn!(path = %dir.display(), error = %e, "orphan sweep: cannot inspect the quarantine");
                return None;
            }
        }
        let mut builder = tokio::fs::DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        match builder.create(&dir).await {
            Ok(()) => Some(dir),
            // Created meanwhile: use it only if it's a real directory.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let meta = tokio::fs::symlink_metadata(&dir).await.ok()?;
                is_real_dir(&meta).then_some(dir)
            }
            Err(e) => {
                warn!(path = %dir.display(), error = %e, "orphan sweep: cannot create the quarantine");
                None
            }
        }
    }
}

impl OrphanSweep {
    fn log(self) {
        if self.quarantined > 0 || self.purged > 0 {
            info!(
                quarantined = self.quarantined,
                purged = self.purged,
                quarantine = QUARANTINE_DIR,
                "swept orphaned blobs"
            );
        }
    }
}

/// The upload id a blob in `files_root` is named after: `name` must be
/// exactly a lowercase hyphenated UUID, the only names `finish` gives blobs.
fn blob_id(name: &OsStr) -> Option<Uuid> {
    let name = name.to_str()?;
    let id = Uuid::parse_str(name).ok()?;
    (id.to_string() == name).then_some(id)
}

/// When a quarantined blob, named `<uuid>.<unix seconds>`, was quarantined.
fn quarantined_at(name: &OsStr) -> Option<u64> {
    let (blob, stamp) = name.to_str()?.rsplit_once('.')?;
    blob_id(OsStr::new(blob))?;
    if stamp.is_empty() || !stamp.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    stamp.parse().ok()
}

async fn sweep_periodically(shared: Weak<Shared>) {
    let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // immediate; startup already swept
    let mut sweeps = 0u32;
    loop {
        ticker.tick().await;
        let Some(shared) = shared.upgrade() else {
            return; // manager dropped
        };
        let removed = shared.sweep(shared.limits.stale_after).await;
        if removed > 0 {
            info!(removed, "discarded abandoned uploads");
        }
        sweeps = sweeps.wrapping_add(1);
        if sweeps.is_multiple_of(ORPHAN_SWEEP_EVERY) {
            shared.sweep_orphan_blobs(SystemTime::now()).await.log();
        }
    }
}

/// Is `node` the entry upload `id` was filed as? Blobs are named after the
/// upload that produced them, so only `finish` of that upload writes an
/// entry whose bytes are `<files_root>/<id>`; the hash must match too.
fn is_filed_upload(node: &Node, id: &str, sha256: &[u8]) -> bool {
    node.kind == NodeKind::File
        && node.sha256.as_deref() == Some(sha256)
        && node
            .storage_path
            .as_deref()
            .and_then(|stored| Path::new(stored).file_name())
            .is_some_and(|blob| blob == id)
}

async fn exists(path: &Path) -> bool {
    tokio::fs::try_exists(path).await.unwrap_or(false)
}

/// Make a rename inside `dir` durable (on Unix, fsync the directory).
/// Failures are only logged: the rename itself has happened.
async fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    {
        let dir = dir.to_path_buf();
        let synced = tokio::task::spawn_blocking(move || std::fs::File::open(&dir)?.sync_all())
            .await
            .map_err(std::io::Error::other)
            .and_then(|result| result);
        if let Err(e) = synced {
            warn!(error = %e, "could not sync files_root after a rename");
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Create `files_root` (owner-only on Unix) and return its absolute path.
async fn prepare_files_root(root: &Path) -> Result<PathBuf, TransferError> {
    let mut builder = tokio::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(root).await?;
    let root = tokio::fs::canonicalize(root).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = tokio::fs::metadata(&root).await?.permissions().mode();
        if mode & 0o077 != 0 {
            warn!(
                path = %root.display(),
                mode = format!("{:o}", mode & 0o777),
                "files_root is accessible to other local users; consider chmod 700"
            );
        }
    }
    Ok(root)
}

/// Create a fresh partial file (owner-only on Unix) pre-sized to `size`.
async fn create_part(path: &Path, size: u64) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true).read(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path).await?;
    if let Err(e) = file.set_len(size).await {
        drop(file);
        remove_quietly(path).await;
        return Err(e);
    }
    Ok(file)
}

/// Reopen an existing partial file, checking it still has the right size.
async fn open_part(path: &Path, size: u64) -> std::io::Result<File> {
    let file = OpenOptions::new().write(true).read(true).open(path).await?;
    let len = file.metadata().await?.len();
    if len != size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("partial file is {len} bytes, expected {size}"),
        ));
    }
    Ok(file)
}

async fn remove_quietly(path: &Path) {
    if let Err(e) = tokio::fs::remove_file(path).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(path = %path.display(), error = %e, "could not remove file");
        }
    }
}

/// SHA-256 of a whole file, on the blocking pool (it may be gigabytes).
/// Syncs the data to disk first, since it is about to become a published
/// blob.
async fn hash_file(file: File) -> std::io::Result<[u8; 32]> {
    let mut file = file.into_std().await;
    tokio::task::spawn_blocking(move || -> std::io::Result<[u8; 32]> {
        file.sync_data()?;
        file.seek(SeekFrom::Start(0))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 128 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hasher.finalize().into())
    })
    .await
    .map_err(std::io::Error::other)?
}

/// Bytes available to unprivileged users on the volume holding `path`, or
/// `None` where that can't be determined (the check is then skipped).
#[cfg(unix)]
fn available_space(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `statvfs` only writes into the zero-initialised struct we pass
    // and reads the NUL-terminated path, which outlives the call.
    let stat = unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stat) != 0 {
            return None;
        }
        stat
    };
    #[allow(clippy::useless_conversion)] // field widths differ across platforms
    let (blocks, block_size) = (u64::from(stat.f_bavail), u64::from(stat.f_frsize));
    Some(blocks.saturating_mul(block_size))
}

#[cfg(not(unix))]
fn available_space(_path: &Path) -> Option<u64> {
    None
}

impl ActiveUpload {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Fraction of chunks received, for progress reporting.
    pub fn progress(&self) -> f32 {
        if self.total_chunks == 0 {
            return 1.0;
        }
        self.received as f32 / self.total_chunks as f32
    }

    /// Every chunk has arrived (always true for an empty file): the caller
    /// should `finish` now — the client has nothing left to send.
    pub fn is_complete(&self) -> bool {
        self.received == self.total_chunks
    }

    async fn save_bitmap(&mut self) -> Result<(), TransferError> {
        transfer_state::update_bitmap(&self.pool, &self.id.to_string(), self.bitmap.as_raw_slice())
            .await?;
        self.unsaved = 0;
        self.last_save = Instant::now();
        Ok(())
    }

    fn expected_chunk_len(&self, chunk_index: u32) -> usize {
        let last = self.total_chunks - 1;
        if chunk_index == last {
            let rem = (self.size % u64::from(self.chunk_size)) as usize;
            if rem == 0 {
                self.chunk_size as usize
            } else {
                rem
            }
        } else {
            self.chunk_size as usize
        }
    }
}

impl Drop for ActiveUpload {
    fn drop(&mut self) {
        let Some(claim) = self.claim.take() else {
            return;
        };
        if self.unsaved == 0 {
            return; // `claim` drops here: released at once
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        // Keep the transfer held until its progress is saved, so a resume on
        // another connection sees every chunk received on this one.
        let pool = self.pool.clone();
        let id = self.id.to_string();
        let bitmap = self.bitmap.as_raw_slice().to_vec();
        runtime.spawn(async move {
            if let Err(e) = transfer_state::update_bitmap(&pool, &id, &bitmap).await {
                warn!(%id, error = %e, "could not save upload progress");
            }
            drop(claim);
        });
    }
}

/// Helper shared with the client side (tests, future client crate): the
/// wire-format Arc for a resume id — all zeros means "fresh".
pub fn resume_id_from_wire(bytes: [u8; 16]) -> Option<Uuid> {
    (bytes != [0u8; 16]).then(|| Uuid::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    fn sess(class: BaseClass) -> Session {
        Session {
            id: Uuid::new_v4(),
            account_id: "a".into(),
            username: "tester".into(),
            class,
            privileges: BaseClass::privileges(class),
            expires_at: tokio::time::Instant::now(),
        }
    }

    use super::*;
    use crate::auth::{BaseClass, Privileges};

    struct Fixture {
        manager: TransferManager,
        tree: FileTree,
        session: Session,
        pool: SqlitePool,
        _dir: tempfile::TempDir,
    }

    async fn fixture(rate: u64) -> Fixture {
        fixture_with(rate, TransferLimits::default()).await
    }

    async fn fixture_with(rate: u64, limits: TransferLimits) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let pool = kdx_storage::connect(&dir.path().join("t.db")).await.unwrap();
        let tree = FileTree::load(pool.clone()).await.unwrap();
        let manager = TransferManager::with_limits(
            pool.clone(),
            TransferConfig {
                files_root: dir.path().join("files"),
                max_upload_bytes_per_sec: rate,
                max_download_bytes_per_sec: 0,
            },
            limits,
        )
        .await
        .unwrap();
        // As kdxd wires it: deletes find blobs the way downloads do.
        let tree = tree.with_files_root(manager.files_root());
        // PowerUser: the root folder's default write ACL is min class 2.
        let session = Session {
            id: Uuid::new_v4(),
            account_id: "acct-1".into(),
            username: "phraq".into(),
            class: BaseClass::PowerUser,
            privileges: BaseClass::PowerUser.privileges() | Privileges::FILE_UPLOAD,
            expires_at: Instant::now() + std::time::Duration::from_secs(600),
        };
        Fixture {
            manager,
            tree,
            session,
            pool,
            _dir: dir,
        }
    }

    fn chunked(data: &[u8], chunk_size: usize) -> Vec<(u32, [u8; 32], &[u8])> {
        data.chunks(chunk_size)
            .enumerate()
            .map(|(i, c)| (i as u32, Sha256::digest(c).into(), c))
            .collect()
    }

    /// Names of the files in `files_root`, sorted.
    fn stored_files(f: &Fixture) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(f.manager.files_root())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    async fn row_bits(f: &Fixture, id: Uuid) -> usize {
        let row = transfer_state::get(&f.pool, &id.to_string())
            .await
            .unwrap()
            .expect("row present");
        BitVec::<u8, Lsb0>::from_vec(row.bitmap).count_ones()
    }

    /// Wait (briefly) for a dropped upload's background save to release it.
    async fn wait_released(f: &Fixture, id: Uuid) {
        for _ in 0..200 {
            if !f.manager.is_live(id) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("upload {id} never released");
    }

    #[tokio::test]
    async fn multi_chunk_upload_verifies_and_files() {
        let f = fixture(0).await;
        let data: Vec<u8> = (0..100_000u32).flat_map(|v| v.to_be_bytes()).collect();
        let sha: [u8; 32] = Sha256::digest(&data).into();

        let (mut upload, accept) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "big.bin", data.len() as u64, 8192, sha, None)
            .await
            .unwrap();
        assert_eq!(accept.total_chunks, (data.len() as u64).div_ceil(8192) as u32);

        let mut complete = false;
        for (i, hash, chunk) in chunked(&data, 8192) {
            complete = f.manager.write_chunk(&mut upload, i, &hash, chunk).await.unwrap();
        }
        assert!(complete);
        f.manager.finish(&f.tree, upload).await.unwrap();

        let entries = f.tree.list("/", &sess(BaseClass::Guest)).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "big.bin");
        assert_eq!(entries[0].size, data.len() as u64);
    }

    #[tokio::test]
    async fn resume_after_partial_upload() {
        let f = fixture(0).await;
        let data: Vec<u8> = (0..60_000u32).flat_map(|v| v.to_be_bytes()).collect();
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let chunks = chunked(&data, 8192);

        // First attempt: send only the first half, then "disconnect" (drop).
        let (mut upload, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "r.bin", data.len() as u64, 8192, sha, None)
            .await
            .unwrap();
        let transfer_id = upload.id();
        let half = chunks.len() / 2;
        for (i, hash, chunk) in &chunks[..half] {
            f.manager.write_chunk(&mut upload, *i, hash, chunk).await.unwrap();
        }
        drop(upload);
        wait_released(&f, transfer_id).await;

        // Resume: server reports exactly which chunks it has.
        let (mut upload, accept) = f
            .manager
            .begin_upload(
                &f.tree,
                &f.session,
                "/",
                "r.bin",
                data.len() as u64,
                8192,
                sha,
                Some(transfer_id),
            )
            .await
            .unwrap();
        let have = BitVec::<u8, Lsb0>::from_vec(accept.have_bitmap.clone());
        assert_eq!(have.count_ones(), half);

        // Send only what's missing; completion must trigger on the last one.
        let mut complete = false;
        for (i, hash, chunk) in &chunks {
            if !have[*i as usize] {
                complete = f.manager.write_chunk(&mut upload, *i, hash, chunk).await.unwrap();
            }
        }
        assert!(complete);
        f.manager.finish(&f.tree, upload).await.unwrap();
        assert_eq!(f.tree.list("/", &sess(BaseClass::Guest)).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn resume_from_wrong_account_rejected() {
        let f = fixture(0).await;
        let data = vec![7u8; 10_000];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let (upload, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "x.bin", data.len() as u64, 8192, sha, None)
            .await
            .unwrap();
        let transfer_id = upload.id();
        drop(upload);

        let mut other = f.session.clone();
        other.account_id = "someone-else".into();
        let result = f
            .manager
            .begin_upload(
                &f.tree,
                &other,
                "/",
                "x.bin",
                data.len() as u64,
                8192,
                sha,
                Some(transfer_id),
            )
            .await;
        assert!(matches!(result, Err(TransferError::UnknownTransfer)));
    }

    #[tokio::test]
    async fn corrupted_chunk_rejected() {
        let f = fixture(0).await;
        let data = vec![1u8; 10_000];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let (mut upload, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "c.bin", data.len() as u64, 8192, sha, None)
            .await
            .unwrap();
        let bogus_hash = [0u8; 32];
        let result = f
            .manager
            .write_chunk(&mut upload, 0, &bogus_hash, &data[..8192])
            .await;
        assert!(matches!(result, Err(TransferError::ChunkHashMismatch)));
    }

    #[tokio::test]
    async fn wrong_final_hash_destroys_transfer() {
        let f = fixture(0).await;
        let data = vec![2u8; 5_000];
        let wrong_sha = [9u8; 32]; // not the hash of `data`
        let (mut upload, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "w.bin", data.len() as u64, 8192, wrong_sha, None)
            .await
            .unwrap();
        let hash: [u8; 32] = Sha256::digest(&data).into();
        let complete = f.manager.write_chunk(&mut upload, 0, &hash, &data).await.unwrap();
        assert!(complete);
        let result = f.manager.finish(&f.tree, upload).await;
        assert!(matches!(result, Err(TransferError::FileHashMismatch)));
        assert!(f.tree.list("/", &sess(BaseClass::Guest)).await.unwrap().is_empty());
        assert!(stored_files(&f).is_empty());
    }

    #[tokio::test]
    async fn throttle_paces_upload() {
        // Real time (sqlx misbehaves under a paused clock): 128 KiB/s with
        // 128 KiB burst means a 256 KiB upload needs ~1s for the second half.
        let f = fixture(128 * 1024).await;
        let data = vec![3u8; 256 * 1024];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let (mut upload, _) = f
            .manager
            .begin_upload(
                &f.tree,
                &f.session,
                "/",
                "slow.bin",
                data.len() as u64,
                32 * 1024,
                sha,
                None,
            )
            .await
            .unwrap();
        let start = Instant::now();
        for (i, hash, chunk) in chunked(&data, 32 * 1024) {
            f.manager.write_chunk(&mut upload, i, &hash, chunk).await.unwrap();
        }
        let elapsed = Instant::now().duration_since(start);
        assert!(
            elapsed >= std::time::Duration::from_millis(700),
            "throttle not applied: {elapsed:?}"
        );
    }

    // XFER-9: rejected chunks are charged too, so garbage can't be hashed
    // faster than the configured rate.
    #[tokio::test]
    async fn rejected_chunks_are_throttled() {
        let f = fixture(128 * 1024).await;
        let data = vec![3u8; 256 * 1024];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let (mut upload, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "g.bin", data.len() as u64, 32 * 1024, sha, None)
            .await
            .unwrap();
        let start = Instant::now();
        for _ in 0..8 {
            let result = f
                .manager
                .write_chunk(&mut upload, 0, &[0u8; 32], &data[..32 * 1024])
                .await;
            assert!(matches!(result, Err(TransferError::ChunkHashMismatch)));
        }
        let elapsed = Instant::now().duration_since(start);
        assert!(
            elapsed >= std::time::Duration::from_millis(700),
            "rejected chunks not throttled: {elapsed:?}"
        );
    }

    // XFER-9: the throttle is per account, not per transfer.
    #[tokio::test]
    async fn throttle_is_shared_by_an_accounts_uploads() {
        let f = fixture(128 * 1024).await;
        let data = vec![4u8; 128 * 1024];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let begin = |name: &'static str| {
            f.manager.begin_upload(
                &f.tree,
                &f.session,
                "/",
                name,
                data.len() as u64,
                32 * 1024,
                sha,
                None,
            )
        };
        let (mut a, _) = begin("a.bin").await.unwrap();
        let (mut b, _) = begin("b.bin").await.unwrap();
        let start = Instant::now();
        // 256 KiB in total at 128 KiB/s (128 KiB burst): ~1s, whereas two
        // separate buckets would let both through instantly.
        for (i, hash, chunk) in chunked(&data, 32 * 1024) {
            f.manager.write_chunk(&mut a, i, &hash, chunk).await.unwrap();
            f.manager.write_chunk(&mut b, i, &hash, chunk).await.unwrap();
        }
        let elapsed = Instant::now().duration_since(start);
        assert!(
            elapsed >= std::time::Duration::from_millis(700),
            "per-account throttle not shared: {elapsed:?}"
        );
    }

    // XFER-2 / XFER-6: a transfer may not need more than MAX_TOTAL_CHUNKS
    // chunks; the check happens before anything touches the disk.
    #[tokio::test]
    async fn too_many_chunks_rejected_before_any_state() {
        let f = fixture(0).await;
        let result = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "huge.bin", 16 << 30, 4096, [0u8; 32], None)
            .await;
        assert!(matches!(result, Err(TransferError::BadChunkSize)));
        assert!(stored_files(&f).is_empty());
        assert!(transfer_state::list_stale(&f.pool, 0).await.unwrap().is_empty());

        // Exactly at the cap is fine, and its bitmap fits the u16 wire length.
        let at_cap = u64::from(MAX_TOTAL_CHUNKS) * 4096;
        assert_eq!(check_upload_shape(at_cap, 4096).unwrap(), MAX_TOTAL_CHUNKS);
        assert!(check_upload_shape(at_cap + 1, 4096).is_err());
        assert!((MAX_TOTAL_CHUNKS as usize).div_ceil(8) <= usize::from(u16::MAX));
        // The stock 32 KiB chunk size covers files up to just under 16 GiB.
        assert!(check_upload_shape(MAX_FILE_SIZE - 256 * 1024, 32 * 1024).is_ok());
    }

    // XFER-2: the bitmap is saved in batches, plus when the upload is let
    // go — not on every chunk.
    #[tokio::test]
    async fn bitmap_saved_in_batches_and_on_release() {
        let limits = TransferLimits {
            bitmap_flush_chunks: 4,
            bitmap_flush_interval: Duration::from_secs(3600),
            ..TransferLimits::default()
        };
        let f = fixture_with(0, limits).await;
        let data = vec![5u8; 20 * 4096];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let (mut upload, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "b.bin", data.len() as u64, 4096, sha, None)
            .await
            .unwrap();
        let id = upload.id();
        let chunks = chunked(&data, 4096);
        for (i, hash, chunk) in &chunks[..3] {
            f.manager.write_chunk(&mut upload, *i, hash, chunk).await.unwrap();
        }
        assert_eq!(row_bits(&f, id).await, 0, "saved before a batch was due");
        f.manager.write_chunk(&mut upload, 3, &chunks[3].1, chunks[3].2).await.unwrap();
        assert_eq!(row_bits(&f, id).await, 4);
        for (i, hash, chunk) in &chunks[4..10] {
            f.manager.write_chunk(&mut upload, *i, hash, chunk).await.unwrap();
        }
        assert_eq!(row_bits(&f, id).await, 8);
        // A resend of a held chunk is accepted without counting twice.
        assert!(!f.manager.write_chunk(&mut upload, 0, &chunks[0].1, chunks[0].2).await.unwrap());
        assert_eq!(upload.received, 10);

        f.manager.release(upload).await;
        assert!(!f.manager.is_live(id));
        assert_eq!(row_bits(&f, id).await, 10);

        // Dropping (a disconnect) saves too, in the background.
        let (mut upload, accept) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "b.bin", data.len() as u64, 4096, sha, Some(id))
            .await
            .unwrap();
        assert_eq!(BitVec::<u8, Lsb0>::from_vec(accept.have_bitmap).count_ones(), 10);
        f.manager.write_chunk(&mut upload, 10, &chunks[10].1, chunks[10].2).await.unwrap();
        drop(upload);
        wait_released(&f, id).await;
        assert_eq!(row_bits(&f, id).await, 11);
    }

    // XFER-3: the sweeper removes stale rows with their partial files, and
    // partial files no row owns; live uploads are left alone.
    #[tokio::test]
    async fn sweep_removes_stale_and_orphaned_uploads() {
        let f = fixture(0).await;
        let data = vec![6u8; 10_000];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let (dropped, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "old.bin", data.len() as u64, 4096, sha, None)
            .await
            .unwrap();
        drop(dropped);
        let (live, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "live.bin", data.len() as u64, 4096, sha, None)
            .await
            .unwrap();
        let orphan = f.manager.files_root().join(format!("{}.part", Uuid::new_v4()));
        std::fs::write(&orphan, b"leftover").unwrap();
        // Not ours to judge: blobs and unrelated files stay.
        std::fs::write(f.manager.files_root().join("notes.txt"), b"x").unwrap();

        // Fresh rows survive a 24h sweep, but the orphan goes.
        assert_eq!(f.manager.sweep_stale(Duration::from_secs(24 * 3600)).await, 1);
        assert!(!orphan.exists());
        assert_eq!(stored_files(&f).len(), 3); // two .part + notes.txt

        // Everything stale: only the live upload's state survives.
        assert_eq!(f.manager.sweep_stale(Duration::ZERO).await, 1);
        let rows = transfer_state::list_stale(&f.pool, 0).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, live.id().to_string());
        assert_eq!(
            stored_files(&f),
            vec![format!("{}.part", live.id()), "notes.txt".to_string()]
        );
    }

    // XFER-3: leftovers from a previous run are swept at startup.
    #[tokio::test]
    async fn startup_sweeps_orphaned_partials() {
        let dir = tempfile::tempdir().unwrap();
        let files = dir.path().join("files");
        std::fs::create_dir_all(&files).unwrap();
        let orphan = files.join(format!("{}.part", Uuid::new_v4()));
        std::fs::write(&orphan, b"leftover").unwrap();
        let pool = kdx_storage::connect(&dir.path().join("t.db")).await.unwrap();
        let _manager = TransferManager::new(
            pool,
            TransferConfig {
                files_root: files,
                max_upload_bytes_per_sec: 0,
                max_download_bytes_per_sec: 0,
            },
        )
        .await
        .unwrap();
        assert!(!orphan.exists());
    }

    // XFER-3: an account keeps at most `max_open_uploads_per_account`
    // unfinished uploads; the oldest idle one makes way.
    #[tokio::test]
    async fn open_uploads_per_account_are_capped() {
        let f = fixture(0).await;
        let cap = f.manager.limits().max_open_uploads_per_account;
        let data = vec![8u8; 5000];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let mut ids = Vec::new();
        for n in 0..=cap {
            let (upload, _) = f
                .manager
                .begin_upload(
                    &f.tree,
                    &f.session,
                    "/",
                    &format!("u{n}.bin"),
                    data.len() as u64,
                    4096,
                    sha,
                    None,
                )
                .await
                .unwrap();
            ids.push(upload.id());
            drop(upload);
        }
        let mine = transfer_state::list_for_account(&f.pool, "acct-1").await.unwrap();
        assert_eq!(mine.len(), cap);
        assert!(mine.iter().all(|r| r.id != ids[0].to_string()), "oldest kept");
        assert!(!f.manager.files_root().join(format!("{}.part", ids[0])).exists());
        assert_eq!(stored_files(&f).len(), cap);
    }

    // XFER-9: live uploads per account are capped across connections.
    #[tokio::test]
    async fn concurrent_uploads_per_account_are_capped() {
        let f = fixture(0).await;
        let data = vec![8u8; 5000];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let mut live = Vec::new();
        for n in 0..f.manager.limits().max_uploads_per_account {
            let (upload, _) = f
                .manager
                .begin_upload(&f.tree, &f.session, "/", &format!("c{n}.bin"), 5000, 4096, sha, None)
                .await
                .unwrap();
            live.push(upload);
        }
        let result = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "extra.bin", 5000, 4096, sha, None)
            .await;
        assert!(matches!(result, Err(TransferError::TooManyTransfers)));
        // Another account is unaffected.
        let mut other = f.session.clone();
        other.account_id = "acct-2".into();
        f.manager
            .begin_upload(&f.tree, &other, "/", "theirs.bin", 5000, 4096, sha, None)
            .await
            .unwrap();
        // Finishing one frees a slot.
        drop(live.pop());
        f.manager
            .begin_upload(&f.tree, &f.session, "/", "extra.bin", 5000, 4096, sha, None)
            .await
            .unwrap();
    }

    // XFER-5: a transfer can be live on one connection only.
    #[tokio::test]
    async fn resume_of_a_live_upload_is_busy() {
        let f = fixture(0).await;
        let data = vec![9u8; 10_000];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let (u1, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "x.bin", data.len() as u64, 4096, sha, None)
            .await
            .unwrap();
        let id = u1.id();
        let again = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "x.bin", data.len() as u64, 4096, sha, Some(id))
            .await;
        assert!(matches!(again, Err(TransferError::Busy)));
        // The refused resume must not have discarded the live upload.
        assert!(transfer_state::get(&f.pool, &id.to_string()).await.unwrap().is_some());

        drop(u1);
        wait_released(&f, id).await;
        f.manager
            .begin_upload(&f.tree, &f.session, "/", "x.bin", data.len() as u64, 4096, sha, Some(id))
            .await
            .unwrap();
    }

    // XFER-4: a live upload reserves its name against other uploads.
    #[tokio::test]
    async fn same_name_upload_while_one_is_live_is_refused() {
        let f = fixture(0).await;
        let sha = [0u8; 32];
        let (first, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "dup.bin", 10, 4096, sha, None)
            .await
            .unwrap();
        let mut other = f.session.clone();
        other.account_id = "acct-2".into();
        let second = f
            .manager
            .begin_upload(&f.tree, &other, "/", "dup.bin", 10, 4096, sha, None)
            .await;
        assert!(matches!(second, Err(TransferError::Tree(TreeError::Exists))));
        drop(first);
        f.manager
            .begin_upload(&f.tree, &other, "/", "dup.bin", 10, 4096, sha, None)
            .await
            .unwrap();
    }

    // XFER-4: if the name gets taken another way mid-upload, finishing
    // fails cleanly — no orphaned blob, no leftover partial or row.
    #[tokio::test]
    async fn finish_into_a_taken_name_cleans_up() {
        let f = fixture(0).await;
        let data = vec![1u8; 9000];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let (mut upload, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "a.bin", data.len() as u64, 4096, sha, None)
            .await
            .unwrap();
        let id = upload.id();
        for (i, hash, chunk) in chunked(&data, 4096) {
            f.manager.write_chunk(&mut upload, i, &hash, chunk).await.unwrap();
        }
        // Someone files "a.bin" into the same folder first.
        f.tree
            .add_file(file_tree_root(), "a.bin", 1, &[0u8; 32], "/elsewhere")
            .await
            .unwrap();
        assert!(f.manager.finish(&f.tree, upload).await.is_err());
        assert!(stored_files(&f).is_empty(), "blob or partial left behind");
        assert!(transfer_state::get(&f.pool, &id.to_string()).await.unwrap().is_none());
        assert!(!f.manager.is_live(id));
    }

    fn file_tree_root() -> &'static str {
        kdx_storage::file_tree::ROOT_ID
    }

    // XFER-8: a resume re-checks write access (account demoted meanwhile)
    // and discards the upload when it can no longer land.
    #[tokio::test]
    async fn resume_after_demotion_is_refused() {
        let f = fixture(0).await;
        let data = vec![2u8; 9000];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let (upload, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "p.bin", data.len() as u64, 4096, sha, None)
            .await
            .unwrap();
        let id = upload.id();
        drop(upload);
        wait_released(&f, id).await;

        let mut demoted = f.session.clone();
        demoted.class = BaseClass::User;
        demoted.privileges = BaseClass::User.privileges();
        let result = f
            .manager
            .begin_upload(&f.tree, &demoted, "/", "p.bin", data.len() as u64, 4096, sha, Some(id))
            .await;
        assert!(matches!(result, Err(TransferError::Tree(TreeError::Acl(_)))), "{:?}", result.err());
        assert!(transfer_state::get(&f.pool, &id.to_string()).await.unwrap().is_none());
        assert!(stored_files(&f).is_empty());
    }

    // XFER-8: a resume re-checks the name is still free.
    #[tokio::test]
    async fn resume_into_a_taken_name_is_refused() {
        let f = fixture(0).await;
        let data = vec![2u8; 9000];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let (upload, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "a.bin", data.len() as u64, 4096, sha, None)
            .await
            .unwrap();
        let id = upload.id();
        drop(upload);
        wait_released(&f, id).await;
        f.tree
            .add_file(file_tree_root(), "a.bin", 1, &[0u8; 32], "/elsewhere")
            .await
            .unwrap();
        let result = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "a.bin", data.len() as u64, 4096, sha, Some(id))
            .await;
        assert!(matches!(result, Err(TransferError::Tree(TreeError::Exists))));
        assert!(transfer_state::get(&f.pool, &id.to_string()).await.unwrap().is_none());
        assert!(stored_files(&f).is_empty());
    }

    // XFER-7: an empty upload is complete as soon as it starts.
    #[tokio::test]
    async fn zero_byte_upload_completes_immediately() {
        let f = fixture(0).await;
        let sha: [u8; 32] = Sha256::digest(b"").into();
        let (upload, accept) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "empty.txt", 0, 4096, sha, None)
            .await
            .unwrap();
        assert_eq!(accept.total_chunks, 0);
        assert!(upload.is_complete());
        f.manager.finish(&f.tree, upload).await.unwrap();
        let entries = f.tree.list("/", &sess(BaseClass::Guest)).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].size, 0);
    }

    // XFER-7: resuming an upload whose every chunk already arrived (e.g. the
    // server died while verifying it) is complete on resume.
    #[tokio::test]
    async fn resume_of_a_fully_received_upload_is_complete() {
        let f = fixture(0).await;
        let data = vec![3u8; 9000];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let (mut upload, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "full.bin", data.len() as u64, 4096, sha, None)
            .await
            .unwrap();
        let id = upload.id();
        for (i, hash, chunk) in chunked(&data, 4096) {
            f.manager.write_chunk(&mut upload, i, &hash, chunk).await.unwrap();
        }
        f.manager.release(upload).await;
        let (upload, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "full.bin", data.len() as u64, 4096, sha, Some(id))
            .await
            .unwrap();
        assert!(upload.is_complete());
        f.manager.finish(&f.tree, upload).await.unwrap();
    }

    /// Begin `name` in `/`, send every chunk of `data`, and let go of it
    /// with its progress saved — the state a crash during `finish` leaves.
    async fn fully_received(f: &Fixture, name: &str, data: &[u8]) -> Uuid {
        let sha: [u8; 32] = Sha256::digest(data).into();
        let (mut upload, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", name, data.len() as u64, 4096, sha, None)
            .await
            .unwrap();
        for (i, hash, chunk) in chunked(data, 4096) {
            f.manager.write_chunk(&mut upload, i, &hash, chunk).await.unwrap();
        }
        let id = upload.id();
        f.manager.release(upload).await;
        assert!(!f.manager.is_live(id));
        id
    }

    fn part_of(f: &Fixture, id: Uuid) -> PathBuf {
        f.manager.files_root().join(format!("{id}.part"))
    }

    fn blob_of(f: &Fixture, id: Uuid) -> PathBuf {
        f.manager.files_root().join(id.to_string())
    }

    /// File upload `id` as `/name` the way `finish` does, without moving
    /// its bytes (a crash right after the entry was committed).
    async fn file_entry(f: &Fixture, id: Uuid, name: &str, data: &[u8]) {
        let sha: [u8; 32] = Sha256::digest(data).into();
        f.tree
            .add_file(
                file_tree_root(),
                name,
                data.len() as u64,
                &sha,
                &blob_of(f, id).display().to_string(),
            )
            .await
            .unwrap();
    }

    // Seam review #1: when the bytes can't be moved into place, the entry
    // is withdrawn (no file without bytes) and the verified upload stays
    // resumable; resuming it once the obstacle is gone files it.
    #[tokio::test]
    async fn failed_rename_withdraws_the_entry_and_keeps_the_upload() {
        let f = fixture(0).await;
        let data: Vec<u8> = (0..9000u32).map(|i| (i % 253) as u8).collect();
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let (mut upload, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "r.bin", data.len() as u64, 4096, sha, None)
            .await
            .unwrap();
        let id = upload.id();
        for (i, hash, chunk) in chunked(&data, 4096) {
            f.manager.write_chunk(&mut upload, i, &hash, chunk).await.unwrap();
        }
        // Something occupies the blob's name, so the rename fails.
        let blocker = blob_of(&f, id);
        std::fs::create_dir(&blocker).unwrap();
        std::fs::write(blocker.join("x"), b"x").unwrap();
        let err = f.manager.finish(&f.tree, upload).await.unwrap_err();
        assert!(err.is_internal(), "{err}");
        assert!(matches!(f.tree.resolve("/r.bin").await, Err(TreeError::NotFound)));
        assert!(transfer_state::get(&f.pool, &id.to_string()).await.unwrap().is_some());
        assert!(part_of(&f, id).exists(), "verified bytes were thrown away");
        assert!(!f.manager.is_live(id));

        std::fs::remove_dir_all(&blocker).unwrap();
        let (upload, accept) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "r.bin", data.len() as u64, 4096, sha, Some(id))
            .await
            .unwrap();
        assert_eq!(BitVec::<u8, Lsb0>::from_vec(accept.have_bitmap).count_ones(), 3);
        assert!(upload.is_complete());
        f.manager.finish(&f.tree, upload).await.unwrap();
        let node = f.tree.resolve("/r.bin").await.unwrap();
        assert_eq!(std::fs::read(node.storage_path.unwrap()).unwrap(), data);
        assert!(transfer_state::get(&f.pool, &id.to_string()).await.unwrap().is_none());
        assert_eq!(stored_files(&f), vec![id.to_string()]);
    }

    // Seam review #1: a crash between filing the entry and moving the
    // bytes used to make the resume discard the verified partial (its name
    // was "taken" — by itself). Now the resume finishes the job.
    #[tokio::test]
    async fn resume_after_a_crash_mid_finish_files_the_bytes() {
        let f = fixture(0).await;
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 249) as u8).collect();
        let id = fully_received(&f, "c.bin", &data).await;
        file_entry(&f, id, "c.bin", &data).await;

        let sha: [u8; 32] = Sha256::digest(&data).into();
        let (upload, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "c.bin", data.len() as u64, 4096, sha, Some(id))
            .await
            .unwrap();
        assert!(upload.is_complete());
        f.manager.finish(&f.tree, upload).await.unwrap();
        assert_eq!(std::fs::read(blob_of(&f, id)).unwrap(), data);
        assert!(transfer_state::get(&f.pool, &id.to_string()).await.unwrap().is_none());
        assert_eq!(stored_files(&f), vec![id.to_string()]);
        let (mut download, _) = f
            .manager
            .begin_download(&f.tree, &f.session, "/c.bin", 4096, &[])
            .await
            .unwrap();
        assert!(download.next_chunk().await.unwrap().is_some());

        // Someone else's file under that name is still "taken", though.
        let other = fully_received(&f, "d.bin", &data).await;
        f.tree
            .add_file(file_tree_root(), "d.bin", 1, &sha, "/elsewhere/d.bin")
            .await
            .unwrap();
        let resumed = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "d.bin", data.len() as u64, 4096, sha, Some(other))
            .await;
        assert!(matches!(resumed, Err(TransferError::Tree(TreeError::Exists))));
        assert!(!part_of(&f, other).exists());
    }

    // Seam review #1: startup repairs whatever prefix of a finish (entry,
    // rename, row delete) reached the disk before the sweep runs.
    #[tokio::test]
    async fn startup_completes_finishes_a_crash_interrupted() {
        let f = fixture(0).await;
        let data: Vec<u8> = (0..9000u32).map(|i| (i % 241) as u8).collect();
        // Entry filed, rename lost: row and partial still there.
        let filed = fully_received(&f, "filed.bin", &data).await;
        file_entry(&f, filed, "filed.bin", &data).await;
        // Entry filed and row deleted, rename lost: a partial with no row.
        let rowless = fully_received(&f, "rowless.bin", &data).await;
        file_entry(&f, rowless, "rowless.bin", &data).await;
        transfer_state::delete(&f.pool, &rowless.to_string()).await.unwrap();
        // Entry filed and bytes moved, row delete lost.
        let done = fully_received(&f, "done.bin", &data).await;
        file_entry(&f, done, "done.bin", &data).await;
        std::fs::rename(part_of(&f, done), blob_of(&f, done)).unwrap();
        // Rename kept but the entry rolled back: a blob nothing names.
        let unfiled = fully_received(&f, "unfiled.bin", &data).await;
        std::fs::rename(part_of(&f, unfiled), blob_of(&f, unfiled)).unwrap();
        // Both rolled back (no entry, no row): an orphan.
        let orphan = Uuid::new_v4();
        std::fs::write(blob_of(&f, orphan), b"orphan").unwrap();

        // Restart.
        let manager = TransferManager::new(
            f.pool.clone(),
            TransferConfig {
                files_root: f.manager.files_root().to_path_buf(),
                max_upload_bytes_per_sec: 0,
                max_download_bytes_per_sec: 0,
            },
        )
        .await
        .unwrap();
        for id in [filed, rowless, done] {
            assert_eq!(std::fs::read(blob_of(&f, id)).unwrap(), data, "{id}");
            assert!(!part_of(&f, id).exists(), "{id}");
            assert!(transfer_state::get(&f.pool, &id.to_string()).await.unwrap().is_none());
        }
        // The orphan sweep ran after the repair: only the true orphan went
        // into quarantine.
        assert!(!blob_of(&f, orphan).exists());
        let quarantined = quarantined(&f);
        assert_eq!(quarantined.len(), 1, "{quarantined:?}");
        assert!(quarantined[0].starts_with(&format!("{orphan}.")), "{quarantined:?}");
        // The unfiled upload is resumable again, and resuming files it.
        assert!(part_of(&f, unfiled).exists());
        assert!(!blob_of(&f, unfiled).exists());
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let (upload, _) = manager
            .begin_upload(&f.tree, &f.session, "/", "unfiled.bin", data.len() as u64, 4096, sha, Some(unfiled))
            .await
            .unwrap();
        assert!(upload.is_complete());
        manager.finish(&f.tree, upload).await.unwrap();
        let node = f.tree.resolve("/unfiled.bin").await.unwrap();
        assert_eq!(std::fs::read(node.storage_path.unwrap()).unwrap(), data);
    }

    // Seam review #1: a database failure while filing a verified upload
    // keeps it resumable instead of throwing it away.
    #[tokio::test]
    async fn storage_failure_while_filing_keeps_the_upload() {
        let f = fixture(0).await;
        let data = vec![5u8; 9000];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let (mut upload, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "s.bin", data.len() as u64, 4096, sha, None)
            .await
            .unwrap();
        let id = upload.id();
        for (i, hash, chunk) in chunked(&data, 4096) {
            f.manager.write_chunk(&mut upload, i, &hash, chunk).await.unwrap();
        }
        // A tree whose database connection is gone: filing the entry fails
        // with a storage error.
        let lost = kdx_storage::connect(&f._dir.path().join("t.db")).await.unwrap();
        let unreachable = FileTree::load(lost.clone()).await.unwrap();
        lost.close().await;
        let err = f.manager.finish(&unreachable, upload).await.unwrap_err();
        assert!(matches!(err, TransferError::Tree(TreeError::Storage(_))), "{err:?}");
        assert!(err.is_internal());
        assert!(transfer_state::get(&f.pool, &id.to_string()).await.unwrap().is_some());
        assert!(part_of(&f, id).exists());
        assert!(!f.manager.is_live(id));

        let (upload, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "s.bin", data.len() as u64, 4096, sha, Some(id))
            .await
            .unwrap();
        f.manager.finish(&f.tree, upload).await.unwrap();
        assert!(f.tree.resolve("/s.bin").await.is_ok());
    }

    // Seam review #2: deleting a file finds its bytes the way a download
    // does, even under a stale stored path, instead of leaking them.
    #[tokio::test]
    async fn delete_removes_bytes_under_a_stale_stored_path() {
        let f = fixture(0).await;
        let blob_name = Uuid::new_v4().to_string();
        let blob = f.manager.files_root().join(&blob_name);
        std::fs::write(&blob, b"hello").unwrap();
        let sha: [u8; 32] = Sha256::digest(b"hello").into();
        f.tree
            .add_file(file_tree_root(), "old.txt", 5, &sha, &format!("nonexistent-dir/{blob_name}"))
            .await
            .unwrap();
        let (download, _) = f
            .manager
            .begin_download(&f.tree, &f.session, "/old.txt", 4096, &[])
            .await
            .unwrap();
        drop(download);
        f.tree.delete("/old.txt", &f.session).await.unwrap();
        assert!(!blob.exists(), "deleted file's bytes leaked");
    }

    // Seam review #4: a resume finds its destination by id, wherever the
    // folder has moved since.
    #[tokio::test]
    async fn resume_into_a_moved_folder_files_it_there() {
        let f = fixture(0).await;
        let admin = sess(BaseClass::Admin);
        for (parent, name) in [("/", "a"), ("/a", "b"), ("/", "c")] {
            f.tree
                .create_folder(parent, name, NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin)
                .await
                .unwrap();
        }
        let data = vec![6u8; 9000];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let (upload, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/a/b", "m.bin", data.len() as u64, 4096, sha, None)
            .await
            .unwrap();
        let id = upload.id();
        f.manager.release(upload).await;
        f.tree.move_node("/a", "/c", &admin).await.unwrap();

        let (mut upload, _) = f
            .manager
            .begin_upload(&f.tree, &f.session, "/", "ignored", data.len() as u64, 4096, sha, Some(id))
            .await
            .unwrap();
        for (i, hash, chunk) in chunked(&data, 4096) {
            f.manager.write_chunk(&mut upload, i, &hash, chunk).await.unwrap();
        }
        f.manager.finish(&f.tree, upload).await.unwrap();
        assert!(f.tree.resolve("/c/a/b/m.bin").await.is_ok());
    }

    // XFER-10 / OPS-2: files_root is made absolute (so stored paths survive
    // a change of working directory) and, on Unix, private.
    #[cfg(unix)]
    #[tokio::test]
    async fn files_root_is_absolute_and_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // The same directory, spelled relative to the current one.
        let cwd = std::env::current_dir().unwrap();
        let mut relative = PathBuf::new();
        for _ in cwd.components().skip(1) {
            relative.push("..");
        }
        relative.push(dir.path().strip_prefix("/").unwrap());
        relative.push("files");
        assert!(relative.is_relative());

        let pool = kdx_storage::connect(&dir.path().join("t.db")).await.unwrap();
        let tree = FileTree::load(pool.clone()).await.unwrap();
        let manager = TransferManager::new(
            pool.clone(),
            TransferConfig {
                files_root: relative,
                max_upload_bytes_per_sec: 0,
                max_download_bytes_per_sec: 0,
            },
        )
        .await
        .unwrap();
        let mode = std::fs::metadata(manager.files_root()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);

        let session = fixture(0).await.session;
        let data = vec![1u8; 100];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let (mut upload, _) = manager
            .begin_upload(&tree, &session, "/", "abs.bin", 100, 4096, sha, None)
            .await
            .unwrap();
        let row = transfer_state::get(&pool, &upload.id().to_string()).await.unwrap().unwrap();
        assert!(Path::new(&row.temp_path).is_absolute(), "{}", row.temp_path);
        let part_mode = std::fs::metadata(&row.temp_path).unwrap().permissions().mode();
        assert_eq!(part_mode & 0o777, 0o600);

        manager.write_chunk(&mut upload, 0, &sha, &data).await.unwrap();
        manager.finish(&tree, upload).await.unwrap();
        let node = tree.resolve("/abs.bin").await.unwrap();
        let blob = node.storage_path.unwrap();
        assert!(Path::new(&blob).is_absolute(), "{blob}");
        let blob_mode = std::fs::metadata(&blob).unwrap().permissions().mode();
        assert_eq!(blob_mode & 0o777, 0o600);
    }

    // ---- drop-box name oracle (round 3, G3) ---------------------------------

    /// A User-class session for `username`, on its own account.
    fn user(username: &str) -> Session {
        Session {
            id: Uuid::new_v4(),
            account_id: format!("acct-{username}"),
            username: username.into(),
            class: BaseClass::User,
            privileges: BaseClass::User.privileges() | Privileges::FILE_UPLOAD,
            expires_at: Instant::now() + Duration::from_secs(600),
        }
    }

    /// `/drop`: a drop box owned by bob that Users may upload into.
    async fn drop_box(f: &Fixture) -> Node {
        f.tree
            .create_folder("/", "drop", NodeKind::DropBox, BaseClass::Guest, BaseClass::User, Some("bob"), &sess(BaseClass::Admin))
            .await
            .unwrap();
        f.tree.resolve("/drop").await.unwrap()
    }

    async fn begin(
        f: &Fixture,
        session: &Session,
        path: &str,
        name: &str,
        data: &[u8],
    ) -> Result<(ActiveUpload, AcceptInfo), TransferError> {
        let sha: [u8; 32] = Sha256::digest(data).into();
        f.manager
            .begin_upload(&f.tree, session, path, name, data.len() as u64, 4096, sha, None)
            .await
    }

    async fn resume(f: &Fixture, session: &Session, id: Uuid, data: &[u8]) -> (ActiveUpload, AcceptInfo) {
        let sha: [u8; 32] = Sha256::digest(data).into();
        f.manager
            .begin_upload(&f.tree, session, "/ignored", "ignored", data.len() as u64, 4096, sha, Some(id))
            .await
            .unwrap()
    }

    /// Send whatever chunks of `data` `upload` lacks, then finish it.
    async fn complete(f: &Fixture, mut upload: ActiveUpload, data: &[u8]) -> Result<(), TransferError> {
        for (i, hash, chunk) in chunked(data, upload.chunk_size as usize) {
            if !upload.bitmap[i as usize] {
                f.manager.write_chunk(&mut upload, i, &hash, chunk).await.unwrap();
            }
        }
        f.manager.finish(&f.tree, upload).await
    }

    /// The name upload `id`'s row says it is headed for.
    async fn row_name(f: &Fixture, id: Uuid) -> String {
        transfer_state::get(&f.pool, &id.to_string()).await.unwrap().expect("row present").name
    }

    /// (name, size) of every entry in `path`, as an admin sees them.
    async fn listing(f: &Fixture, path: &str) -> Vec<(String, u64)> {
        f.tree
            .list(path, &sess(BaseClass::Admin))
            .await
            .unwrap()
            .into_iter()
            .map(|e| (e.name, e.size))
            .collect()
    }

    fn entry(name: &str, size: usize) -> (String, u64) {
        (name.to_string(), size as u64)
    }

    // A non-owner's upload into a drop box is answered the same whether
    // or not its name is taken; a taken one is stored under a variant.
    #[tokio::test]
    async fn blind_upload_with_a_taken_name_is_stored_as_a_variant_and_answered_alike() {
        let f = fixture(0).await;
        let inbox = drop_box(&f).await;
        f.tree.add_file(&inbox.id, "report.pdf", 1, &[0u8; 32], "/elsewhere/r").await.unwrap();
        let alice = user("alice");
        let data = vec![4u8; 9000];

        let (taken, taken_accept) = begin(&f, &alice, "/drop", "report.pdf", &data).await.unwrap();
        let (fresh, fresh_accept) = begin(&f, &alice, "/drop", "fresh.pdf", &data).await.unwrap();
        // Everything in the reply but the (random) transfer id is the same.
        assert_ne!(taken_accept.transfer_id, fresh_accept.transfer_id);
        let shape = |a: &AcceptInfo| (a.chunk_size, a.total_chunks, a.size, a.sha256, a.have_bitmap.clone());
        assert_eq!(shape(&taken_accept), shape(&fresh_accept));
        assert_eq!(row_name(&f, taken.id()).await, "report (2).pdf");
        assert_eq!(row_name(&f, fresh.id()).await, "fresh.pdf");
        complete(&f, taken, &data).await.unwrap();
        complete(&f, fresh, &data).await.unwrap();
        assert_eq!(
            listing(&f, "/drop").await,
            [entry("fresh.pdf", 9000), entry("report (2).pdf", 9000), entry("report.pdf", 1)]
        );
        // The next one gets the next free variant.
        let (again, _) = begin(&f, &alice, "/drop", "report.pdf", &data).await.unwrap();
        assert_eq!(row_name(&f, again.id()).await, "report (3).pdf");
        complete(&f, again, &data).await.unwrap();
        assert!(f.tree.resolve("/drop/report (3).pdf").await.is_ok());
    }

    // Uploads racing for one name in a drop box each get their own: the
    // pick and the reservation are one step, and a name taken behind an
    // upload's back by the time it finishes is passed over too.
    #[tokio::test]
    async fn concurrent_blind_uploads_of_one_name_get_distinct_names() {
        let f = fixture(0).await;
        let inbox = drop_box(&f).await;
        f.tree.add_file(&inbox.id, "x.bin", 1, &[0u8; 32], "/elsewhere/x").await.unwrap();
        let (alice, carol, dave) = (user("alice"), user("carol"), user("dave"));
        let data = vec![5u8; 5000];

        let (a1, _) = begin(&f, &alice, "/drop", "x.bin", &data).await.unwrap();
        let (c1, _) = begin(&f, &carol, "/drop", "x.bin", &data).await.unwrap();
        let (a2, _) = begin(&f, &alice, "/drop", "x.bin", &data).await.unwrap();
        assert_eq!(row_name(&f, a1.id()).await, "x (2).bin");
        assert_eq!(row_name(&f, c1.id()).await, "x (3).bin");
        assert_eq!(row_name(&f, a2.id()).await, "x (4).bin");
        // A name merely reserved by a live upload is passed over as well.
        let (y1, _) = begin(&f, &carol, "/drop", "y.bin", &data).await.unwrap();
        let (y2, _) = begin(&f, &dave, "/drop", "y.bin", &data).await.unwrap();
        assert_eq!(row_name(&f, y1.id()).await, "y.bin");
        assert_eq!(row_name(&f, y2.id()).await, "y (2).bin");

        // The owner files "x (3).bin" directly while carol's upload is
        // headed there: carol's lands on the first name neither filed nor
        // reserved.
        f.tree.add_file(&inbox.id, "x (3).bin", 1, &[0u8; 32], "/elsewhere/x3").await.unwrap();
        complete(&f, c1, &data).await.unwrap();
        for upload in [a1, a2, y1, y2] {
            complete(&f, upload, &data).await.unwrap();
        }
        assert_eq!(
            listing(&f, "/drop").await,
            [
                entry("x (2).bin", 5000),
                entry("x (3).bin", 1),
                entry("x (4).bin", 5000),
                entry("x (5).bin", 5000),
                entry("x.bin", 1),
                entry("y (2).bin", 5000),
                entry("y.bin", 5000),
            ]
        );
        assert!(transfer_state::list_stale(&f.pool, 0).await.unwrap().is_empty());
    }

    // Owners and admins can list the box, so they keep the explicit answer.
    #[tokio::test]
    async fn owner_and_admin_uploads_still_report_a_taken_name() {
        let f = fixture(0).await;
        let inbox = drop_box(&f).await;
        f.tree.add_file(&inbox.id, "a.txt", 1, &[0u8; 32], "/elsewhere/a").await.unwrap();
        let data = vec![6u8; 100];
        let bob = user("bob");
        let mut root = user("root");
        root.class = BaseClass::Admin;
        root.privileges = BaseClass::Admin.privileges();
        for session in [&bob, &root] {
            let result = begin(&f, session, "/drop", "a.txt", &data).await;
            assert!(matches!(result, Err(TransferError::Tree(TreeError::Exists))), "{}", session.username);
        }
        // A non-owner's reservation is no secret from the owner...
        let alice = user("alice");
        let (held, _) = begin(&f, &alice, "/drop", "new.bin", &data).await.unwrap();
        let result = begin(&f, &bob, "/drop", "new.bin", &data).await;
        assert!(matches!(result, Err(TransferError::Tree(TreeError::Exists))));
        // ...but the owner's is from the non-owner.
        let (bobs, _) = begin(&f, &bob, "/drop", "other.bin", &data).await.unwrap();
        let (alices, _) = begin(&f, &alice, "/drop", "other.bin", &data).await.unwrap();
        assert_eq!(row_name(&f, bobs.id()).await, "other.bin");
        assert_eq!(row_name(&f, alices.id()).await, "other (2).bin");
        drop((held, bobs, alices));
    }

    // A renamed upload resumes into the name its row carries; one whose
    // name was taken while it was paused moves on, row and all, unseen.
    #[tokio::test]
    async fn resume_of_a_renamed_blind_upload_follows_its_stored_name() {
        let f = fixture(0).await;
        let inbox = drop_box(&f).await;
        f.tree.add_file(&inbox.id, "a.txt", 1, &[0u8; 32], "/elsewhere/a").await.unwrap();
        let alice = user("alice");
        let data: Vec<u8> = (0..12_000u32).map(|i| (i % 251) as u8).collect();

        let (mut upload, _) = begin(&f, &alice, "/drop", "a.txt", &data).await.unwrap();
        let first = upload.id();
        let (i, hash, chunk) = chunked(&data, 4096)[0];
        f.manager.write_chunk(&mut upload, i, &hash, chunk).await.unwrap();
        drop(upload);
        wait_released(&f, first).await;
        assert_eq!(row_name(&f, first).await, "a (2).txt");
        let (upload, accept) = resume(&f, &alice, first, &data).await;
        assert_eq!(BitVec::<u8, Lsb0>::from_vec(accept.have_bitmap).count_ones(), 1);
        complete(&f, upload, &data).await.unwrap();

        let (upload, _) = begin(&f, &alice, "/drop", "a.txt", &data).await.unwrap();
        let second = upload.id();
        assert_eq!(row_name(&f, second).await, "a (3).txt");
        f.manager.release(upload).await;
        f.tree.add_file(&inbox.id, "a (3).txt", 1, &[0u8; 32], "/elsewhere/a3").await.unwrap();
        let (upload, accept) = resume(&f, &alice, second, &data).await;
        assert_eq!(accept.transfer_id, *second.as_bytes());
        assert_eq!(row_name(&f, second).await, "a (4).txt");
        complete(&f, upload, &data).await.unwrap();

        assert_eq!(
            listing(&f, "/drop").await,
            [entry("a (2).txt", 12_000), entry("a (3).txt", 1), entry("a (4).txt", 12_000), entry("a.txt", 1)]
        );
        assert!(transfer_state::list_stale(&f.pool, 0).await.unwrap().is_empty());
    }

    // A blind upload's finish filed it under a re-picked name, then the
    // server died before moving the bytes: the resume completes that entry
    // instead of filing a second one.
    #[tokio::test]
    async fn blind_resume_after_a_crash_mid_finish_files_it_once() {
        let f = fixture(0).await;
        let inbox = drop_box(&f).await;
        f.tree.add_file(&inbox.id, "c.bin", 1, &[0u8; 32], "/elsewhere/c").await.unwrap();
        let alice = user("alice");
        let data: Vec<u8> = (0..9000u32).map(|i| (i % 239) as u8).collect();
        let sha: [u8; 32] = Sha256::digest(&data).into();
        let (mut upload, _) = begin(&f, &alice, "/drop", "c.bin", &data).await.unwrap();
        let id = upload.id();
        for (i, hash, chunk) in chunked(&data, 4096) {
            f.manager.write_chunk(&mut upload, i, &hash, chunk).await.unwrap();
        }
        f.manager.release(upload).await;
        let blob = blob_of(&f, id).display().to_string();
        f.tree.add_file(&inbox.id, "c (7).bin", data.len() as u64, &sha, &blob).await.unwrap();

        let (upload, _) = resume(&f, &alice, id, &data).await;
        assert!(upload.is_complete());
        f.manager.finish(&f.tree, upload).await.unwrap();
        assert_eq!(listing(&f, "/drop").await, [entry("c (7).bin", 9000), entry("c.bin", 1)]);
        assert_eq!(std::fs::read(blob_of(&f, id)).unwrap(), data);
        assert!(!part_of(&f, id).exists());
    }

    // ---- orphan blob sweep (round 3, G3) -------------------------------------

    const T0: u64 = 1_800_000_000;
    const DAY: u64 = 24 * 60 * 60;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// Names in the quarantine, sorted (none if it doesn't exist).
    fn quarantined(f: &Fixture) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(f.manager.files_root().join(QUARANTINE_DIR)) else {
            return Vec::new();
        };
        let mut names: Vec<String> =
            entries.map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn orphan_blob_is_quarantined_then_purged_after_retention() {
        let f = fixture(0).await;
        let orphan = Uuid::new_v4();
        std::fs::write(blob_of(&f, orphan), b"lost bytes").unwrap();
        let swept = f.manager.shared.sweep_orphan_blobs(at(T0)).await;
        assert_eq!(swept, OrphanSweep { quarantined: 1, purged: 0 });
        assert!(!blob_of(&f, orphan).exists());
        let quarantine = f.manager.files_root().join(QUARANTINE_DIR);
        let kept = quarantine.join(format!("{orphan}.{T0}"));
        assert_eq!(std::fs::read(&kept).unwrap(), b"lost bytes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&quarantine).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        // What isn't named like a quarantined blob is never purged.
        let other = Uuid::new_v4();
        for name in [
            "README".to_string(),
            other.to_string(),
            format!("{other}.12x"),
            format!("{}.5", other.simple()),
        ] {
            std::fs::write(quarantine.join(name), b"x").unwrap();
        }
        std::fs::create_dir(quarantine.join(format!("{other}.5"))).unwrap();

        // A second short of the retention: kept.
        let swept = f.manager.shared.sweep_orphan_blobs(at(T0 + 30 * DAY - 1)).await;
        assert_eq!(swept, OrphanSweep::default());
        assert!(kept.exists());
        let swept = f.manager.shared.sweep_orphan_blobs(at(T0 + 30 * DAY)).await;
        assert_eq!(swept, OrphanSweep { quarantined: 0, purged: 1 });
        assert!(!kept.exists());
        assert_eq!(quarantined(&f).len(), 5);
    }

    #[tokio::test]
    async fn quarantine_is_kept_without_a_retention() {
        let limits = TransferLimits {
            orphan_retention: None,
            ..TransferLimits::default()
        };
        let f = fixture_with(0, limits).await;
        let orphan = Uuid::new_v4();
        std::fs::write(blob_of(&f, orphan), b"x").unwrap();
        assert_eq!(f.manager.shared.sweep_orphan_blobs(at(T0)).await.quarantined, 1);
        assert_eq!(f.manager.shared.sweep_orphan_blobs(at(T0 + 3650 * DAY)).await.purged, 0);
        assert_eq!(quarantined(&f), [format!("{orphan}.{T0}")]);
    }

    #[tokio::test]
    async fn orphan_sweep_leaves_referenced_unfinished_live_and_foreign_files_alone() {
        let f = fixture(0).await;
        let data = vec![7u8; 5000];
        let sha: [u8; 32] = Sha256::digest(&data).into();
        // A finished upload's blob.
        let (upload, _) = begin(&f, &f.session, "/", "done.bin", &data).await.unwrap();
        complete(&f, upload, &data).await.unwrap();
        // A blob an entry names under a stale path (found by name, the way
        // downloads find it).
        let stale = Uuid::new_v4();
        std::fs::write(blob_of(&f, stale), b"x").unwrap();
        f.tree
            .add_file(file_tree_root(), "old.bin", 1, &sha, &format!("gone-dir/{stale}"))
            .await
            .unwrap();
        // A blob an entry reaches through a symlink elsewhere.
        #[cfg(unix)]
        {
            let linked = Uuid::new_v4();
            std::fs::write(blob_of(&f, linked), b"x").unwrap();
            let legacy = f._dir.path().join("legacy");
            std::fs::create_dir(&legacy).unwrap();
            std::os::unix::fs::symlink(blob_of(&f, linked), legacy.join("a.bin")).unwrap();
            let stored = legacy.join("a.bin").display().to_string();
            f.tree.add_file(file_tree_root(), "linked.bin", 1, &sha, &stored).await.unwrap();
        }
        // An unfinished upload: its partial, and a blob under its id (a
        // finish rolled back whose startup repair failed).
        let (upload, _) = begin(&f, &f.session, "/", "paused.bin", &data).await.unwrap();
        let paused = upload.id();
        f.manager.release(upload).await;
        std::fs::write(blob_of(&f, paused), b"x").unwrap();
        // A live upload, with a blob under its id.
        let (live, _) = begin(&f, &f.session, "/", "live.bin", &data).await.unwrap();
        std::fs::write(blob_of(&f, live.id()), b"x").unwrap();
        // Things not named like a blob, and a directory that is.
        for name in [
            "notes.txt".to_string(),
            Uuid::new_v4().to_string().to_uppercase(),
            Uuid::new_v4().simple().to_string(),
            format!("{}.bak", Uuid::new_v4()),
        ] {
            std::fs::write(f.manager.files_root().join(name), b"x").unwrap();
        }
        std::fs::create_dir(blob_of(&f, Uuid::new_v4())).unwrap();

        let before = stored_files(&f);
        assert_eq!(f.manager.sweep_orphan_blobs().await, OrphanSweep::default());
        assert_eq!(stored_files(&f), before);
        assert!(!f.manager.files_root().join(QUARANTINE_DIR).exists());
        assert!(f.manager.is_live(live.id()));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn orphan_sweep_never_follows_symlinks() {
        use std::os::unix::fs::symlink;
        let f = fixture(0).await;
        let outside = f._dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let victim = outside.join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        // A symlink named like a blob is not a blob: neither it nor its
        // target is moved.
        let link = blob_of(&f, Uuid::new_v4());
        symlink(&victim, &link).unwrap();
        assert_eq!(f.manager.sweep_orphan_blobs().await, OrphanSweep::default());
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");

        // A quarantine that is a symlink to elsewhere isn't used: orphans
        // stay put, and nothing over there is purged.
        let elsewhere = f._dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let old = elsewhere.join(format!("{}.1", Uuid::new_v4()));
        std::fs::write(&old, b"old").unwrap();
        symlink(&elsewhere, f.manager.files_root().join(QUARANTINE_DIR)).unwrap();
        let orphan = blob_of(&f, Uuid::new_v4());
        std::fs::write(&orphan, b"x").unwrap();
        assert_eq!(f.manager.shared.sweep_orphan_blobs(at(T0)).await, OrphanSweep::default());
        assert!(orphan.exists());
        assert!(old.exists());
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 1);
    }
}
