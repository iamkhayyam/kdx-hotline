//! Server-side upload handling with resume.
//!
//! An upload's durable state is a `transfer_state` row (destination, sizes,
//! expected hash, received-chunk bitmap) plus a temp file of the bytes so
//! far. The bitmap row is updated after every accepted chunk, so a
//! disconnect or crash loses at most the chunk in flight; on resume the
//! client is told exactly which chunks the server already holds and sends
//! only the rest. Chunks are hash-checked individually on receipt and the
//! whole file is hash-verified before it enters the file tree.

use std::io::SeekFrom;
use std::path::PathBuf;

use bitvec::prelude::*;
use kdx_storage::transfer_state::{self, TransferRow};
use kdx_storage::SqlitePool;
use sha2::{Digest, Sha256};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tracing::debug;
use uuid::Uuid;

use super::throttle::TokenBucket;
use crate::auth::Session;
use crate::files::{FileTree, TreeError};

/// Chunk sizes a client may request.
pub const MIN_CHUNK: u32 = 4 * 1024;
pub const MAX_CHUNK: u32 = 256 * 1024;
/// Largest accepted file (sanity cap; adjust when real deployments need it).
pub const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024;

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
}

/// Server-wide transfer services: where files land and how fast uploads may
/// flow.
pub struct TransferConfig {
    /// Completed files are stored here as `<uuid>` blobs; partials as
    /// `<uuid>.part`.
    pub files_root: PathBuf,
    /// Per-transfer upload throttle, bytes/sec. 0 = unlimited.
    pub max_upload_bytes_per_sec: u64,
    /// Per-transfer download throttle, bytes/sec. 0 = unlimited.
    pub max_download_bytes_per_sec: u64,
}

pub struct TransferManager {
    pool: SqlitePool,
    config: TransferConfig,
}

/// One live upload, owned by its connection task.
pub struct ActiveUpload {
    id: Uuid,
    account_id: String,
    parent_id: String,
    name: String,
    size: u64,
    chunk_size: u32,
    total_chunks: u32,
    expected_sha256: [u8; 32],
    bitmap: BitVec<u8, Lsb0>,
    temp_path: PathBuf,
    file: File,
    throttle: TokenBucket,
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

fn total_chunks(size: u64, chunk_size: u32) -> u32 {
    if size == 0 {
        0
    } else {
        size.div_ceil(chunk_size as u64) as u32
    }
}

impl TransferManager {
    pub async fn new(pool: SqlitePool, config: TransferConfig) -> Result<Self, TransferError> {
        tokio::fs::create_dir_all(&config.files_root).await?;
        Ok(Self { pool, config })
    }

    /// Configured download throttle in bytes/sec (0 = unlimited).
    pub(crate) fn download_rate(&self) -> u64 {
        self.config.max_download_bytes_per_sec
    }

    /// Configured upload throttle in bytes/sec (0 = unlimited).
    pub(crate) fn upload_rate(&self) -> u64 {
        self.config.max_upload_bytes_per_sec
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
            return self.resume_upload(session, resume_id, size, chunk_size, sha256).await;
        }

        if !(MIN_CHUNK..=MAX_CHUNK).contains(&chunk_size) {
            return Err(TransferError::BadChunkSize);
        }
        if size > MAX_FILE_SIZE {
            return Err(TransferError::TooLarge);
        }
        let parent = tree.prepare_upload(path, name, session).await?;

        let id = Uuid::new_v4();
        let chunks = total_chunks(size, chunk_size);
        let bitmap = bitvec![u8, Lsb0; 0; chunks as usize];
        let temp_path = self.config.files_root.join(format!("{id}.part"));
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&temp_path)
            .await?;
        file.set_len(size).await?;

        transfer_state::create(
            &self.pool,
            &TransferRow {
                id: id.to_string(),
                account_id: session.account_id.clone(),
                parent_id: parent.id.clone(),
                name: name.to_owned(),
                size: size as i64,
                chunk_size: chunk_size as i64,
                sha256: sha256.to_vec(),
                bitmap: bitmap.clone().into_vec(),
                temp_path: temp_path.display().to_string(),
            },
        )
        .await?;
        debug!(%id, name, size, "upload started");

        let accept = AcceptInfo {
            transfer_id: *id.as_bytes(),
            chunk_size,
            total_chunks: chunks,
            size,
            sha256,
            have_bitmap: Vec::new(),
        };
        Ok((
            ActiveUpload {
                id,
                account_id: session.account_id.clone(),
                parent_id: parent.id,
                name: name.to_owned(),
                size,
                chunk_size,
                total_chunks: chunks,
                expected_sha256: sha256,
                bitmap,
                temp_path,
                file,
                throttle: TokenBucket::new(self.config.max_upload_bytes_per_sec),
            },
            accept,
        ))
    }

    async fn resume_upload(
        &self,
        session: &Session,
        resume_id: Uuid,
        size: u64,
        chunk_size: u32,
        sha256: [u8; 32],
    ) -> Result<(ActiveUpload, AcceptInfo), TransferError> {
        let row = transfer_state::get(&self.pool, &resume_id.to_string())
            .await?
            .ok_or(TransferError::UnknownTransfer)?;
        // Resumes must come from the same account and describe the same file.
        if row.account_id != session.account_id {
            return Err(TransferError::UnknownTransfer);
        }
        if row.size as u64 != size
            || row.chunk_size as u64 != chunk_size as u64
            || row.sha256 != sha256
        {
            return Err(TransferError::ResumeMismatch);
        }

        let chunks = total_chunks(size, chunk_size);
        let mut bitmap = BitVec::<u8, Lsb0>::from_vec(row.bitmap.clone());
        bitmap.truncate(chunks as usize);
        let temp_path = PathBuf::from(&row.temp_path);
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .open(&temp_path)
            .await?;
        debug!(%resume_id, have = bitmap.count_ones(), total = chunks, "upload resumed");

        let accept = AcceptInfo {
            transfer_id: *resume_id.as_bytes(),
            chunk_size,
            total_chunks: chunks,
            size,
            sha256,
            have_bitmap: bitmap.clone().into_vec(),
        };
        Ok((
            ActiveUpload {
                id: resume_id,
                account_id: row.account_id,
                parent_id: row.parent_id,
                name: row.name,
                size,
                chunk_size,
                total_chunks: chunks,
                expected_sha256: sha256,
                bitmap,
                temp_path,
                file,
                throttle: TokenBucket::new(self.config.max_upload_bytes_per_sec),
            },
            accept,
        ))
    }

    /// Accept one chunk: throttle, verify its hash, write it at its offset,
    /// persist the bitmap. Returns `true` when every chunk has arrived.
    pub async fn write_chunk(
        &self,
        upload: &mut ActiveUpload,
        chunk_index: u32,
        chunk_hash: &[u8; 32],
        data: &[u8],
    ) -> Result<bool, TransferError> {
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

        upload.throttle.consume(data.len()).await;

        let offset = chunk_index as u64 * upload.chunk_size as u64;
        upload.file.seek(SeekFrom::Start(offset)).await?;
        upload.file.write_all(data).await?;

        if !upload.bitmap[chunk_index as usize] {
            upload.bitmap.set(chunk_index as usize, true);
            transfer_state::update_bitmap(
                &self.pool,
                &upload.id.to_string(),
                &upload.bitmap.clone().into_vec(),
            )
            .await?;
        }
        Ok(upload.bitmap.count_ones() == upload.total_chunks as usize)
    }

    /// Verify the whole file and promote it into the tree. Consumes the
    /// upload; on hash mismatch the partial state is destroyed (the client
    /// must start over — its source differs from what it announced).
    pub async fn finish(
        &self,
        tree: &FileTree,
        mut upload: ActiveUpload,
    ) -> Result<(), TransferError> {
        upload.file.flush().await?;
        upload.file.seek(SeekFrom::Start(0)).await?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 128 * 1024];
        loop {
            let n = upload.file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != upload.expected_sha256 {
            self.abort(&upload).await;
            return Err(TransferError::FileHashMismatch);
        }

        let final_path = self.config.files_root.join(upload.id.to_string());
        tokio::fs::rename(&upload.temp_path, &final_path).await?;
        tree.add_file(
            &upload.parent_id,
            &upload.name,
            upload.size,
            &upload.expected_sha256,
            &final_path.display().to_string(),
        )
        .await?;
        transfer_state::delete(&self.pool, &upload.id.to_string()).await?;
        debug!(id = %upload.id, name = %upload.name, "upload verified and filed");
        Ok(())
    }

    /// Destroy a transfer's durable state and partial bytes.
    pub async fn abort(&self, upload: &ActiveUpload) {
        let _ = transfer_state::delete(&self.pool, &upload.id.to_string()).await;
        let _ = tokio::fs::remove_file(&upload.temp_path).await;
    }
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
        self.bitmap.count_ones() as f32 / self.total_chunks as f32
    }

    fn expected_chunk_len(&self, chunk_index: u32) -> usize {
        let last = self.total_chunks - 1;
        if chunk_index == last {
            let rem = (self.size % self.chunk_size as u64) as usize;
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
    use tokio::time::Instant;

    struct Fixture {
        manager: TransferManager,
        tree: FileTree,
        session: Session,
        _dir: tempfile::TempDir,
    }

    async fn fixture(rate: u64) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let pool = kdx_storage::connect(&dir.path().join("t.db")).await.unwrap();
        let tree = FileTree::load(pool.clone()).await.unwrap();
        let manager = TransferManager::new(
            pool,
            TransferConfig {
                files_root: dir.path().join("files"),
                max_upload_bytes_per_sec: rate,
                max_download_bytes_per_sec: 0,
            },
        )
        .await
        .unwrap();
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
            _dir: dir,
        }
    }

    fn chunked(data: &[u8], chunk_size: usize) -> Vec<(u32, [u8; 32], &[u8])> {
        data.chunks(chunk_size)
            .enumerate()
            .map(|(i, c)| (i as u32, Sha256::digest(c).into(), c))
            .collect()
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
}
