//! Server-side download streaming.
//!
//! Symmetric with upload but with the resume knowledge inverted: on a
//! download the *client* knows which chunks it already holds, so it sends its
//! bitmap in the `TransferRequest` and the server streams only the rest.
//! Each chunk is hashed and throttled exactly like an upload chunk. The
//! server keeps no durable download state — if the client disconnects it just
//! re-requests with an updated bitmap next time.

use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use bitvec::prelude::*;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use uuid::Uuid;

use super::manager::{
    chunk_count, Claim, TransferError, TransferManager, MAX_CHUNK, MAX_TOTAL_CHUNKS, MIN_CHUNK,
};
use super::throttle::{reserve_shared, wait_until, SharedBucket};
use crate::auth::Session;
use crate::files::FileTree;

/// One chunk ready to send to the client.
pub struct DownloadChunk {
    pub index: u32,
    pub hash: [u8; 32],
    pub data: Bytes,
}

/// A live download: the connection task pulls chunks from it and frames them
/// as `TransferData`. Chunks the client already has are skipped. Dropping it
/// frees the account's download slot.
pub struct ActiveDownload {
    id: Uuid,
    /// Read on the blocking pool; the mutex keeps a read abandoned by a
    /// cancelled `next_chunk` from interleaving with the next one.
    file: Arc<Mutex<std::fs::File>>,
    size: u64,
    chunk_size: u32,
    total_chunks: u32,
    sha256: [u8; 32],
    /// Chunks the client already holds (skipped).
    have: BitVec<u8, Lsb0>,
    /// Next index to consider sending.
    cursor: u32,
    /// The account's download throttle (shared by its downloads).
    throttle: SharedBucket,
    /// Throttle charge already made for chunk `.0`, payable at `.1` — kept so
    /// a `next_chunk` cancelled while waiting isn't charged twice.
    charged: Option<(u32, Instant)>,
    _claim: Claim,
}

/// What the connection reports back in `TransferAccept` for a download.
pub struct DownloadAccept {
    pub transfer_id: [u8; 16],
    pub chunk_size: u32,
    pub total_chunks: u32,
    pub size: u64,
    pub sha256: [u8; 32],
    pub have_bitmap: Vec<u8>,
}

/// The chunk size to serve `size` bytes with. The client's choice is kept
/// unless it would need more than `MAX_TOTAL_CHUNKS` chunks; a fresh download
/// then gets the smallest power of two that fits (clients adopt the accept's
/// chunk size). A resume must keep its chunk size, so it is refused instead.
fn download_chunk_size(size: u64, requested: u32, resuming: bool) -> Result<u32, TransferError> {
    if chunk_count(size, requested) <= u64::from(MAX_TOTAL_CHUNKS) {
        return Ok(requested);
    }
    if resuming {
        return Err(TransferError::BadChunkSize);
    }
    let needed = size.div_ceil(u64::from(MAX_TOTAL_CHUNKS)).next_power_of_two();
    if needed > u64::from(MAX_CHUNK) {
        return Err(TransferError::TooLarge);
    }
    Ok(needed as u32)
}

impl TransferManager {
    /// Begin a download of `path` for `session`. Enforces read ACLs and
    /// refuses DropBox files. `client_bitmap` is the LSB-first set of chunks
    /// the client already holds (empty for a fresh download). The accepted
    /// chunk size may be larger than requested for very large files.
    pub async fn begin_download(
        &self,
        tree: &FileTree,
        session: &Session,
        path: &str,
        chunk_size: u32,
        client_bitmap: &[u8],
    ) -> Result<(ActiveDownload, DownloadAccept), TransferError> {
        if !(MIN_CHUNK..=MAX_CHUNK).contains(&chunk_size) {
            return Err(TransferError::BadChunkSize);
        }
        let node = tree.open_for_read(path, session).await?;
        let storage_path = node
            .storage_path
            .clone()
            .ok_or(TransferError::UnknownTransfer)?;
        let sha256: [u8; 32] = node
            .sha256
            .clone()
            .and_then(|v| v.try_into().ok())
            .ok_or(TransferError::UnknownTransfer)?;
        let size = node.size;
        let resuming = !client_bitmap.is_empty();
        let chunk_size = download_chunk_size(size, chunk_size, resuming)?;
        let total = chunk_count(size, chunk_size) as u32;

        let (claim, throttle) = self.claim_download(&session.account_id)?;
        let path = self.locate(&storage_path).await;
        let file = tokio::fs::File::open(&path).await?.into_std().await;

        let mut have = BitVec::<u8, Lsb0>::from_vec(client_bitmap.to_vec());
        have.resize(total as usize, false);

        let id = Uuid::new_v4();
        let accept = DownloadAccept {
            transfer_id: *id.as_bytes(),
            chunk_size,
            total_chunks: total,
            size,
            sha256,
            // Echo what the client said it has on a resume; a fresh download
            // has nothing to echo (and a full bitmap could overflow a frame).
            have_bitmap: if resuming {
                have.clone().into_vec()
            } else {
                Vec::new()
            },
        };
        Ok((
            ActiveDownload {
                id,
                file: Arc::new(Mutex::new(file)),
                size,
                chunk_size,
                total_chunks: total,
                sha256,
                have,
                cursor: 0,
                throttle,
                charged: None,
                _claim: claim,
            },
            accept,
        ))
    }
}

impl ActiveDownload {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn total_chunks(&self) -> u32 {
        self.total_chunks
    }

    pub fn whole_hash(&self) -> [u8; 32] {
        self.sha256
    }

    /// Read and return the next chunk the client still needs, or `None` when
    /// the download is complete. Throttled and per-chunk hashed.
    ///
    /// Cancel-safe: if the future is dropped before it completes (e.g. it
    /// lost a `select!`), no chunk is skipped and the throttle isn't charged
    /// again — the next call picks up the same chunk.
    pub async fn next_chunk(&mut self) -> Result<Option<DownloadChunk>, TransferError> {
        while self.cursor < self.total_chunks && self.have[self.cursor as usize] {
            self.cursor += 1; // client already has it
        }
        if self.cursor >= self.total_chunks {
            return Ok(None);
        }
        let index = self.cursor;
        let len = self.chunk_len(index);

        let ready = match self.charged {
            Some((charged, at)) if charged == index => at,
            _ => {
                let at = reserve_shared(&self.throttle, len);
                self.charged = Some((index, at));
                at
            }
        };
        wait_until(ready).await;

        let offset = u64::from(index) * u64::from(self.chunk_size);
        let file = self.file.clone();
        let (data, hash) = tokio::task::spawn_blocking(move || read_chunk(&file, offset, len))
            .await
            .map_err(std::io::Error::other)??;

        self.cursor = index + 1;
        self.charged = None;
        Ok(Some(DownloadChunk {
            index,
            hash,
            data: Bytes::from(data),
        }))
    }

    fn chunk_len(&self, index: u32) -> usize {
        let last = self.total_chunks - 1;
        if index == last {
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

/// Read `len` bytes at `offset` and hash them (blocking).
fn read_chunk(
    file: &Mutex<std::fs::File>,
    offset: u64,
    len: usize,
) -> std::io::Result<(Vec<u8>, [u8; 32])> {
    let mut file = file.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    let hash: [u8; 32] = Sha256::digest(&buf).into();
    Ok((buf, hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{BaseClass, Privileges};
    use crate::transfer::{TransferConfig, TransferLimits};

    struct Fixture {
        manager: TransferManager,
        tree: FileTree,
        session: Session,
        _dir: tempfile::TempDir,
    }

    async fn fixture(limits: TransferLimits) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let pool = kdx_storage::connect(&dir.path().join("t.db")).await.unwrap();
        let tree = FileTree::load(pool.clone()).await.unwrap();
        let manager = TransferManager::with_limits(
            pool,
            TransferConfig {
                files_root: dir.path().join("files"),
                max_upload_bytes_per_sec: 0,
                max_download_bytes_per_sec: 0,
            },
            limits,
        )
        .await
        .unwrap();
        let session = Session {
            id: Uuid::new_v4(),
            account_id: "acct-1".into(),
            username: "phraq".into(),
            class: BaseClass::PowerUser,
            privileges: BaseClass::PowerUser.privileges() | Privileges::FILE_DOWNLOAD,
            expires_at: Instant::now() + std::time::Duration::from_secs(600),
        };
        Fixture {
            manager,
            tree,
            session,
            _dir: dir,
        }
    }

    /// File `data` as `/name` directly (no upload needed).
    async fn seed(f: &Fixture, name: &str, data: &[u8]) {
        let path = f.manager.files_root().join(name);
        std::fs::write(&path, data).unwrap();
        let sha: [u8; 32] = Sha256::digest(data).into();
        f.tree
            .add_file(
                kdx_storage::file_tree::ROOT_ID,
                name,
                data.len() as u64,
                &sha,
                &path.display().to_string(),
            )
            .await
            .unwrap();
    }

    #[test]
    fn chunk_size_grows_only_when_the_chunk_count_would_overflow() {
        let k32 = 32 * 1024;
        // Small enough: the client's choice stands.
        assert_eq!(download_chunk_size(5 << 30, k32, false).unwrap(), k32);
        // 5 GiB at 4 KiB is 1.3M chunks: bumped to 16 KiB (327,680 chunks).
        let bumped = download_chunk_size(5 << 30, 4096, false).unwrap();
        assert_eq!(bumped, 16 * 1024);
        assert!(chunk_count(5 << 30, bumped) <= u64::from(MAX_TOTAL_CHUNKS));
        // A 16 GiB file at the stock 32 KiB size needs 64 KiB chunks.
        assert_eq!(download_chunk_size(16 << 30, k32, false).unwrap(), 64 * 1024);
        // A resume can't change chunk size.
        assert!(matches!(
            download_chunk_size(16 << 30, k32, true),
            Err(TransferError::BadChunkSize)
        ));
        // Beyond what even the largest chunk can cover.
        assert!(matches!(
            download_chunk_size(1 << 40, k32, false),
            Err(TransferError::TooLarge)
        ));
    }

    #[tokio::test]
    async fn fresh_download_accept_has_no_bitmap() {
        let f = fixture(TransferLimits::default()).await;
        let data = vec![7u8; 3 * 4096 + 5];
        seed(&f, "f.bin", &data).await;
        let (_dl, accept) = f
            .manager
            .begin_download(&f.tree, &f.session, "/f.bin", 4096, &[])
            .await
            .unwrap();
        assert_eq!(accept.total_chunks, 4);
        assert!(accept.have_bitmap.is_empty());

        let (_dl, accept) = f
            .manager
            .begin_download(&f.tree, &f.session, "/f.bin", 4096, &[0b0101])
            .await
            .unwrap();
        assert_eq!(accept.have_bitmap, vec![0b0101]);
    }

    #[tokio::test]
    async fn cancelled_next_chunk_skips_nothing() {
        let f = fixture(TransferLimits::default()).await;
        let data: Vec<u8> = (0..4 * 4096u32).map(|i| (i % 251) as u8).collect();
        seed(&f, "c.bin", &data).await;
        let (mut dl, _) = f
            .manager
            .begin_download(&f.tree, &f.session, "/c.bin", 4096, &[])
            .await
            .unwrap();
        let mut got = Vec::new();
        loop {
            // Abandon every other call before it can finish.
            let mut call = Box::pin(dl.next_chunk());
            let polled = futures_util::poll!(call.as_mut());
            drop(call);
            match polled {
                std::task::Poll::Ready(Ok(None)) => break,
                std::task::Poll::Ready(Ok(Some(chunk))) => {
                    got.push(chunk.index);
                    continue;
                }
                std::task::Poll::Ready(Err(e)) => panic!("{e}"),
                std::task::Poll::Pending => {}
            }
            match dl.next_chunk().await.unwrap() {
                Some(chunk) => got.push(chunk.index),
                None => break,
            }
        }
        assert_eq!(got, vec![0, 1, 2, 3]);
    }

    // XFER-9: downloads per account are capped across connections.
    #[tokio::test]
    async fn concurrent_downloads_per_account_are_capped() {
        let f = fixture(TransferLimits {
            max_downloads_per_account: 1,
            ..TransferLimits::default()
        })
        .await;
        seed(&f, "d.bin", b"hello").await;
        let (first, _) = f
            .manager
            .begin_download(&f.tree, &f.session, "/d.bin", 4096, &[])
            .await
            .unwrap();
        let second = f
            .manager
            .begin_download(&f.tree, &f.session, "/d.bin", 4096, &[])
            .await;
        assert!(matches!(second, Err(TransferError::TooManyTransfers)));
        drop(first);
        f.manager
            .begin_download(&f.tree, &f.session, "/d.bin", 4096, &[])
            .await
            .unwrap();
    }

    // XFER-9: a server-wide cap applies across accounts.
    #[tokio::test]
    async fn server_wide_transfer_cap() {
        let f = fixture(TransferLimits {
            max_concurrent_transfers: 1,
            ..TransferLimits::default()
        })
        .await;
        seed(&f, "d.bin", b"hello").await;
        let (_first, _) = f
            .manager
            .begin_download(&f.tree, &f.session, "/d.bin", 4096, &[])
            .await
            .unwrap();
        let mut other = f.session.clone();
        other.account_id = "acct-2".into();
        let second = f
            .manager
            .begin_download(&f.tree, &other, "/d.bin", 4096, &[])
            .await;
        assert!(matches!(second, Err(TransferError::ServerBusy)));
    }
}
