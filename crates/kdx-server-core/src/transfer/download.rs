//! Server-side download streaming.
//!
//! Symmetric with upload but with the resume knowledge inverted: on a
//! download the *client* knows which chunks it already holds, so it sends its
//! bitmap in the `TransferRequest` and the server streams only the rest.
//! Each chunk is hashed and throttled exactly like an upload chunk. The
//! server keeps no durable download state — if the client disconnects it just
//! re-requests with an updated bitmap next time.

use std::io::SeekFrom;
use std::path::PathBuf;

use bitvec::prelude::*;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use uuid::Uuid;

use super::manager::{TransferError, TransferManager, MAX_CHUNK, MIN_CHUNK};
use super::throttle::TokenBucket;
use crate::auth::Session;
use crate::files::FileTree;

/// One chunk ready to send to the client.
pub struct DownloadChunk {
    pub index: u32,
    pub hash: [u8; 32],
    pub data: Bytes,
}

/// A live download: the connection task pulls chunks from it and frames them
/// as `TransferData`. Chunks the client already has are skipped.
pub struct ActiveDownload {
    id: Uuid,
    file: File,
    size: u64,
    chunk_size: u32,
    total_chunks: u32,
    sha256: [u8; 32],
    /// Chunks the client already holds (skipped).
    have: BitVec<u8, Lsb0>,
    /// Next index to consider sending.
    cursor: u32,
    throttle: TokenBucket,
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

impl TransferManager {
    /// Begin a download of `path` for `session`. Enforces read ACLs and
    /// refuses DropBox files. `client_bitmap` is the LSB-first set of chunks
    /// the client already holds (empty for a fresh download).
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
        let node = tree.open_for_read(path, session.class).await?;
        let storage_path = node
            .storage_path
            .clone()
            .ok_or(TransferError::UnknownTransfer)?;
        let sha256: [u8; 32] = node
            .sha256
            .clone()
            .and_then(|v| v.try_into().ok())
            .ok_or(TransferError::UnknownTransfer)?;

        let file = File::open(&PathBuf::from(storage_path)).await?;
        let size = node.size;
        let total = if size == 0 {
            0
        } else {
            size.div_ceil(chunk_size as u64) as u32
        };
        let mut have = BitVec::<u8, Lsb0>::from_vec(client_bitmap.to_vec());
        have.resize(total as usize, false);

        let id = Uuid::new_v4();
        let accept = DownloadAccept {
            transfer_id: *id.as_bytes(),
            chunk_size,
            total_chunks: total,
            size,
            sha256,
            have_bitmap: have.clone().into_vec(),
        };
        Ok((
            ActiveDownload {
                id,
                file,
                size,
                chunk_size,
                total_chunks: total,
                sha256,
                have,
                cursor: 0,
                throttle: TokenBucket::new(self.download_rate()),
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
    pub async fn next_chunk(&mut self) -> Result<Option<DownloadChunk>, TransferError> {
        while self.cursor < self.total_chunks {
            let index = self.cursor;
            self.cursor += 1;
            if self.have[index as usize] {
                continue; // client already has it
            }

            let len = self.chunk_len(index);
            let offset = index as u64 * self.chunk_size as u64;
            let mut buf = vec![0u8; len];
            self.file.seek(SeekFrom::Start(offset)).await?;
            self.file.read_exact(&mut buf).await?;

            self.throttle.consume(len).await;
            let hash: [u8; 32] = Sha256::digest(&buf).into();
            return Ok(Some(DownloadChunk {
                index,
                hash,
                data: Bytes::from(buf),
            }));
        }
        Ok(None)
    }

    fn chunk_len(&self, index: u32) -> usize {
        let last = self.total_chunks - 1;
        if index == last {
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
