//! Client-side transfer helpers: chunk math, the received-chunk bitmap, and
//! the `.kdxpart` resume sidecar. The upload/download state machines that use
//! these live in the connection actor (they need the socket).

use std::path::{Path, PathBuf};

use bitvec::prelude::*;
use uuid::Uuid;

/// Default chunk size the client requests (32 KiB, matching the server).
pub const DEFAULT_CHUNK_SIZE: u32 = 32 * 1024;

pub type ChunkBitmap = BitVec<u8, Lsb0>;

/// Number of chunks a file of `size` splits into at `chunk_size`.
pub fn total_chunks(size: u64, chunk_size: u32) -> u32 {
    if size == 0 {
        0
    } else {
        size.div_ceil(chunk_size as u64) as u32
    }
}

/// Byte length of chunk `index` given the total size.
pub fn chunk_len(size: u64, chunk_size: u32, index: u32, total: u32) -> usize {
    if total == 0 {
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

/// A resume sidecar written next to a partially-downloaded file. Records
/// enough to verify a resume request matches and which chunks are present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sidecar {
    pub transfer_id: [u8; 16],
    pub size: u64,
    pub chunk_size: u32,
    pub sha256: [u8; 32],
    pub bitmap: Vec<u8>,
}

impl Sidecar {
    pub fn path_for(local: &Path) -> PathBuf {
        let mut s = local.as_os_str().to_owned();
        s.push(".kdxpart");
        PathBuf::from(s)
    }

    /// Serialize as a tiny line-oriented text file (no toml dep here).
    pub fn write(&self, local: &Path) -> std::io::Result<()> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let body = format!(
            "id={}\nsize={}\nchunk_size={}\nsha256={}\nbitmap={}\n",
            Uuid::from_bytes(self.transfer_id),
            self.size,
            self.chunk_size,
            b64.encode(self.sha256),
            b64.encode(&self.bitmap),
        );
        std::fs::write(Self::path_for(local), body)
    }

    pub fn read(local: &Path) -> Option<Sidecar> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let text = std::fs::read_to_string(Self::path_for(local)).ok()?;
        let mut id = None;
        let mut size = None;
        let mut chunk_size = None;
        let mut sha256 = None;
        let mut bitmap = None;
        for line in text.lines() {
            let (k, v) = line.split_once('=')?;
            match k {
                "id" => id = Uuid::parse_str(v).ok().map(|u| *u.as_bytes()),
                "size" => size = v.parse().ok(),
                "chunk_size" => chunk_size = v.parse().ok(),
                "sha256" => {
                    sha256 = b64.decode(v).ok().and_then(|b| b.try_into().ok());
                }
                "bitmap" => bitmap = b64.decode(v).ok(),
                _ => {}
            }
        }
        Some(Sidecar {
            transfer_id: id?,
            size: size?,
            chunk_size: chunk_size?,
            sha256: sha256?,
            bitmap: bitmap?,
        })
    }

    pub fn remove(local: &Path) {
        let _ = std::fs::remove_file(Self::path_for(local));
    }
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
    }

    #[test]
    fn sidecar_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("file.bin");
        let sc = Sidecar {
            transfer_id: [7u8; 16],
            size: 12345,
            chunk_size: 32 * 1024,
            sha256: [9u8; 32],
            bitmap: vec![0b1010_1010, 0b0000_0011],
        };
        sc.write(&local).unwrap();
        assert_eq!(Sidecar::read(&local).unwrap(), sc);
        Sidecar::remove(&local);
        assert!(Sidecar::read(&local).is_none());
    }
}
