use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::wire::{expect_end, get_str, put_str};
use crate::ProtocolError;

/// Node kinds on the wire (mirror kdx-storage's kind column).
pub const KIND_DIR: u8 = 0;
pub const KIND_FILE: u8 = 1;
pub const KIND_DROPBOX: u8 = 2;
pub const KIND_UPLOAD: u8 = 3;
pub const KIND_ALIAS: u8 = 4;

/// Transfer end/result status codes.
pub const TRANSFER_VERIFIED: u8 = 0;
pub const TRANSFER_HASH_MISMATCH: u8 = 1;
pub const TRANSFER_ABORTED: u8 = 2;

/// Transfer direction (in `TransferRequest`).
pub const DIRECTION_UPLOAD: u8 = 0;
pub const DIRECTION_DOWNLOAD: u8 = 1;

/// Client → server: list a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileListRequest {
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub name: String,
    pub kind: u8,
    pub size: u64,
}

/// Server → client: directory contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileListResponse {
    pub path: String,
    pub entries: Vec<FileEntry>,
}

/// Client → server: create a folder-like node (`kind` is `KIND_DIR`,
/// `KIND_DROPBOX`, or `KIND_UPLOAD`). `min_read_class` / `min_write_class` are
/// base-class thresholds. Requires write access to `path`. The server replies
/// with a `FileListResponse` for `path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCreateFolder {
    pub path: String,
    pub name: String,
    pub kind: u8,
    pub min_read_class: u8,
    pub min_write_class: u8,
}

/// Client → server: delete a node (recursively, for folders). Requires write
/// access to the node. The server replies with a `FileListResponse` for the
/// deleted node's parent directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDelete {
    pub path: String,
}

/// Client → server: move a node into a different folder (Select-for-Move →
/// Move-into), keeping its name. Requires write access to both the node and
/// `dest_path`. The server replies with a `FileListResponse` for `dest_path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMove {
    pub path: String,
    pub dest_path: String,
}

/// Client → server: create an alias entry at `dest_path` pointing to
/// `source_path` (Select-for-Alias → Alias-into). The alias inherits the
/// source's leaf name. Requires `FILE_MANAGE_TREE`; the server additionally
/// enforces write access on `dest_path` and refuses aliases to the root or
/// to another alias. The server replies with a `FileListResponse` for
/// `dest_path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAlias {
    pub source_path: String,
    pub dest_path: String,
}

/// Client → server: (re)build the server's search catalog — a snapshot index
/// of the whole tree. Requires `FILE_MANAGE_TREE`; the catalog does not
/// auto-refresh, so search results reflect the tree as of the last call.
/// Empty payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileGenerateCatalog;

/// Server → client: reply to `FileGenerateCatalog` with the entry count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileCatalogGenerated {
    pub count: u32,
}

/// Client → server: search the catalog. Empty `query` matches everything (a
/// full listing of what the caller may see). Requires `FILE_LIST`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSearchRequest {
    pub query: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSearchEntry {
    pub path: String,
    pub name: String,
    pub kind: u8,
    pub size: u64,
}

/// Server → client: matches, already filtered to the caller's read class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSearchResponse {
    pub entries: Vec<FileSearchEntry>,
}

/// Client → server (in a FileTransferStart packet): request a transfer.
///
/// `direction` selects upload or download. For an **upload**, `size`/`sha256`
/// describe the file being sent and `have_bitmap` is empty. For a
/// **download**, `size`/`sha256` are zero (the server reports them in the
/// accept) and `have_bitmap` carries the chunks the client already holds so
/// a resumed download only re-fetches the rest. `resume_id` of all zeros
/// means a fresh transfer; otherwise it names a prior transfer to resume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRequest {
    pub direction: u8,
    pub path: String,
    pub name: String,
    pub size: u64,
    pub chunk_size: u32,
    pub sha256: [u8; 32],
    pub resume_id: [u8; 16],
    pub have_bitmap: Vec<u8>,
}

/// Server → client (in a FileTransferStart packet): transfer accepted.
///
/// For an upload, `size`/`sha256` echo the request and `have_bitmap` marks
/// chunks the server already holds (LSB-first, empty for a fresh transfer).
/// For a download, `size`/`sha256` tell the client the file's true size and
/// hash to allocate and verify against, and `have_bitmap` echoes the chunks
/// the server will skip (those the client reported having).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferAccept {
    pub transfer_id: [u8; 16],
    pub chunk_size: u32,
    pub total_chunks: u32,
    pub size: u64,
    pub sha256: [u8; 32],
    pub have_bitmap: Vec<u8>,
}

/// Client → server: one chunk of file data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferData {
    pub transfer_id: [u8; 16],
    pub chunk_index: u32,
    pub chunk_hash: [u8; 32],
    pub data: Bytes,
}

/// Server → client: transfer outcome (see TRANSFER_* status codes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferEnd {
    pub transfer_id: [u8; 16],
    pub status: u8,
    pub message: String,
}

impl FileListRequest {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(2 + self.path.len());
        put_str(&mut buf, &self.path);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let path = get_str(&mut payload, "FileListRequest")?;
        expect_end(payload, "FileListRequest")?;
        Ok(Self { path })
    }
}

impl FileListResponse {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.path);
        buf.put_u16(self.entries.len() as u16);
        for entry in &self.entries {
            put_str(&mut buf, &entry.name);
            buf.put_u8(entry.kind);
            buf.put_u64(entry.size);
        }
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let path = get_str(&mut payload, "FileListResponse")?;
        if payload.remaining() < 2 {
            return Err(ProtocolError::MalformedPayload("FileListResponse"));
        }
        let count = payload.get_u16() as usize;
        let mut entries = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            let name = get_str(&mut payload, "FileListResponse")?;
            if payload.remaining() < 9 {
                return Err(ProtocolError::MalformedPayload("FileListResponse"));
            }
            let kind = payload.get_u8();
            let size = payload.get_u64();
            entries.push(FileEntry { name, kind, size });
        }
        expect_end(payload, "FileListResponse")?;
        Ok(Self { path, entries })
    }
}

impl FileCreateFolder {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.path);
        put_str(&mut buf, &self.name);
        buf.put_u8(self.kind);
        buf.put_u8(self.min_read_class);
        buf.put_u8(self.min_write_class);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let path = get_str(&mut payload, "FileCreateFolder")?;
        let name = get_str(&mut payload, "FileCreateFolder")?;
        if payload.remaining() < 3 {
            return Err(ProtocolError::MalformedPayload("FileCreateFolder"));
        }
        let kind = payload.get_u8();
        let min_read_class = payload.get_u8();
        let min_write_class = payload.get_u8();
        expect_end(payload, "FileCreateFolder")?;
        Ok(Self {
            path,
            name,
            kind,
            min_read_class,
            min_write_class,
        })
    }
}

impl FileDelete {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.path);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let path = get_str(&mut payload, "FileDelete")?;
        expect_end(payload, "FileDelete")?;
        Ok(Self { path })
    }
}

impl FileGenerateCatalog {
    pub fn encode(&self) -> Bytes {
        Bytes::new()
    }
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        expect_end(payload, "FileGenerateCatalog")?;
        Ok(Self)
    }
}

impl FileCatalogGenerated {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u32(self.count);
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 4 {
            return Err(ProtocolError::MalformedPayload("FileCatalogGenerated"));
        }
        let count = payload.get_u32();
        expect_end(payload, "FileCatalogGenerated")?;
        Ok(Self { count })
    }
}

impl FileSearchRequest {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.query);
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let query = get_str(&mut payload, "FileSearchRequest")?;
        expect_end(payload, "FileSearchRequest")?;
        Ok(Self { query })
    }
}

impl FileSearchResponse {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u32(self.entries.len() as u32);
        for e in &self.entries {
            put_str(&mut buf, &e.path);
            put_str(&mut buf, &e.name);
            buf.put_u8(e.kind);
            buf.put_u64(e.size);
        }
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 4 {
            return Err(ProtocolError::MalformedPayload("FileSearchResponse"));
        }
        let count = payload.get_u32() as usize;
        let mut entries = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            let path = get_str(&mut payload, "FileSearchResponse")?;
            let name = get_str(&mut payload, "FileSearchResponse")?;
            if payload.remaining() < 9 {
                return Err(ProtocolError::MalformedPayload("FileSearchResponse"));
            }
            let kind = payload.get_u8();
            let size = payload.get_u64();
            entries.push(FileSearchEntry { path, name, kind, size });
        }
        expect_end(payload, "FileSearchResponse")?;
        Ok(Self { entries })
    }
}

impl FileMove {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.path);
        put_str(&mut buf, &self.dest_path);
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let path = get_str(&mut payload, "FileMove")?;
        let dest_path = get_str(&mut payload, "FileMove")?;
        expect_end(payload, "FileMove")?;
        Ok(Self { path, dest_path })
    }
}

impl FileAlias {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.source_path);
        put_str(&mut buf, &self.dest_path);
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let source_path = get_str(&mut payload, "FileAlias")?;
        let dest_path = get_str(&mut payload, "FileAlias")?;
        expect_end(payload, "FileAlias")?;
        Ok(Self { source_path, dest_path })
    }
}

impl TransferRequest {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u8(self.direction);
        put_str(&mut buf, &self.path);
        put_str(&mut buf, &self.name);
        buf.put_u64(self.size);
        buf.put_u32(self.chunk_size);
        buf.put_slice(&self.sha256);
        buf.put_slice(&self.resume_id);
        buf.put_u16(self.have_bitmap.len() as u16);
        buf.put_slice(&self.have_bitmap);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 1 {
            return Err(ProtocolError::MalformedPayload("TransferRequest"));
        }
        let direction = payload.get_u8();
        let path = get_str(&mut payload, "TransferRequest")?;
        let name = get_str(&mut payload, "TransferRequest")?;
        if payload.remaining() < 8 + 4 + 32 + 16 + 2 {
            return Err(ProtocolError::MalformedPayload("TransferRequest"));
        }
        let size = payload.get_u64();
        let chunk_size = payload.get_u32();
        let mut sha256 = [0u8; 32];
        payload.copy_to_slice(&mut sha256);
        let mut resume_id = [0u8; 16];
        payload.copy_to_slice(&mut resume_id);
        let bitmap_len = payload.get_u16() as usize;
        if payload.remaining() != bitmap_len {
            return Err(ProtocolError::MalformedPayload("TransferRequest"));
        }
        Ok(Self {
            direction,
            path,
            name,
            size,
            chunk_size,
            sha256,
            resume_id,
            have_bitmap: payload[..bitmap_len].to_vec(),
        })
    }
}

impl TransferAccept {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(16 + 4 + 4 + 8 + 32 + 2 + self.have_bitmap.len());
        buf.put_slice(&self.transfer_id);
        buf.put_u32(self.chunk_size);
        buf.put_u32(self.total_chunks);
        buf.put_u64(self.size);
        buf.put_slice(&self.sha256);
        buf.put_u16(self.have_bitmap.len() as u16);
        buf.put_slice(&self.have_bitmap);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 16 + 4 + 4 + 8 + 32 + 2 {
            return Err(ProtocolError::MalformedPayload("TransferAccept"));
        }
        let mut transfer_id = [0u8; 16];
        payload.copy_to_slice(&mut transfer_id);
        let chunk_size = payload.get_u32();
        let total_chunks = payload.get_u32();
        let size = payload.get_u64();
        let mut sha256 = [0u8; 32];
        payload.copy_to_slice(&mut sha256);
        let bitmap_len = payload.get_u16() as usize;
        if payload.remaining() != bitmap_len {
            return Err(ProtocolError::MalformedPayload("TransferAccept"));
        }
        Ok(Self {
            transfer_id,
            chunk_size,
            total_chunks,
            size,
            sha256,
            have_bitmap: payload[..bitmap_len].to_vec(),
        })
    }
}

impl TransferData {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(16 + 4 + 32 + self.data.len());
        buf.put_slice(&self.transfer_id);
        buf.put_u32(self.chunk_index);
        buf.put_slice(&self.chunk_hash);
        buf.put_slice(&self.data);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 16 + 4 + 32 {
            return Err(ProtocolError::MalformedPayload("TransferData"));
        }
        let mut transfer_id = [0u8; 16];
        payload.copy_to_slice(&mut transfer_id);
        let chunk_index = payload.get_u32();
        let mut chunk_hash = [0u8; 32];
        payload.copy_to_slice(&mut chunk_hash);
        Ok(Self {
            transfer_id,
            chunk_index,
            chunk_hash,
            data: Bytes::copy_from_slice(payload),
        })
    }
}

impl TransferEnd {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(16 + 1 + 2 + self.message.len());
        buf.put_slice(&self.transfer_id);
        buf.put_u8(self.status);
        put_str(&mut buf, &self.message);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 16 + 1 + 2 {
            return Err(ProtocolError::MalformedPayload("TransferEnd"));
        }
        let mut transfer_id = [0u8; 16];
        payload.copy_to_slice(&mut transfer_id);
        let status = payload.get_u8();
        let message = get_str(&mut payload, "TransferEnd")?;
        expect_end(payload, "TransferEnd")?;
        Ok(Self {
            transfer_id,
            status,
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_round_trip() {
        let list_req = FileListRequest {
            path: "/warez".into(),
        };
        assert_eq!(FileListRequest::decode(&list_req.encode()).unwrap(), list_req);

        let list_resp = FileListResponse {
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
        };
        assert_eq!(
            FileListResponse::decode(&list_resp.encode()).unwrap(),
            list_resp
        );

        let request = TransferRequest {
            direction: DIRECTION_UPLOAD,
            path: "/incoming".into(),
            name: "payload.bin".into(),
            size: 1 << 20,
            chunk_size: 32 * 1024,
            sha256: [5u8; 32],
            resume_id: [0u8; 16],
            have_bitmap: vec![],
        };
        assert_eq!(TransferRequest::decode(&request.encode()).unwrap(), request);

        let download_req = TransferRequest {
            direction: DIRECTION_DOWNLOAD,
            path: "/pub".into(),
            name: "big.iso".into(),
            size: 0,
            chunk_size: 32 * 1024,
            sha256: [0u8; 32],
            resume_id: [7u8; 16],
            have_bitmap: vec![0b0000_1111],
        };
        assert_eq!(
            TransferRequest::decode(&download_req.encode()).unwrap(),
            download_req
        );

        let accept = TransferAccept {
            transfer_id: [9u8; 16],
            chunk_size: 32 * 1024,
            total_chunks: 32,
            size: 1 << 20,
            sha256: [5u8; 32],
            have_bitmap: vec![0b1010_1010],
        };
        assert_eq!(TransferAccept::decode(&accept.encode()).unwrap(), accept);

        let data = TransferData {
            transfer_id: [9u8; 16],
            chunk_index: 7,
            chunk_hash: [3u8; 32],
            data: Bytes::from_static(b"chunk bytes"),
        };
        assert_eq!(TransferData::decode(&data.encode()).unwrap(), data);

        let end = TransferEnd {
            transfer_id: [9u8; 16],
            status: TRANSFER_VERIFIED,
            message: "ok".into(),
        };
        assert_eq!(TransferEnd::decode(&end.encode()).unwrap(), end);
    }

    #[test]
    fn rejects_malformed() {
        assert!(FileListRequest::decode(&[9]).is_err());
        assert!(TransferRequest::decode(&[0, 0]).is_err());
        assert!(TransferData::decode(&[0u8; 20]).is_err());
    }

    #[test]
    fn create_folder_and_delete_round_trip() {
        let mk = FileCreateFolder {
            path: "/pub".into(),
            name: "docs".into(),
            kind: KIND_DROPBOX,
            min_read_class: 0,
            min_write_class: 1,
        };
        assert_eq!(FileCreateFolder::decode(&mk.encode()).unwrap(), mk);

        let del = FileDelete { path: "/pub/docs".into() };
        assert_eq!(FileDelete::decode(&del.encode()).unwrap(), del);

        assert!(FileCreateFolder::decode(&[0, 1, 65]).is_err());
        assert!(FileDelete::decode(&[]).is_err());
    }

    #[test]
    fn catalog_and_search_round_trip() {
        assert!(FileGenerateCatalog::decode(&FileGenerateCatalog.encode()).is_ok());
        let generated = FileCatalogGenerated { count: 42 };
        assert_eq!(FileCatalogGenerated::decode(&generated.encode()).unwrap(), generated);

        let req = FileSearchRequest { query: "readme".into() };
        assert_eq!(FileSearchRequest::decode(&req.encode()).unwrap(), req);

        let resp = FileSearchResponse {
            entries: vec![
                FileSearchEntry {
                    path: "/pub/readme.txt".into(),
                    name: "readme.txt".into(),
                    kind: KIND_FILE,
                    size: 10,
                },
                FileSearchEntry {
                    path: "/pub".into(),
                    name: "pub".into(),
                    kind: KIND_DIR,
                    size: 0,
                },
            ],
        };
        assert_eq!(FileSearchResponse::decode(&resp.encode()).unwrap(), resp);

        assert!(FileCatalogGenerated::decode(&[0, 0]).is_err());
        assert!(FileSearchResponse::decode(&[0, 0]).is_err());
    }

    #[test]
    fn file_move_round_trip() {
        let mv = FileMove {
            path: "/a/sub".into(),
            dest_path: "/b".into(),
        };
        assert_eq!(FileMove::decode(&mv.encode()).unwrap(), mv);
        assert!(FileMove::decode(&[0, 1, 65]).is_err());
    }

    #[test]
    fn file_alias_round_trip() {
        let a = FileAlias {
            source_path: "/pub/readme.txt".into(),
            dest_path: "/aliases".into(),
        };
        assert_eq!(FileAlias::decode(&a.encode()).unwrap(), a);
        // Length-prefix declares 5 bytes but only 1 follows.
        assert!(FileAlias::decode(&[0, 5, 65]).is_err());
    }
}
