//! In-memory virtual file tree, loaded from the `file_nodes` table at
//! startup and written through on mutation. Read-heavy/write-rare, so a
//! `tokio::sync::RwLock` around the whole tree is appropriate here (the
//! hot paths are chat and transfer data, not tree metadata).

use std::collections::HashMap;

use kdx_storage::file_tree::{self, FileNodeRow, ROOT_ID};
use kdx_storage::SqlitePool;
use tokio::sync::RwLock;

use super::acl::{self, AclError};
use crate::auth::BaseClass;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Directory,
    File,
    DropBox,
    UploadFolder,
}

impl NodeKind {
    pub fn from_i64(kind: i64) -> Option<Self> {
        Some(match kind {
            0 => NodeKind::Directory,
            1 => NodeKind::File,
            2 => NodeKind::DropBox,
            3 => NodeKind::UploadFolder,
            _ => return None,
        })
    }

    pub fn as_u8(self) -> u8 {
        match self {
            NodeKind::Directory => 0,
            NodeKind::File => 1,
            NodeKind::DropBox => 2,
            NodeKind::UploadFolder => 3,
        }
    }

    pub fn is_folder(self) -> bool {
        !matches!(self, NodeKind::File)
    }
}

#[derive(Debug, Clone)]
pub struct Node {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub kind: NodeKind,
    pub size: u64,
    pub sha256: Option<Vec<u8>>,
    pub min_class_read: BaseClass,
    pub min_class_write: BaseClass,
    pub storage_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub kind: NodeKind,
    pub size: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum TreeError {
    #[error("path not found")]
    NotFound,
    #[error("not a folder")]
    NotAFolder,
    #[error("not a file")]
    NotAFile,
    #[error("name already exists")]
    Exists,
    #[error(transparent)]
    Acl(#[from] AclError),
    #[error("storage error: {0}")]
    Storage(#[from] kdx_storage::StorageError),
    #[error("corrupt node kind {0}")]
    CorruptKind(i64),
}

struct TreeState {
    nodes: HashMap<String, Node>,
    /// parent id → child ids
    children: HashMap<String, Vec<String>>,
}

pub struct FileTree {
    pool: SqlitePool,
    state: RwLock<TreeState>,
}

fn class_from_i64(v: i64) -> BaseClass {
    BaseClass::try_from((v.clamp(0, 3)) as u8).expect("clamped to valid class")
}

fn node_from_row(row: FileNodeRow) -> Result<Node, TreeError> {
    Ok(Node {
        kind: NodeKind::from_i64(row.kind).ok_or(TreeError::CorruptKind(row.kind))?,
        id: row.id,
        parent_id: row.parent_id,
        name: row.name,
        size: row.size as u64,
        sha256: row.sha256,
        min_class_read: class_from_i64(row.min_class_read),
        min_class_write: class_from_i64(row.min_class_write),
        storage_path: row.storage_path,
    })
}

impl FileTree {
    /// Load the whole tree from the database.
    pub async fn load(pool: SqlitePool) -> Result<Self, TreeError> {
        let rows = file_tree::all(&pool).await?;
        let mut nodes = HashMap::with_capacity(rows.len());
        let mut children: HashMap<String, Vec<String>> = HashMap::new();
        for row in rows {
            let node = node_from_row(row)?;
            if let Some(parent) = &node.parent_id {
                children.entry(parent.clone()).or_default().push(node.id.clone());
            }
            nodes.insert(node.id.clone(), node);
        }
        Ok(Self {
            pool,
            state: RwLock::new(TreeState { nodes, children }),
        })
    }

    /// Resolve a `/`-separated virtual path to a node.
    pub async fn resolve(&self, path: &str) -> Result<Node, TreeError> {
        let state = self.state.read().await;
        Ok(state.resolve(path)?.clone())
    }

    /// List a folder's entries, enforcing read ACLs. DropBoxes refuse
    /// listing for everyone — write-only is structural, not conventional.
    pub async fn list(&self, path: &str, class: BaseClass) -> Result<Vec<Entry>, TreeError> {
        let state = self.state.read().await;
        let node = state.resolve(path)?;
        if !node.kind.is_folder() {
            return Err(TreeError::NotAFolder);
        }
        acl::check_list(node.kind, node.min_class_read, class)?;
        let mut entries: Vec<Entry> = state
            .children
            .get(&node.id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| state.nodes.get(id))
                    .map(|n| Entry {
                        name: n.name.clone(),
                        kind: n.kind,
                        size: n.size,
                    })
                    .collect()
            })
            .unwrap_or_default();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    /// Validate an upload destination and return the parent node. Enforces
    /// write ACLs and name collisions.
    pub async fn prepare_upload(
        &self,
        path: &str,
        name: &str,
        class: BaseClass,
    ) -> Result<Node, TreeError> {
        let state = self.state.read().await;
        let node = state.resolve(path)?;
        if !node.kind.is_folder() {
            return Err(TreeError::NotAFolder);
        }
        acl::check_write(node.kind, node.min_class_write, class)?;
        if let Some(ids) = state.children.get(&node.id) {
            if ids
                .iter()
                .filter_map(|id| state.nodes.get(id))
                .any(|n| n.name == name)
            {
                return Err(TreeError::Exists);
            }
        }
        Ok(node.clone())
    }

    /// Resolve a file for download, enforcing read access on its containing
    /// folder. A file inside a DropBox is refused (write-only is structural,
    /// same rule as listing), as is a file in a folder the class can't read.
    pub async fn open_for_read(&self, path: &str, class: BaseClass) -> Result<Node, TreeError> {
        let state = self.state.read().await;
        let node = state.resolve(path)?;
        if node.kind != NodeKind::File {
            return Err(TreeError::NotAFile);
        }
        // A file always has a parent; apply the parent folder's read ACL.
        let parent = node
            .parent_id
            .as_ref()
            .and_then(|id| state.nodes.get(id))
            .ok_or(TreeError::NotFound)?;
        acl::check_list(parent.kind, parent.min_class_read, class)?;
        Ok(node.clone())
    }

    /// Create a folder-like node (directory/dropbox/upload folder).
    pub async fn create_folder(
        &self,
        parent_path: &str,
        name: &str,
        kind: NodeKind,
        min_class_read: BaseClass,
        min_class_write: BaseClass,
    ) -> Result<Node, TreeError> {
        debug_assert!(kind.is_folder());
        let parent = self.resolve(parent_path).await?;
        let row = file_tree::create_folder(
            &self.pool,
            &parent.id,
            name,
            kind.as_u8() as i64,
            min_class_read as i64,
            min_class_write as i64,
        )
        .await?;
        let node = node_from_row(row)?;
        self.insert_in_memory(node.clone()).await;
        Ok(node)
    }

    /// Record a completed upload as a file node.
    pub async fn add_file(
        &self,
        parent_id: &str,
        name: &str,
        size: u64,
        sha256: &[u8],
        storage_path: &str,
    ) -> Result<Node, TreeError> {
        let row =
            file_tree::create_file(&self.pool, parent_id, name, size as i64, sha256, storage_path)
                .await?;
        let node = node_from_row(row)?;
        self.insert_in_memory(node.clone()).await;
        Ok(node)
    }

    async fn insert_in_memory(&self, node: Node) {
        let mut state = self.state.write().await;
        if let Some(parent) = &node.parent_id {
            state
                .children
                .entry(parent.clone())
                .or_default()
                .push(node.id.clone());
        }
        state.nodes.insert(node.id.clone(), node);
    }
}

impl TreeState {
    fn resolve(&self, path: &str) -> Result<&Node, TreeError> {
        let mut current = self.nodes.get(ROOT_ID).ok_or(TreeError::NotFound)?;
        for segment in path.split('/').filter(|s| !s.is_empty()) {
            let child_ids = self.children.get(&current.id).ok_or(TreeError::NotFound)?;
            current = child_ids
                .iter()
                .filter_map(|id| self.nodes.get(id))
                .find(|n| n.name == segment)
                .ok_or(TreeError::NotFound)?;
        }
        Ok(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn tree() -> (FileTree, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = kdx_storage::connect(&dir.path().join("t.db")).await.unwrap();
        (FileTree::load(pool).await.unwrap(), dir)
    }

    #[tokio::test]
    async fn root_resolves_and_lists_empty() {
        let (tree, _dir) = tree().await;
        assert!(tree.resolve("/").await.is_ok());
        assert!(tree.list("/", BaseClass::Guest).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn nested_folders_resolve_by_path() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::PowerUser)
            .await
            .unwrap();
        tree.create_folder("/pub", "docs", NodeKind::Directory, BaseClass::Guest, BaseClass::User)
            .await
            .unwrap();
        let node = tree.resolve("/pub/docs").await.unwrap();
        assert_eq!(node.name, "docs");
        let entries = tree.list("/pub", BaseClass::Guest).await.unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn dropbox_rejects_listing_even_for_admin() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "drop", NodeKind::DropBox, BaseClass::Guest, BaseClass::User)
            .await
            .unwrap();
        assert!(matches!(
            tree.list("/drop", BaseClass::Admin).await,
            Err(TreeError::Acl(AclError::DropBoxIsWriteOnly))
        ));
    }

    #[tokio::test]
    async fn class_gates_reads_and_writes() {
        let (tree, _dir) = tree().await;
        tree.create_folder(
            "/",
            "staff",
            NodeKind::Directory,
            BaseClass::PowerUser, // read: power user and up
            BaseClass::Admin,     // write: admin only
        )
        .await
        .unwrap();
        assert!(tree.list("/staff", BaseClass::User).await.is_err());
        assert!(tree.list("/staff", BaseClass::PowerUser).await.is_ok());
        assert!(tree
            .prepare_upload("/staff", "x.bin", BaseClass::PowerUser)
            .await
            .is_err());
        assert!(tree
            .prepare_upload("/staff", "x.bin", BaseClass::Admin)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn upload_name_collision_rejected() {
        let (tree, _dir) = tree().await;
        let parent = tree.resolve("/").await.unwrap();
        tree.add_file(&parent.id, "dup.bin", 3, &[0u8; 32], "/tmp/x")
            .await
            .unwrap();
        assert!(matches!(
            tree.prepare_upload("/", "dup.bin", BaseClass::Admin).await,
            Err(TreeError::Exists)
        ));
    }
}
