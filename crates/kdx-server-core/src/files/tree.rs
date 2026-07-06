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

/// One indexed node, as produced by [`FileTree::generate_catalog`] and
/// returned by [`FileTree::search`]. `min_read_class` mirrors the same gate
/// [`FileTree::list`] / [`FileTree::open_for_read`] apply to this entry (a
/// folder's own class for a folder, its parent's for a file) — the catalog is
/// shared across all classes, so visibility is filtered at search time rather
/// than baked into which entries get indexed.
#[derive(Debug, Clone)]
pub struct CatalogEntry {
    pub path: String,
    pub name: String,
    pub kind: NodeKind,
    pub size: u64,
    pub min_read_class: BaseClass,
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
    #[error("no catalog has been generated yet")]
    CatalogNotGenerated,
    #[error("cannot move a folder into itself or one of its own descendants")]
    WouldCreateCycle,
}

struct TreeState {
    nodes: HashMap<String, Node>,
    /// parent id → child ids
    children: HashMap<String, Vec<String>>,
}

pub struct FileTree {
    pool: SqlitePool,
    state: RwLock<TreeState>,
    /// Snapshot built by `generate_catalog`; `None` until the first call.
    /// Deliberately not auto-built or auto-refreshed — it's an explicit,
    /// admin-triggered index, not a live search of the tree.
    catalog: RwLock<Option<Vec<CatalogEntry>>>,
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
            catalog: RwLock::new(None),
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

    /// Delete a node (recursively, for folders), enforcing write access on the
    /// containing folder. The root cannot be deleted. Backing files on disk are
    /// removed for file nodes. Returns the deleted node's kind.
    ///
    /// Holds a single write-lock guard for the entire operation (validate →
    /// DB → in-memory update) rather than a read lock that's dropped and
    /// later re-acquired — a `tokio::sync::RwLock` guard is safe to hold
    /// across `.await` (unlike a std mutex), and doing so closes a real race:
    /// with a drop-and-reacquire split, a concurrent `add_file`/`move_node`
    /// could land in the gap and get silently swept up (or left dangling) by
    /// this call's stale snapshot.
    pub async fn delete(&self, path: &str, class: BaseClass) -> Result<NodeKind, TreeError> {
        let mut state = self.state.write().await;

        let (kind, node_id, parent_id) = {
            let node = state.resolve(path)?;
            if node.id == ROOT_ID {
                return Err(TreeError::NotAFolder); // root isn't a deletable entry
            }
            // Require write access to the node itself — you may not delete a
            // folder (or its subtree) you couldn't write to.
            acl::check_write(node.kind, node.min_class_write, class)?;
            (node.kind, node.id.clone(), node.parent_id.clone())
        };

        let mut ordered = Vec::new();
        let mut storage_paths = Vec::new();
        collect_subtree(&state, &node_id, &mut ordered, &mut storage_paths);

        // Remove backing files first (best-effort), then rows (post-order so a
        // partial failure never orphans a child under enforced FKs).
        for sp in &storage_paths {
            let _ = tokio::fs::remove_file(sp).await;
        }
        for id in &ordered {
            file_tree::delete(&self.pool, id).await?;
        }

        // Drop from the in-memory tree.
        for id in &ordered {
            state.nodes.remove(id);
            state.children.remove(id);
        }
        if let Some(pid) = &parent_id {
            if let Some(siblings) = state.children.get_mut(pid) {
                siblings.retain(|id| !ordered.contains(id));
            }
        }
        Ok(kind)
    }

    /// Move a node to a new parent folder (Select-for-Move → Move-into),
    /// keeping its name. Requires write access to both the node itself (you
    /// must be able to remove it from its current spot) and the destination
    /// folder (you must be able to place something there) — the same two
    /// checks `delete` and `prepare_upload` each apply individually. Refuses
    /// to move the root, move a folder into itself or one of its own
    /// descendants, or move onto a name collision at the destination.
    ///
    /// Holds a single write-lock guard for the entire operation — see
    /// `delete`'s doc comment for why. Without this, two concurrent moves
    /// (e.g. A moves x into y while B moves y into x) could each pass their
    /// own cycle check against a stale snapshot and both land, producing an
    /// actual cycle that permanently orphans the subtree from the root.
    pub async fn move_node(
        &self,
        path: &str,
        dest_path: &str,
        class: BaseClass,
    ) -> Result<(), TreeError> {
        let mut state = self.state.write().await;

        let (node_id, node_name) = {
            let node = state.resolve(path)?;
            if node.id == ROOT_ID {
                return Err(TreeError::NotAFolder); // root isn't a movable entry
            }
            acl::check_write(node.kind, node.min_class_write, class)?;
            (node.id.clone(), node.name.clone())
        };
        let dest_id = {
            let dest = state.resolve(dest_path)?;
            if !dest.kind.is_folder() {
                return Err(TreeError::NotAFolder);
            }
            acl::check_write(dest.kind, dest.min_class_write, class)?;
            dest.id.clone()
        };

        if dest_id == node_id || is_descendant(&state, &node_id, &dest_id) {
            return Err(TreeError::WouldCreateCycle);
        }
        if let Some(siblings) = state.children.get(&dest_id) {
            if siblings
                .iter()
                .filter(|id| id.as_str() != node_id)
                .filter_map(|id| state.nodes.get(id))
                .any(|n| n.name == node_name)
            {
                return Err(TreeError::Exists);
            }
        }

        file_tree::reparent(&self.pool, &node_id, &dest_id).await?;

        let old_parent = state.nodes.get(&node_id).and_then(|n| n.parent_id.clone());
        if let Some(old_parent) = old_parent {
            if let Some(siblings) = state.children.get_mut(&old_parent) {
                siblings.retain(|id| id != &node_id);
            }
        }
        state.children.entry(dest_id.clone()).or_default().push(node_id.clone());
        if let Some(node) = state.nodes.get_mut(&node_id) {
            node.parent_id = Some(dest_id);
        }
        Ok(())
    }

    /// (Re)build the search catalog: a flat snapshot of every entry currently
    /// in the tree, excluding drop-box subtrees (their contents can never be
    /// listed by anyone — same structural rule `list()` enforces). Returns the
    /// number of entries indexed.
    pub async fn generate_catalog(&self) -> usize {
        let entries = {
            let state = self.state.read().await;
            let mut entries = Vec::new();
            let root = &state.nodes[ROOT_ID];
            collect_catalog(&state, root, "", &mut entries);
            entries
        };
        let count = entries.len();
        *self.catalog.write().await = Some(entries);
        count
    }

    /// Search the last-generated catalog for `query` (case-insensitive
    /// substring of the entry's name), filtered to what `class` may actually
    /// see. Errors if `generate_catalog` has never been called.
    pub async fn search(
        &self,
        query: &str,
        class: BaseClass,
        limit: usize,
    ) -> Result<Vec<CatalogEntry>, TreeError> {
        let catalog = self.catalog.read().await;
        let entries = catalog.as_ref().ok_or(TreeError::CatalogNotGenerated)?;
        let needle = query.to_lowercase();
        Ok(entries
            .iter()
            .filter(|e| needle.is_empty() || e.name.to_lowercase().contains(&needle))
            .filter(|e| class >= e.min_read_class)
            .take(limit)
            .cloned()
            .collect())
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

/// Post-order walk of a subtree: pushes every descendant id (deepest first,
/// then the node itself) and collects the storage paths of any file nodes so
/// their bytes can be removed from disk.
fn collect_subtree(
    state: &TreeState,
    id: &str,
    ordered: &mut Vec<String>,
    storage_paths: &mut Vec<String>,
) {
    if let Some(children) = state.children.get(id) {
        for child in children.clone() {
            collect_subtree(state, &child, ordered, storage_paths);
        }
    }
    if let Some(node) = state.nodes.get(id) {
        if let Some(sp) = &node.storage_path {
            storage_paths.push(sp.clone());
        }
    }
    ordered.push(id.to_owned());
}

/// Is `candidate` equal to `ancestor` or somewhere in its subtree? Used to
/// refuse moving a folder into itself or one of its own descendants.
fn is_descendant(state: &TreeState, ancestor: &str, candidate: &str) -> bool {
    if ancestor == candidate {
        return true;
    }
    if let Some(children) = state.children.get(ancestor) {
        children.iter().any(|c| is_descendant(state, c, candidate))
    } else {
        false
    }
}

/// Recursively flatten `node`'s subtree into `out`, building full `/`-joined
/// paths as it goes. Does not recurse into (or index the contents of) a
/// DropBox — only the drop box entry itself is indexed, matching the fact
/// that its contents are structurally unlistable to everyone.
fn collect_catalog(state: &TreeState, node: &Node, parent_path: &str, out: &mut Vec<CatalogEntry>) {
    let path = if node.id == ROOT_ID {
        String::from("/")
    } else {
        format!("{}/{}", parent_path.trim_end_matches('/'), node.name)
    };
    if node.id != ROOT_ID {
        let min_read_class = if node.kind.is_folder() {
            node.min_class_read
        } else {
            // A file's visibility follows its containing folder's read gate
            // (mirrors open_for_read), not any class of its own.
            state
                .nodes
                .get(node.parent_id.as_deref().unwrap_or(""))
                .map(|p| p.min_class_read)
                .unwrap_or(node.min_class_read)
        };
        out.push(CatalogEntry {
            path: path.clone(),
            name: node.name.clone(),
            kind: node.kind,
            size: node.size,
            min_read_class,
        });
    }
    if node.kind == NodeKind::DropBox {
        return; // structurally unlistable — don't index what's inside
    }
    if let Some(children) = state.children.get(&node.id) {
        for child_id in children {
            if let Some(child) = state.nodes.get(child_id) {
                collect_catalog(state, child, &path, out);
            }
        }
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
    async fn delete_removes_folder_and_children() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User)
            .await
            .unwrap();
        tree.create_folder("/pub", "docs", NodeKind::Directory, BaseClass::Guest, BaseClass::User)
            .await
            .unwrap();
        let parent = tree.resolve("/pub/docs").await.unwrap();
        tree.add_file(&parent.id, "a.txt", 1, &[0u8; 32], "/tmp/none")
            .await
            .unwrap();

        // A user may delete under /pub (write class User).
        tree.delete("/pub", BaseClass::User).await.unwrap();
        assert!(matches!(tree.resolve("/pub").await, Err(TreeError::NotFound)));
        assert!(matches!(
            tree.resolve("/pub/docs").await,
            Err(TreeError::NotFound)
        ));
        assert!(tree.list("/", BaseClass::Guest).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_enforces_parent_write_class_and_guards_root() {
        let (tree, _dir) = tree().await;
        // /staff is writable only by admin.
        tree.create_folder("/", "staff", NodeKind::Directory, BaseClass::Guest, BaseClass::Admin)
            .await
            .unwrap();
        assert!(tree.delete("/staff", BaseClass::PowerUser).await.is_err());
        assert!(tree.delete("/staff", BaseClass::Admin).await.is_ok());
        // Root is not a deletable entry.
        assert!(tree.delete("/", BaseClass::Admin).await.is_err());
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

    #[tokio::test]
    async fn search_requires_a_generated_catalog() {
        let (tree, _dir) = tree().await;
        assert!(matches!(
            tree.search("x", BaseClass::Admin, 50).await,
            Err(TreeError::CatalogNotGenerated)
        ));
    }

    #[tokio::test]
    async fn catalog_indexes_the_tree_and_search_filters_by_name_and_class() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User)
            .await
            .unwrap();
        let pub_dir = tree.resolve("/pub").await.unwrap();
        tree.add_file(&pub_dir.id, "readme.txt", 10, &[0u8; 32], "/tmp/a")
            .await
            .unwrap();
        tree.create_folder(
            "/",
            "staff",
            NodeKind::Directory,
            BaseClass::Admin, // only admins may even see this folder
            BaseClass::Admin,
        )
        .await
        .unwrap();
        let staff_dir = tree.resolve("/staff").await.unwrap();
        tree.add_file(&staff_dir.id, "payroll.csv", 20, &[0u8; 32], "/tmp/b")
            .await
            .unwrap();

        let count = tree.generate_catalog().await;
        assert_eq!(count, 4); // pub, pub/readme.txt, staff, staff/payroll.csv

        // A guest sees the public entries but not the admin-only folder or
        // its file, even though both are in the catalog.
        let guest_hits = tree.search("", BaseClass::Guest, 50).await.unwrap();
        let names: Vec<_> = guest_hits.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"pub"));
        assert!(names.contains(&"readme.txt"));
        assert!(!names.contains(&"staff"));
        assert!(!names.contains(&"payroll.csv"));

        // An admin sees everything; a name filter narrows it further.
        let admin_hits = tree.search("read", BaseClass::Admin, 50).await.unwrap();
        assert_eq!(admin_hits.len(), 1);
        assert_eq!(admin_hits[0].path, "/pub/readme.txt");
    }

    #[tokio::test]
    async fn catalog_excludes_dropbox_contents() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "drop", NodeKind::DropBox, BaseClass::Guest, BaseClass::User)
            .await
            .unwrap();
        let drop = tree.resolve("/drop").await.unwrap();
        tree.add_file(&drop.id, "secret.zip", 5, &[0u8; 32], "/tmp/c")
            .await
            .unwrap();

        tree.generate_catalog().await;
        let hits = tree.search("", BaseClass::Admin, 50).await.unwrap();
        let names: Vec<_> = hits.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"drop")); // the box itself is indexed
        assert!(!names.contains(&"secret.zip")); // its contents are not
    }

    #[tokio::test]
    async fn move_reparents_a_node_and_its_subtree() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "a", NodeKind::Directory, BaseClass::Guest, BaseClass::User)
            .await
            .unwrap();
        tree.create_folder("/", "b", NodeKind::Directory, BaseClass::Guest, BaseClass::User)
            .await
            .unwrap();
        let a = tree.resolve("/a").await.unwrap();
        tree.add_file(&a.id, "doc.txt", 3, &[0u8; 32], "/tmp/x")
            .await
            .unwrap();
        tree.create_folder("/a", "sub", NodeKind::Directory, BaseClass::Guest, BaseClass::User)
            .await
            .unwrap();

        tree.move_node("/a", "/b", BaseClass::User).await.unwrap();

        assert!(matches!(tree.resolve("/a").await, Err(TreeError::NotFound)));
        assert!(tree.resolve("/b/a").await.is_ok());
        // The subtree moved with it.
        assert!(tree.resolve("/b/a/doc.txt").await.is_ok());
        assert!(tree.resolve("/b/a/sub").await.is_ok());
        assert_eq!(tree.list("/b", BaseClass::Guest).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn concurrent_opposing_moves_cannot_create_a_cycle() {
        // Regression test: `move_node` used to validate (including the cycle
        // check) under a read lock that was dropped before the write-lock
        // mutation, leaving a window where two racing calls could each pass
        // their own stale-snapshot cycle check and both land — e.g. A moves
        // x into y while B concurrently moves y into x, producing an actual
        // cycle that orphans the subtree from root forever. `move_node` now
        // holds one write-lock guard for its entire duration, so these two
        // calls are fully serialized: whichever runs second sees the
        // first's result and correctly refuses.
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "x", NodeKind::Directory, BaseClass::Guest, BaseClass::User)
            .await
            .unwrap();
        tree.create_folder("/", "y", NodeKind::Directory, BaseClass::Guest, BaseClass::User)
            .await
            .unwrap();

        let (r1, r2) = tokio::join!(
            tree.move_node("/x", "/y", BaseClass::User),
            tree.move_node("/y", "/x", BaseClass::User),
        );

        // Exactly one of the two opposing moves may succeed — never both.
        assert_ne!(r1.is_ok(), r2.is_ok(), "r1={r1:?} r2={r2:?}");

        // Whichever won, the tree must still be a tree: both x and y remain
        // resolvable from root (no orphaned cycle), one nested under the
        // other.
        if r1.is_ok() {
            assert!(tree.resolve("/y/x").await.is_ok());
        } else {
            assert!(tree.resolve("/x/y").await.is_ok());
        }
    }

    #[tokio::test]
    async fn move_refuses_cycle_root_and_name_collision() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "a", NodeKind::Directory, BaseClass::Guest, BaseClass::User)
            .await
            .unwrap();
        tree.create_folder("/a", "sub", NodeKind::Directory, BaseClass::Guest, BaseClass::User)
            .await
            .unwrap();

        // Can't move a folder into its own descendant.
        assert!(matches!(
            tree.move_node("/a", "/a/sub", BaseClass::User).await,
            Err(TreeError::WouldCreateCycle)
        ));
        // Can't move a folder into itself.
        assert!(matches!(
            tree.move_node("/a", "/a", BaseClass::User).await,
            Err(TreeError::WouldCreateCycle)
        ));
        // Root is not a movable entry.
        assert!(tree.move_node("/", "/a", BaseClass::Admin).await.is_err());

        // Name collision at the destination is refused. (Root's default write
        // class is PowerUser, so use that here — this assertion is about the
        // collision check, not the ACL check exercised above.)
        tree.create_folder("/", "sub", NodeKind::Directory, BaseClass::Guest, BaseClass::User)
            .await
            .unwrap();
        assert!(matches!(
            tree.move_node("/a/sub", "/", BaseClass::PowerUser).await,
            Err(TreeError::Exists)
        ));
    }

    #[tokio::test]
    async fn move_enforces_write_class_on_source_and_destination() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "movable", NodeKind::Directory, BaseClass::Guest, BaseClass::User)
            .await
            .unwrap();
        tree.create_folder("/", "vault", NodeKind::Directory, BaseClass::Guest, BaseClass::Admin)
            .await
            .unwrap();
        tree.create_folder(
            "/",
            "locked",
            NodeKind::Directory,
            BaseClass::Guest,
            BaseClass::Admin,
        )
        .await
        .unwrap();

        // A plain user can't move into an admin-only destination...
        assert!(tree.move_node("/movable", "/vault", BaseClass::User).await.is_err());
        // ...nor move a node they can't write to in the first place.
        assert!(tree.move_node("/locked", "/", BaseClass::User).await.is_err());
        // An admin can do both.
        assert!(tree.move_node("/movable", "/vault", BaseClass::Admin).await.is_ok());
    }
}
