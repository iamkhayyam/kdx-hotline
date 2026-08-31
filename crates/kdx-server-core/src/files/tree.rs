//! In-memory virtual file tree, loaded from the `file_nodes` table at
//! startup and written through on mutation. Read-heavy/write-rare, so a
//! `tokio::sync::RwLock` around the whole tree is appropriate here (the
//! hot paths are chat and transfer data, not tree metadata).

use std::collections::HashMap;

use kdx_storage::file_tree::{self, FileNodeRow, ROOT_ID};
use kdx_storage::SqlitePool;
use tokio::sync::RwLock;

use super::acl::{self, AccessItem, AclError};
use crate::auth::{BaseClass, Session};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Directory,
    File,
    DropBox,
    UploadFolder,
    /// Points at another node; behaves like the target for read/download.
    /// Never contains children of its own, never has storage, never chains
    /// (an alias may not target another alias — enforced in `create_alias`).
    Alias,
}

impl NodeKind {
    pub fn from_i64(kind: i64) -> Option<Self> {
        Some(match kind {
            0 => NodeKind::Directory,
            1 => NodeKind::File,
            2 => NodeKind::DropBox,
            3 => NodeKind::UploadFolder,
            4 => NodeKind::Alias,
            _ => return None,
        })
    }

    pub fn as_u8(self) -> u8 {
        match self {
            NodeKind::Directory => 0,
            NodeKind::File => 1,
            NodeKind::DropBox => 2,
            NodeKind::UploadFolder => 3,
            NodeKind::Alias => 4,
        }
    }

    /// True for kinds that structurally contain other nodes. Aliases are
    /// NOT folders (they never have `children` of their own — reads through
    /// them go via the target).
    pub fn is_folder(self) -> bool {
        matches!(
            self,
            NodeKind::Directory | NodeKind::DropBox | NodeKind::UploadFolder
        )
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
    /// For `NodeKind::Alias`: the id of the target node. `None` for every
    /// other kind. A dangling alias (target deleted) has `Some(...)` but
    /// no matching row in the tree — resolving through it yields
    /// `TreeError::NotFound`, matching the alias's intent (it silently
    /// stops working when the target goes away).
    pub target_id: Option<String>,
    /// Access-item bundle derived from the node name's `[tag]` suffix
    /// (original KDX semantics). Meaningful on folders; files inherit the
    /// containing folder's item at ACL time.
    pub access_item: AccessItem,
    /// Optional owner login — the owner may read/delete inside a drop box
    /// (or a `[db]` folder) that is write-only to everyone else.
    pub owner: Option<String>,
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
    #[error("alias target must be a real file or folder, not another alias")]
    AliasChainRefused,
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
    let access_item = AccessItem::parse(&row.name);
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
        target_id: row.target_id,
        access_item,
        owner: row.owner,
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
    ///
    /// Aliases resolve transparently: `list("/aliases/pubcopy")` where
    /// `pubcopy` points at `/pub` lists `/pub`'s children (with `/pub`'s
    /// ACL). Alias children in the result list themselves show up as
    /// `NodeKind::Alias` entries carrying the target's displayable size,
    /// so the UI can badge them without a follow-up round-trip.
    pub async fn list(&self, path: &str, session: &Session) -> Result<Vec<Entry>, TreeError> {
        let state = self.state.read().await;
        let node = state.resolve(path)?;
        // If the path landed on an alias, list what it points at.
        let node = resolve_through_alias(&state, node)?;
        if !node.kind.is_folder() {
            return Err(TreeError::NotAFolder);
        }
        acl::check_read(
            node.kind,
            node.access_item,
            node.min_class_read,
            session.class,
            session.privileges,
            node.owner.as_deref(),
            &session.username,
        )?;
        let mut entries: Vec<Entry> = state
            .children
            .get(&node.id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| state.nodes.get(id))
                    .map(|n| {
                        // For an alias child, show the target's size so the
                        // listing is useful — but keep kind = Alias so the
                        // UI can badge it.
                        let size = if n.kind == NodeKind::Alias {
                            n.target_id
                                .as_ref()
                                .and_then(|t| state.nodes.get(t))
                                .map(|t| t.size)
                                .unwrap_or(0)
                        } else {
                            n.size
                        };
                        Entry {
                            name: n.name.clone(),
                            kind: n.kind,
                            size,
                        }
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
        session: &Session,
    ) -> Result<Node, TreeError> {
        let state = self.state.read().await;
        let node = state.resolve(path)?;
        if !node.kind.is_folder() {
            return Err(TreeError::NotAFolder);
        }
        acl::check_write(
            node.kind,
            node.access_item,
            node.min_class_write,
            session.class,
            session.privileges,
        )?;
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
    ///
    /// Aliases resolve transparently: downloading `/aliases/pubcopy/x.txt`
    /// where `pubcopy` points at `/pub` reads `/pub/x.txt`'s bytes. The ACL
    /// check applies to the *target's* containing folder — you can't escalate
    /// past a class threshold by aliasing something you'd normally be denied.
    pub async fn open_for_read(&self, path: &str, session: &Session) -> Result<Node, TreeError> {
        let state = self.state.read().await;
        let node = state.resolve(path)?;
        let node = resolve_through_alias(&state, node)?;
        if node.kind != NodeKind::File {
            return Err(TreeError::NotAFile);
        }
        // A file always has a parent; apply the parent folder's read ACL.
        // For an aliased file, this is the *target's* parent — never the
        // alias's parent, else you could bypass a stricter target ACL by
        // dropping an alias into a permissive folder.
        let parent = node
            .parent_id
            .as_ref()
            .and_then(|id| state.nodes.get(id))
            .ok_or(TreeError::NotFound)?;
        acl::check_read(
            parent.kind,
            parent.access_item,
            parent.min_class_read,
            session.class,
            session.privileges,
            parent.owner.as_deref(),
            &session.username,
        )?;
        Ok(node.clone())
    }

    /// Node metadata for the Files "Get Info" verb. Aliases resolve to their
    /// target. Read ACL: files gate on their containing folder, folders on
    /// themselves (so Get Info can't probe a drop box you can't read).
    pub async fn info(&self, path: &str, session: &Session) -> Result<Node, TreeError> {
        let state = self.state.read().await;
        let node = state.resolve(path)?;
        let node = resolve_through_alias(&state, node)?;
        if node.kind.is_folder() {
            acl::check_read(
                node.kind,
                node.access_item,
                node.min_class_read,
                session.class,
                session.privileges,
                node.owner.as_deref(),
                &session.username,
            )?;
        } else {
            let parent = node
                .parent_id
                .as_ref()
                .and_then(|id| state.nodes.get(id))
                .ok_or(TreeError::NotFound)?;
            acl::check_read(
                parent.kind,
                parent.access_item,
                parent.min_class_read,
                session.class,
                session.privileges,
                parent.owner.as_deref(),
                &session.username,
            )?;
        }
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
        owner: Option<&str>,
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
            owner,
        )
        .await?;
        let node = node_from_row(row)?;
        self.insert_in_memory(node.clone()).await;
        Ok(node)
    }

    /// Create an alias entry at `dest_path` pointing to the node at
    /// `source_path`, with the source's own leaf name. Requires write
    /// access to `dest_path`. The source may be any real node (file,
    /// folder, dropbox, or upload folder) but NOT another alias — no
    /// chains, so `resolve_through_alias` is a single hop and can't loop.
    /// Name collisions at the destination are refused.
    pub async fn create_alias(
        &self,
        source_path: &str,
        dest_path: &str,
        session: &Session,
    ) -> Result<Node, TreeError> {
        let (source_id, alias_name, dest_id) = {
            let state = self.state.read().await;
            let source = state.resolve(source_path)?;
            if source.kind == NodeKind::Alias {
                return Err(TreeError::AliasChainRefused);
            }
            if source.id == ROOT_ID {
                // Aliasing the root would let a caller shadow everything
                // under an arbitrary name — refuse for the same reason we
                // refuse to move or delete the root.
                return Err(TreeError::NotAFile);
            }
            let dest = state.resolve(dest_path)?;
            if !dest.kind.is_folder() {
                return Err(TreeError::NotAFolder);
            }
            acl::check_write(
                dest.kind,
                dest.access_item,
                dest.min_class_write,
                session.class,
                session.privileges,
            )?;
            let alias_name = source.name.clone();
            if let Some(siblings) = state.children.get(&dest.id) {
                if siblings
                    .iter()
                    .filter_map(|id| state.nodes.get(id))
                    .any(|n| n.name == alias_name)
                {
                    return Err(TreeError::Exists);
                }
            }
            (source.id.clone(), alias_name, dest.id.clone())
        };
        let row = file_tree::create_alias(&self.pool, &dest_id, &alias_name, &source_id).await?;
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
    pub async fn delete(&self, path: &str, session: &Session) -> Result<NodeKind, TreeError> {
        let mut state = self.state.write().await;

        let (kind, node_id, parent_id) = {
            let node = state.resolve(path)?;
            if node.id == ROOT_ID {
                return Err(TreeError::NotAFolder); // root isn't a deletable entry
            }
            // Write access to the node itself is the class gate (original
            // KDX behavior). The access-item rule ([ul] admin-only delete,
            // [db] owner/admin delete) comes from the node's own item for a
            // folder, or the containing folder's item for a file.
            let parent = node
                .parent_id
                .as_ref()
                .and_then(|id| state.nodes.get(id))
                .ok_or(TreeError::NotFound)?;
            let (item, owner) = if node.kind.is_folder() {
                (node.access_item, node.owner.as_deref())
            } else {
                (parent.access_item, parent.owner.as_deref())
            };
            acl::check_delete(
                node.kind,
                item,
                node.min_class_write,
                session.class,
                session.privileges,
                owner,
                &session.username,
            )?;
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
        session: &Session,
    ) -> Result<(), TreeError> {
        let mut state = self.state.write().await;

        let (node_id, node_name) = {
            let node = state.resolve(path)?;
            if node.id == ROOT_ID {
                return Err(TreeError::NotAFolder); // root isn't a movable entry
            }
            acl::check_write(
                node.kind,
                node.access_item,
                node.min_class_write,
                session.class,
                session.privileges,
            )?;
            (node.id.clone(), node.name.clone())
        };
        let dest_id = {
            let dest = state.resolve(dest_path)?;
            if !dest.kind.is_folder() {
                return Err(TreeError::NotAFolder);
            }
            acl::check_write(
                dest.kind,
                dest.access_item,
                dest.min_class_write,
                session.class,
                session.privileges,
            )?;
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

/// If `node` is an alias, look up its target once and return that node.
/// Otherwise return `node` unchanged. Refuses to follow more than one hop —
/// `create_alias` guards that a target is never itself an alias, so a
/// well-formed tree can't chain, and if a chain somehow slipped in this
/// function returns `NotFound` rather than looping. A dangling alias
/// (target row gone — either the FK's `ON DELETE SET NULL` fired or the
/// alias was somehow written pointing at nothing) yields `NotFound`.
fn resolve_through_alias<'a>(state: &'a TreeState, node: &'a Node) -> Result<&'a Node, TreeError> {
    if node.kind != NodeKind::Alias {
        return Ok(node);
    }
    let target_id = node.target_id.as_deref().ok_or(TreeError::NotFound)?;
    let target = state.nodes.get(target_id).ok_or(TreeError::NotFound)?;
    if target.kind == NodeKind::Alias {
        // Should be impossible if all writes go through `create_alias`, but
        // fail closed rather than recurse.
        return Err(TreeError::AliasChainRefused);
    }
    Ok(target)
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
    if node.id != ROOT_ID && node.kind != NodeKind::Alias {
        // Aliases aren't indexed — the target already is, and indexing both
        // would give duplicate hits for the same underlying content. If the
        // catalog ever needs to surface aliases explicitly, that's an
        // orthogonal UI feature; the current search stays deduplicated.
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
    if node.kind == NodeKind::DropBox || node.kind == NodeKind::Alias {
        // Structurally unlistable (dropbox) or has no own children (alias) —
        // in both cases don't recurse.
        return;
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
    /// Walk `path` segment by segment. Aliases are followed at each
    /// intermediate step so a path like `/aliases/pub/readme.txt` resolves
    /// correctly when `pub` is an alias pointing at `/pub` (the walk into
    /// `readme.txt` continues in the target's children, not the alias's
    /// empty children map). The *final* segment is intentionally NOT
    /// unwrapped here — callers use `resolve_through_alias` to decide
    /// whether to see the alias node itself (e.g. `delete` deletes just the
    /// alias) or the target (e.g. `list` / `open_for_read` read through).
    fn resolve(&self, path: &str) -> Result<&Node, TreeError> {
        let mut current = self.nodes.get(ROOT_ID).ok_or(TreeError::NotFound)?;
        for segment in path.split('/').filter(|s| !s.is_empty()) {
            // Before looking up children, hop through any alias — an alias
            // has no children of its own, so the walk continues in the
            // target's children map. We hop here (not at the terminal
            // result) so that a path landing on an alias still returns the
            // alias node itself; callers use `resolve_through_alias` when
            // they want the target instead.
            let walkable = if current.kind == NodeKind::Alias {
                resolve_through_alias(self, current)?
            } else {
                current
            };
            let child_ids = self.children.get(&walkable.id).ok_or(TreeError::NotFound)?;
            current = child_ids
                .iter()
                .filter_map(|id| self.nodes.get(id))
                .find(|n| n.name == *segment)
                .ok_or(TreeError::NotFound)?;
        }
        Ok(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Session;
    use tokio::time::Instant;
    use uuid::Uuid;

    fn sess(class: BaseClass) -> Session {
        Session {
            id: Uuid::new_v4(),
            account_id: "a".into(),
            username: "tester".into(),
            class,
            privileges: BaseClass::privileges(class),
            expires_at: Instant::now(),
        }
    }

    async fn tree() -> (FileTree, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = kdx_storage::connect(&dir.path().join("t.db")).await.unwrap();
        (FileTree::load(pool).await.unwrap(), dir)
    }

    #[tokio::test]
    async fn root_resolves_and_lists_empty() {
        let (tree, _dir) = tree().await;
        assert!(tree.resolve("/").await.is_ok());
        assert!(tree.list("/", &sess(BaseClass::Guest)).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn nested_folders_resolve_by_path() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::PowerUser, None)
            .await
            .unwrap();
        tree.create_folder("/pub", "docs", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        let node = tree.resolve("/pub/docs").await.unwrap();
        assert_eq!(node.name, "docs");
        let entries = tree.list("/pub", &sess(BaseClass::Guest)).await.unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn dropbox_listable_only_by_admin() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "drop", NodeKind::DropBox, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        // Converged semantics (P1-4): admins may list/read a drop box …
        assert!(tree.list("/drop", &sess(BaseClass::Admin)).await.is_ok());
        // … but everyone else is structurally refused.
        assert!(matches!(
            tree.list("/drop", &sess(BaseClass::Guest)).await,
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
            None,
        )
        .await
        .unwrap();
        assert!(tree.list("/staff", &sess(BaseClass::User)).await.is_err());
        assert!(tree.list("/staff", &sess(BaseClass::PowerUser)).await.is_ok());
        assert!(tree
            .prepare_upload("/staff", "x.bin", &sess(BaseClass::PowerUser))
            .await
            .is_err());
        assert!(tree
            .prepare_upload("/staff", "x.bin", &sess(BaseClass::Admin))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn delete_removes_folder_and_children() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        tree.create_folder("/pub", "docs", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        let parent = tree.resolve("/pub/docs").await.unwrap();
        tree.add_file(&parent.id, "a.txt", 1, &[0u8; 32], "/tmp/none")
            .await
            .unwrap();

        // A user may delete under /pub (write class User).
        tree.delete("/pub", &sess(BaseClass::User)).await.unwrap();
        assert!(matches!(tree.resolve("/pub").await, Err(TreeError::NotFound)));
        assert!(matches!(
            tree.resolve("/pub/docs").await,
            Err(TreeError::NotFound)
        ));
        assert!(tree.list("/", &sess(BaseClass::Guest)).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_enforces_parent_write_class_and_guards_root() {
        let (tree, _dir) = tree().await;
        // /staff is writable only by admin.
        tree.create_folder("/", "staff", NodeKind::Directory, BaseClass::Guest, BaseClass::Admin, None)
            .await
            .unwrap();
        assert!(tree.delete("/staff", &sess(BaseClass::PowerUser)).await.is_err());
        assert!(tree.delete("/staff", &sess(BaseClass::Admin)).await.is_ok());
        // Root is not a deletable entry.
        assert!(tree.delete("/", &sess(BaseClass::Admin)).await.is_err());
    }


    #[tokio::test]
    async fn access_item_db_folder_owner_can_read_stranger_cannot() {
        let (tree, _dir) = tree().await;
        // A folder whose name carries the [DB] suffix becomes a drop box;
        // owner "bob" is set explicitly.
        tree.create_folder("/", "inbox [DB]", NodeKind::Directory, BaseClass::Guest, BaseClass::User, Some("bob"))
            .await
            .unwrap();
        // The item is parsed from the name suffix.
        let node = tree.resolve("/inbox [DB]").await.unwrap();
        assert_eq!(node.access_item, AccessItem::DropBox);
        assert_eq!(node.owner.as_deref(), Some("bob"));

        // A stranger cannot list it…
        let mut stranger = sess(BaseClass::User);
        stranger.username = "alice".into();
        assert!(matches!(
            tree.list("/inbox [DB]", &stranger).await,
            Err(TreeError::Acl(AclError::DropBoxIsWriteOnly))
        ));
        // …the owner can…
        let mut owner = sess(BaseClass::User);
        owner.username = "bob".into();
        assert!(tree.list("/inbox [DB]", &owner).await.is_ok());
        // …and so can an admin.
        assert!(tree.list("/inbox [DB]", &sess(BaseClass::Admin)).await.is_ok());
    }

    #[tokio::test]
    async fn access_item_ul_folder_delete_is_admin_only() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "uploads [UL]", NodeKind::Directory, BaseClass::Guest, BaseClass::Guest, None)
            .await
            .unwrap();
        let parent = tree.resolve("/uploads [UL]").await.unwrap();
        tree.add_file(&parent.id, "a.txt", 5, &[0u8; 32], "/tmp/a.txt")
            .await
            .unwrap();
        // A power user may not delete inside an [UL] folder…
        assert!(tree.delete("/uploads [UL]/a.txt", &sess(BaseClass::PowerUser)).await.is_err());
        // …but an admin may.
        assert!(tree.delete("/uploads [UL]/a.txt", &sess(BaseClass::Admin)).await.is_ok());
    }

    #[tokio::test]
    async fn upload_name_collision_rejected() {
        let (tree, _dir) = tree().await;
        let parent = tree.resolve("/").await.unwrap();
        tree.add_file(&parent.id, "dup.bin", 3, &[0u8; 32], "/tmp/x")
            .await
            .unwrap();
        assert!(matches!(
            tree.prepare_upload("/", "dup.bin", &sess(BaseClass::Admin)).await,
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
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
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
            BaseClass::Admin, None)
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
        tree.create_folder("/", "drop", NodeKind::DropBox, BaseClass::Guest, BaseClass::User, None)
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
        tree.create_folder("/", "a", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        tree.create_folder("/", "b", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        let a = tree.resolve("/a").await.unwrap();
        tree.add_file(&a.id, "doc.txt", 3, &[0u8; 32], "/tmp/x")
            .await
            .unwrap();
        tree.create_folder("/a", "sub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();

        tree.move_node("/a", "/b", &sess(BaseClass::User)).await.unwrap();

        assert!(matches!(tree.resolve("/a").await, Err(TreeError::NotFound)));
        assert!(tree.resolve("/b/a").await.is_ok());
        // The subtree moved with it.
        assert!(tree.resolve("/b/a/doc.txt").await.is_ok());
        assert!(tree.resolve("/b/a/sub").await.is_ok());
        assert_eq!(tree.list("/b", &sess(BaseClass::Guest)).await.unwrap().len(), 1);
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
        tree.create_folder("/", "x", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        tree.create_folder("/", "y", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();

        let u = sess(BaseClass::User);
        let (r1, r2) = tokio::join!(
            tree.move_node("/x", "/y", &u),
            tree.move_node("/y", "/x", &u),
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
        tree.create_folder("/", "a", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        tree.create_folder("/a", "sub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();

        // Can't move a folder into its own descendant.
        assert!(matches!(
            tree.move_node("/a", "/a/sub", &sess(BaseClass::User)).await,
            Err(TreeError::WouldCreateCycle)
        ));
        // Can't move a folder into itself.
        assert!(matches!(
            tree.move_node("/a", "/a", &sess(BaseClass::User)).await,
            Err(TreeError::WouldCreateCycle)
        ));
        // Root is not a movable entry.
        assert!(tree.move_node("/", "/a", &sess(BaseClass::Admin)).await.is_err());

        // Name collision at the destination is refused. (Root's default write
        // class is PowerUser, so use that here — this assertion is about the
        // collision check, not the ACL check exercised above.)
        tree.create_folder("/", "sub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        assert!(matches!(
            tree.move_node("/a/sub", "/", &sess(BaseClass::PowerUser)).await,
            Err(TreeError::Exists)
        ));
    }

    #[tokio::test]
    async fn alias_to_a_folder_lists_the_targets_children() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        let pub_dir = tree.resolve("/pub").await.unwrap();
        tree.add_file(&pub_dir.id, "a.txt", 42, &[0u8; 32], "/tmp/a")
            .await
            .unwrap();
        tree.create_folder("/", "aliases", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();

        // Alias /aliases/pub → /pub (inherits the source's leaf name).
        let alias = tree
            .create_alias("/pub", "/aliases", &sess(BaseClass::User))
            .await
            .unwrap();
        assert_eq!(alias.kind, NodeKind::Alias);
        assert_eq!(alias.name, "pub");

        // Listing the alias returns the target's children.
        let entries = tree.list("/aliases/pub", &sess(BaseClass::Guest)).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "a.txt");
        assert_eq!(entries[0].size, 42);
    }

    #[tokio::test]
    async fn alias_to_a_file_resolves_for_download() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        let pub_dir = tree.resolve("/pub").await.unwrap();
        let file = tree
            .add_file(&pub_dir.id, "readme.txt", 10, &[0u8; 32], "/tmp/readme")
            .await
            .unwrap();
        tree.create_folder("/", "aliases", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        tree.create_alias("/pub/readme.txt", "/aliases", &sess(BaseClass::User))
            .await
            .unwrap();

        // Downloading the alias resolves to the target's node (same id,
        // same storage_path, same size).
        let resolved = tree
            .open_for_read("/aliases/readme.txt", &sess(BaseClass::Guest))
            .await
            .unwrap();
        assert_eq!(resolved.id, file.id);
        assert_eq!(resolved.storage_path, file.storage_path);
        assert_eq!(resolved.size, 10);
    }

    #[tokio::test]
    async fn resolve_walks_through_an_intermediate_alias() {
        // Regression: `TreeState::resolve` used to look up children directly
        // under the current node at every step. Once it landed on an alias
        // (which has no children of its own), the next segment failed with
        // NotFound even though the target folder had that child. The
        // real-world hit was any deep read through an alias — e.g. the
        // integration test `admin_aliases_a_folder_into_another_and_
        // download_resolves` couldn't download `/links/pub/readme.txt`.
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        let pub_dir = tree.resolve("/pub").await.unwrap();
        tree.add_file(&pub_dir.id, "readme.txt", 5, &[0u8; 32], "/tmp/r")
            .await
            .unwrap();
        tree.create_folder("/", "links", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        tree.create_alias("/pub", "/links", &sess(BaseClass::User)).await.unwrap();

        // The whole point: resolving through an intermediate alias reaches
        // the file. Without the fix this was `Err(NotFound)`.
        let file = tree.resolve("/links/pub/readme.txt").await.unwrap();
        assert_eq!(file.name, "readme.txt");
        assert_eq!(file.kind, NodeKind::File);
    }

    #[tokio::test]
    async fn alias_download_applies_targets_acl_not_alias_parents() {
        // Security-critical: an alias in a permissive folder must NOT let a
        // low-class user reach a restricted file. The ACL check runs against
        // the target's containing folder, not the alias's parent.
        let (tree, _dir) = tree().await;
        tree.create_folder(
            "/",
            "vault",
            NodeKind::Directory,
            BaseClass::Admin, // admin-only reads
            BaseClass::Admin, None)
        .await
        .unwrap();
        let vault = tree.resolve("/vault").await.unwrap();
        tree.add_file(&vault.id, "secret.txt", 1, &[0u8; 32], "/tmp/s")
            .await
            .unwrap();

        // The permissive folder anyone can read.
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::Admin, None)
            .await
            .unwrap();
        // Only an admin can even create the alias (needs write on /pub).
        tree.create_alias("/vault/secret.txt", "/pub", &sess(BaseClass::Admin))
            .await
            .unwrap();

        // A guest can list /pub and see the alias entry, but CANNOT
        // actually download through it — the vault's admin-only read gate
        // applies.
        assert!(tree.list("/pub", &sess(BaseClass::Guest)).await.is_ok());
        assert!(matches!(
            tree.open_for_read("/pub/secret.txt", &sess(BaseClass::Guest)).await,
            Err(TreeError::Acl(_))
        ));
        // An admin can go through.
        assert!(tree.open_for_read("/pub/secret.txt", &sess(BaseClass::Admin)).await.is_ok());
    }

    #[tokio::test]
    async fn alias_cannot_chain() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        tree.create_folder("/", "aliases", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        tree.create_alias("/pub", "/aliases", &sess(BaseClass::User))
            .await
            .unwrap();
        // Making an alias to an alias is refused.
        assert!(matches!(
            tree.create_alias("/aliases/pub", "/", &sess(BaseClass::PowerUser)).await,
            Err(TreeError::AliasChainRefused)
        ));
    }

    #[tokio::test]
    async fn delete_alias_leaves_target_intact() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        let pub_dir = tree.resolve("/pub").await.unwrap();
        tree.add_file(&pub_dir.id, "a.txt", 1, &[0u8; 32], "/tmp/a")
            .await
            .unwrap();
        tree.create_folder("/", "aliases", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        tree.create_alias("/pub", "/aliases", &sess(BaseClass::User))
            .await
            .unwrap();

        // Delete the alias itself.
        tree.delete("/aliases/pub", &sess(BaseClass::PowerUser)).await.unwrap();
        assert!(matches!(
            tree.resolve("/aliases/pub").await,
            Err(TreeError::NotFound)
        ));
        // Target still there.
        assert!(tree.resolve("/pub").await.is_ok());
        assert!(tree.resolve("/pub/a.txt").await.is_ok());
    }

    #[tokio::test]
    async fn alias_refuses_root_source_and_dropbox_dest_write_check() {
        let (tree, _dir) = tree().await;
        // Root as source is refused (would shadow everything).
        assert!(tree.create_alias("/", "/", &sess(BaseClass::Admin)).await.is_err());

        // A dropbox as destination fails the write ACL for anyone below
        // its min_class_write (aliases are just another write op on the
        // destination folder).
        tree.create_folder("/", "drop", NodeKind::DropBox, BaseClass::Guest, BaseClass::Admin, None)
            .await
            .unwrap();
        tree.create_folder("/", "src", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        assert!(matches!(
            tree.create_alias("/src", "/drop", &sess(BaseClass::User)).await,
            Err(TreeError::Acl(_))
        ));
    }

    #[tokio::test]
    async fn move_enforces_write_class_on_source_and_destination() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "movable", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None)
            .await
            .unwrap();
        tree.create_folder("/", "vault", NodeKind::Directory, BaseClass::Guest, BaseClass::Admin, None)
            .await
            .unwrap();
        tree.create_folder(
            "/",
            "locked",
            NodeKind::Directory,
            BaseClass::Guest,
            BaseClass::Admin, None)
        .await
        .unwrap();

        // A plain user can't move into an admin-only destination...
        assert!(tree.move_node("/movable", "/vault", &sess(BaseClass::User)).await.is_err());
        // ...nor move a node they can't write to in the first place.
        assert!(tree.move_node("/locked", "/", &sess(BaseClass::User)).await.is_err());
        // An admin can do both.
        assert!(tree.move_node("/movable", "/vault", &sess(BaseClass::Admin)).await.is_ok());
    }
}
