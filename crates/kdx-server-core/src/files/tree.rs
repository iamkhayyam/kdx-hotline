//! In-memory virtual file tree, loaded from the `file_nodes` table at
//! startup and written through on mutation. Read-heavy/write-rare, so a
//! `tokio::sync::RwLock` around the whole tree is appropriate here (the
//! hot paths are chat and transfer data, not tree metadata).
//!
//! Access is *inherited*: reading a folder's contents requires
//! [`acl::check_read`] to pass on that folder and on every folder above it,
//! so a class gate or a drop box anywhere up the chain covers the whole
//! subtree below it. Path walks apply the same rule as they descend, so an
//! unreadable folder answers the same way whether or not the name asked for
//! exists inside it.
//!
//! Every walk over the tree is iterative and bounded by the node count, and
//! new nodes are kept within `limits::MAX_TREE_DEPTH` and
//! `limits::MAX_PATH_LEN`, so even a deep chain persisted by an older build
//! can't overflow the stack.

use std::collections::HashMap;

use kdx_storage::file_tree::{self, FileNodeRow, ROOT_ID};
use kdx_storage::{SqlitePool, StorageError};
use tokio::sync::RwLock;
use tracing::warn;

use super::acl::{self, AccessItem, AclError};
use crate::auth::{BaseClass, Privileges, Session};
use crate::limits;

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
/// returned by [`FileTree::search`]. `min_read_class` is the highest read
/// class on the way down to the entry (a folder's own class included, a
/// file's containing folder's) — the same inherited gate
/// [`FileTree::list`] / [`FileTree::open_for_read`] apply. The catalog is
/// shared across all classes, so visibility is filtered at search time
/// rather than baked into which entries get indexed.
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
    /// Deliberately generic: the inner error carries SQL text, which must
    /// not reach clients. Use [`TreeError::client_message`] to log it.
    #[error("storage error")]
    Storage(#[from] kdx_storage::StorageError),
    #[error("corrupt node kind {0}")]
    CorruptKind(i64),
    #[error("no catalog has been generated yet")]
    CatalogNotGenerated,
    #[error("cannot move a folder into itself or one of its own descendants")]
    WouldCreateCycle,
    #[error("alias target must be a real file or folder, not another alias")]
    AliasChainRefused,
    #[error("invalid name: {0}")]
    InvalidName(&'static str),
    #[error("invalid path: {0}")]
    InvalidPath(&'static str),
    #[error("folders are nested too deeply")]
    TooDeep,
}

impl TreeError {
    /// The text to send a client for this error. Storage failures are
    /// logged here with their details and reported generically.
    pub fn client_message(&self) -> String {
        if let TreeError::Storage(e) = self {
            warn!(error = %e, "file tree storage error");
        }
        self.to_string()
    }
}

/// Check a client-supplied file or folder name (upload, new folder, alias):
/// non-empty, at most `limits::MAX_FILE_NAME_LEN` bytes, not `.` or `..`, no
/// `/`, no control characters (C0, DEL, C1, NUL included), no bidi
/// embedding/override/isolate marks (they make a name display as something
/// else), and no leading or trailing whitespace.
pub fn validate_name(name: &str) -> Result<(), TreeError> {
    if name.is_empty() {
        return Err(TreeError::InvalidName("name is empty"));
    }
    if name.len() > limits::MAX_FILE_NAME_LEN {
        return Err(TreeError::InvalidName("name is too long"));
    }
    if name == "." || name == ".." {
        return Err(TreeError::InvalidName("reserved name"));
    }
    if name.trim() != name {
        return Err(TreeError::InvalidName("leading or trailing whitespace"));
    }
    for c in name.chars() {
        if c == '/' {
            return Err(TreeError::InvalidName("name contains '/'"));
        }
        if c.is_control() {
            return Err(TreeError::InvalidName("name contains a control character"));
        }
        if is_bidi_control(c) {
            return Err(TreeError::InvalidName(
                "name contains a bidi control character",
            ));
        }
    }
    Ok(())
}

fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// A request path is bounded and carries no control characters (no valid
/// name contains one).
fn check_path(path: &str) -> Result<(), TreeError> {
    if path.len() > limits::MAX_PATH_LEN {
        return Err(TreeError::InvalidPath("path is too long"));
    }
    if path.chars().any(char::is_control) {
        return Err(TreeError::InvalidPath("path contains a control character"));
    }
    Ok(())
}

/// Map a failed insert/update: a unique violation means the name is taken,
/// a foreign-key violation that the parent is gone. Anything else stays a
/// (generic, logged) storage error.
fn map_write_err(e: StorageError) -> TreeError {
    if let StorageError::Sqlx(inner) = &e {
        if let Some(db) = inner.as_database_error() {
            if db.is_unique_violation() {
                return TreeError::Exists;
            }
            if db.is_foreign_key_violation() {
                return TreeError::NotFound;
            }
        }
    }
    TreeError::Storage(e)
}

/// `acl::check_read` against one folder's own rules.
fn check_read_node(node: &Node, s: &Session) -> Result<(), AclError> {
    acl::check_read(
        node.kind,
        node.access_item,
        node.min_class_read,
        s.class,
        s.privileges,
        node.owner.as_deref(),
        &s.username,
    )
}

/// `acl::check_write` against one folder's own rules.
fn check_write_node(node: &Node, s: &Session) -> Result<(), AclError> {
    acl::check_write(
        node.kind,
        node.access_item,
        node.min_class_write,
        s.class,
        s.privileges,
    )
}

/// May `s` take an entry out of `folder` (delete it, or move it away)? Also
/// the rule for deleting or moving `folder` itself.
fn check_remove_from(folder: &Node, s: &Session) -> Result<(), AclError> {
    acl::check_delete(
        folder.kind,
        folder.access_item,
        folder.min_class_write,
        s.class,
        s.privileges,
        folder.owner.as_deref(),
        &s.username,
    )
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

    /// Resolve a `/`-separated virtual path to a node. Applies no ACL — for
    /// server-internal lookups; anything answering a client goes through
    /// the session-checked methods below.
    pub async fn resolve(&self, path: &str) -> Result<Node, TreeError> {
        let state = self.state.read().await;
        Ok(state.resolve(path)?.clone())
    }

    /// List a folder's entries, enforcing inherited read ACLs. Drop boxes
    /// (and everything under one) refuse listing to all but their owner
    /// and admins — write-only is structural, not conventional.
    ///
    /// Aliases resolve transparently: `list("/aliases/pubcopy")` where
    /// `pubcopy` points at `/pub` lists `/pub`'s children (with `/pub`'s
    /// ACL). Alias children in the result list themselves show up as
    /// `NodeKind::Alias` entries carrying the target's displayable size
    /// (when the caller could read the target), so the UI can badge them
    /// without a follow-up round-trip.
    pub async fn list(&self, path: &str, session: &Session) -> Result<Vec<Entry>, TreeError> {
        let state = self.state.read().await;
        let node = state.resolve_as(path, session)?;
        // If the path landed on an alias, list what it points at.
        let node = resolve_through_alias(&state, node)?;
        if !node.kind.is_folder() {
            return Err(TreeError::NotAFolder);
        }
        state.check_node_readable(node, session)?;
        let mut entries: Vec<Entry> = state
            .child_nodes(&node.id)
            .map(|n| {
                // For an alias child, show the target's size so the listing
                // is useful — but keep kind = Alias so the UI can badge it,
                // and say nothing about a target the caller can't read.
                let size = if n.kind == NodeKind::Alias {
                    n.target_id
                        .as_ref()
                        .and_then(|t| state.nodes.get(t))
                        .filter(|t| state.check_node_readable(t, session).is_ok())
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
            .collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    /// Validate an upload destination and return the parent node. Enforces
    /// the name rules, inherited ACLs on the way to the folder, its write
    /// ACL, the depth/path caps and name collisions. Uploading into a drop
    /// box is allowed (that's what it's for); into anything *under* one is
    /// owner/admin-only.
    pub async fn prepare_upload(
        &self,
        path: &str,
        name: &str,
        session: &Session,
    ) -> Result<Node, TreeError> {
        validate_name(name)?;
        let state = self.state.read().await;
        let node = state.resolve_as(path, session)?;
        if !node.kind.is_folder() {
            return Err(TreeError::NotAFolder);
        }
        state.check_place_into(node, session, false)?;
        state.check_room(node, 0, 1 + name.len())?;
        if state.name_taken(&node.id, name) {
            return Err(TreeError::Exists);
        }
        Ok(node.clone())
    }

    /// Resolve a file for download, enforcing inherited read access on its
    /// containing folder. A file anywhere inside a DropBox is refused to all
    /// but the box's owner and admins (same rule as listing), as is a file
    /// under any folder the class can't read.
    ///
    /// Aliases resolve transparently: downloading `/aliases/pubcopy/x.txt`
    /// where `pubcopy` points at `/pub` reads `/pub/x.txt`'s bytes. The ACL
    /// check applies to the *target's* containing folders — you can't
    /// escalate past a class threshold by aliasing something you'd normally
    /// be denied.
    pub async fn open_for_read(&self, path: &str, session: &Session) -> Result<Node, TreeError> {
        let state = self.state.read().await;
        let node = state.resolve_as(path, session)?;
        let node = resolve_through_alias(&state, node)?;
        state.check_node_readable(node, session)?;
        if node.kind != NodeKind::File {
            return Err(TreeError::NotAFile);
        }
        Ok(node.clone())
    }

    /// Node metadata for the Files "Get Info" verb. Aliases resolve to their
    /// target. Read ACL: files gate on their containing folders, folders on
    /// themselves and theirs (so Get Info can't probe a drop box you can't
    /// read).
    pub async fn info(&self, path: &str, session: &Session) -> Result<Node, TreeError> {
        let state = self.state.read().await;
        let node = state.resolve_as(path, session)?;
        let node = resolve_through_alias(&state, node)?;
        state.check_node_readable(node, session)?;
        Ok(node.clone())
    }

    /// Create a folder-like node (directory/dropbox/upload folder) named
    /// `name` in the real folder at `parent_path`. Requires what an upload
    /// there requires, plus owner/admin inside a drop box. The new folder's
    /// classes are clamped to the caller's own class (nobody hands out
    /// access they don't have), and `owner` may only name the caller unless
    /// they hold `USER_ADMIN`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_folder(
        &self,
        parent_path: &str,
        name: &str,
        kind: NodeKind,
        min_class_read: BaseClass,
        min_class_write: BaseClass,
        owner: Option<&str>,
        session: &Session,
    ) -> Result<Node, TreeError> {
        if !kind.is_folder() {
            return Err(TreeError::NotAFolder);
        }
        validate_name(name)?;
        let owner = owner.filter(|o| !o.is_empty());
        if let Some(owner) = owner {
            if owner.len() > limits::MAX_USERNAME_LEN {
                return Err(TreeError::InvalidName("owner name is too long"));
            }
            if owner != session.username && !session.privileges.contains(Privileges::USER_ADMIN) {
                return Err(AclError::ForeignOwner.into());
            }
        }
        let min_class_read = min_class_read.min(session.class);
        let min_class_write = min_class_write.min(session.class);

        // One write guard across check → insert → memory update, so a
        // concurrent delete or same-name create can't land in between.
        let mut state = self.state.write().await;
        let parent_id = {
            let parent = state.resolve_as(parent_path, session)?;
            if !parent.kind.is_folder() {
                return Err(TreeError::NotAFolder);
            }
            state.check_place_into(parent, session, true)?;
            state.check_room(parent, 0, 1 + name.len())?;
            if state.name_taken(&parent.id, name) {
                return Err(TreeError::Exists);
            }
            parent.id.clone()
        };
        let row = file_tree::create_folder(
            &self.pool,
            &parent_id,
            name,
            kind.as_u8() as i64,
            min_class_read as i64,
            min_class_write as i64,
            owner,
        )
        .await
        .map_err(map_write_err)?;
        let node = node_from_row(row)?;
        Self::insert_in_memory(&mut state, node.clone());
        Ok(node)
    }

    /// Create an alias entry at `dest_path` pointing to the node at
    /// `source_path`, with the source's own leaf name. Requires read access
    /// to the source (you may only point at what you can see) and the same
    /// access to `dest_path` as creating a folder there. The source may be
    /// any real node (file, folder, dropbox, or upload folder) but NOT
    /// another alias — no chains, so `resolve_through_alias` is a single hop
    /// and can't loop. Name collisions at the destination are refused.
    pub async fn create_alias(
        &self,
        source_path: &str,
        dest_path: &str,
        session: &Session,
    ) -> Result<Node, TreeError> {
        let mut state = self.state.write().await;
        let (source_id, alias_name, dest_id) = {
            let source = state.resolve_as(source_path, session)?;
            if source.kind == NodeKind::Alias {
                return Err(TreeError::AliasChainRefused);
            }
            if source.id == ROOT_ID {
                // Aliasing the root would let a caller shadow everything
                // under an arbitrary name — refuse for the same reason we
                // refuse to move or delete the root.
                return Err(TreeError::NotAFile);
            }
            state.check_node_readable(source, session)?;
            let alias_name = source.name.clone();
            validate_name(&alias_name)?;
            let dest = state.resolve_as(dest_path, session)?;
            if !dest.kind.is_folder() {
                return Err(TreeError::NotAFolder);
            }
            state.check_place_into(dest, session, true)?;
            state.check_room(dest, 0, 1 + alias_name.len())?;
            if state.name_taken(&dest.id, &alias_name) {
                return Err(TreeError::Exists);
            }
            (source.id.clone(), alias_name, dest.id.clone())
        };
        let row = file_tree::create_alias(&self.pool, &dest_id, &alias_name, &source_id)
            .await
            .map_err(map_write_err)?;
        let node = node_from_row(row)?;
        Self::insert_in_memory(&mut state, node.clone());
        Ok(node)
    }

    /// Record a completed upload as a file node. Re-checks, under the tree
    /// write lock, that the parent folder still exists (`NotFound` if it was
    /// deleted meanwhile) and that the name is still free (`Exists` if a
    /// concurrent upload or create took it), so the caller can clean up.
    pub async fn add_file(
        &self,
        parent_id: &str,
        name: &str,
        size: u64,
        sha256: &[u8],
        storage_path: &str,
    ) -> Result<Node, TreeError> {
        validate_name(name)?;
        let mut state = self.state.write().await;
        let parent = state.nodes.get(parent_id).ok_or(TreeError::NotFound)?;
        if !parent.kind.is_folder() {
            return Err(TreeError::NotAFolder);
        }
        if state.name_taken(parent_id, name) {
            return Err(TreeError::Exists);
        }
        let row =
            file_tree::create_file(&self.pool, parent_id, name, size as i64, sha256, storage_path)
                .await
                .map_err(map_write_err)?;
        let node = node_from_row(row)?;
        Self::insert_in_memory(&mut state, node.clone());
        Ok(node)
    }

    /// Delete a node (recursively, for folders). The root cannot be deleted.
    /// Needs `FILE_DELETE`, plus `FILE_MANAGE_TREE` for a folder. Taking
    /// the node out of its folder follows that folder's removal rule
    /// (class gate, `[ul]` admin-only, `[db]` owner/admin), and a folder
    /// delete empties every folder below it, so each of those must be
    /// deletable — and, if non-empty, readable — too: one refusal anywhere
    /// refuses the whole delete. Returns the deleted node's kind.
    ///
    /// The rows go in one transaction (all or nothing), then the in-memory
    /// tree is updated, and only then — with the lock released — are the
    /// backing files unlinked, best-effort. So a failure leaves the tree,
    /// the DB and the bytes exactly as they were.
    ///
    /// Holds a single write-lock guard from validation to the in-memory
    /// update rather than a read lock that's dropped and later re-acquired —
    /// a `tokio::sync::RwLock` guard is safe to hold across `.await`, and
    /// doing so means a concurrent `add_file`/`move_node` can't land in the
    /// gap and get silently swept up (or left dangling) by a stale snapshot.
    pub async fn delete(&self, path: &str, session: &Session) -> Result<NodeKind, TreeError> {
        let mut state = self.state.write().await;

        let (kind, node_id, parent_id, ordered, storage_paths) = {
            let node = state.resolve_as(path, session)?;
            if node.id == ROOT_ID {
                return Err(TreeError::NotAFolder); // root isn't a deletable entry
            }
            let parent = state.parent_of(node)?;
            state.check_read_chain(parent, session)?;
            check_remove_from(parent, session)?;
            if !session.privileges.contains(Privileges::FILE_DELETE) {
                return Err(AclError::PrivilegeRequired("FILE_DELETE").into());
            }
            if node.kind.is_folder() && !session.privileges.contains(Privileges::FILE_MANAGE_TREE) {
                return Err(AclError::PrivilegeRequired("FILE_MANAGE_TREE").into());
            }
            let (ordered, storage_paths) = state.collect_subtree_for_delete(node, session)?;
            (
                node.kind,
                node.id.clone(),
                parent.id.clone(),
                ordered,
                storage_paths,
            )
        };

        file_tree::delete_many(&self.pool, &ordered).await?;

        for id in &ordered {
            state.nodes.remove(id);
            state.children.remove(id);
        }
        if let Some(siblings) = state.children.get_mut(&parent_id) {
            siblings.retain(|id| id != &node_id);
        }
        drop(state);

        for sp in &storage_paths {
            if let Err(e) = tokio::fs::remove_file(sp).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!(error = %e, "could not remove a deleted file's bytes");
                }
            }
        }
        Ok(kind)
    }

    /// Move a node to a new parent folder (Select-for-Move → Move-into),
    /// keeping its name. Taking it out of its current folder follows the
    /// same removal rule as `delete` (and moving a folder needs that
    /// folder's own rule too); placing it follows the same rule as creating
    /// a folder at the destination. Refuses to move the root, move a folder
    /// into itself or one of its own descendants, move onto a name
    /// collision, or nest the moved subtree past the depth/path caps.
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

        let (node_id, dest_id) = {
            let node = state.resolve_as(path, session)?;
            if node.id == ROOT_ID {
                return Err(TreeError::NotAFolder); // root isn't a movable entry
            }
            let parent = state.parent_of(node)?;
            state.check_read_chain(parent, session)?;
            check_remove_from(parent, session)?;
            if node.kind.is_folder() {
                check_remove_from(node, session)?;
            }
            let dest = state.resolve_as(dest_path, session)?;
            if !dest.kind.is_folder() {
                return Err(TreeError::NotAFolder);
            }
            state.check_place_into(dest, session, true)?;
            if state.ancestry(dest)?.iter().any(|n| n.id == node.id) {
                return Err(TreeError::WouldCreateCycle);
            }
            if dest.id != parent.id && state.name_taken(&dest.id, &node.name) {
                return Err(TreeError::Exists);
            }
            let (height, rel_len) = state.subtree_extent(node)?;
            state.check_room(dest, height, rel_len)?;
            (node.id.clone(), dest.id.clone())
        };

        file_tree::reparent(&self.pool, &node_id, &dest_id)
            .await
            .map_err(map_write_err)?;

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
    /// in the tree, excluding drop-box subtrees (kind or `[db]` — their
    /// contents are never listable except by owner/admin). Returns the
    /// number of entries indexed.
    pub async fn generate_catalog(&self) -> usize {
        let entries = {
            let state = self.state.read().await;
            collect_catalog(&state)
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

    fn insert_in_memory(state: &mut TreeState, node: Node) {
        if let Some(parent) = &node.parent_id {
            state
                .children
                .entry(parent.clone())
                .or_default()
                .push(node.id.clone());
        }
        state.nodes.insert(node.id.clone(), node);
    }

    /// The current `/`-separated path of node `id` (`"/"` for the root), or
    /// `None` if it is no longer in the tree. Lets a resumed upload re-check
    /// its destination folder (stored by id) through `prepare_upload`.
    pub async fn path_of(&self, id: &str) -> Option<String> {
        let state = self.state.read().await;
        let mut node = state.nodes.get(id)?;
        let mut segments = Vec::new();
        while let Some(parent_id) = &node.parent_id {
            if segments.len() > state.nodes.len() {
                return None; // cycle: fail closed
            }
            segments.push(node.name.as_str());
            node = state.nodes.get(parent_id)?;
        }
        if node.id != ROOT_ID {
            return None; // detached from the root
        }
        segments.reverse();
        Some(format!("/{}", segments.join("/")))
    }
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

/// Flatten the tree into catalog entries with full `/`-joined paths, using
/// an explicit stack (no recursion, so depth can't overflow the stack).
/// Each entry carries the highest read class on its way down. Does not
/// descend into (or index the contents of) a drop box — kind DropBox or a
/// `[db]` folder — nor into aliases, and skips any entry whose path would
/// exceed `limits::MAX_PATH_LEN` (only possible for rows from an older
/// build), together with everything below it.
fn collect_catalog(state: &TreeState) -> Vec<CatalogEntry> {
    let mut out = Vec::new();
    let Some(root) = state.nodes.get(ROOT_ID) else {
        return out;
    };
    // (folder, its path ("" for the root), highest read class down to it)
    let mut stack: Vec<(&Node, String, BaseClass)> =
        vec![(root, String::new(), root.min_class_read)];
    let mut visited = 0usize;
    while let Some((folder, folder_path, folder_class)) = stack.pop() {
        visited += 1;
        if visited > state.nodes.len() {
            break; // can't happen in a tree; fail safe if the links are corrupt
        }
        for child in state.child_nodes(&folder.id) {
            if child.kind == NodeKind::Alias {
                // Aliases aren't indexed — the target already is, and
                // indexing both would give duplicate hits for the same
                // underlying content.
                continue;
            }
            let path = format!("{folder_path}/{}", child.name);
            if path.len() > limits::MAX_PATH_LEN {
                continue;
            }
            let min_read_class = if child.kind.is_folder() {
                folder_class.max(child.min_class_read)
            } else {
                // A file's visibility follows its containing folder's gate
                // (mirrors open_for_read), not any class of its own.
                folder_class
            };
            out.push(CatalogEntry {
                path: path.clone(),
                name: child.name.clone(),
                kind: child.kind,
                size: child.size,
                min_read_class,
            });
            if child.kind.is_folder() && !acl::is_drop_box(child.kind, child.access_item) {
                stack.push((child, path, min_read_class));
            }
        }
    }
    out
}

impl TreeState {
    /// Walk `path` segment by segment, applying no ACL. Aliases are followed
    /// at each intermediate step so a path like `/aliases/pub/readme.txt`
    /// resolves correctly when `pub` is an alias pointing at `/pub` (the
    /// walk into `readme.txt` continues in the target's children, not the
    /// alias's empty children map). The *final* segment is intentionally
    /// NOT unwrapped here — callers use `resolve_through_alias` to decide
    /// whether to see the alias node itself (e.g. `delete` deletes just the
    /// alias) or the target (e.g. `list` / `open_for_read` read through).
    fn resolve(&self, path: &str) -> Result<&Node, TreeError> {
        self.walk(path, None)
    }

    /// `resolve`, but every folder the walk looks inside must be readable by
    /// `session` (its own rule, and — after an alias hop — the target's
    /// whole ancestry). An unreadable folder therefore answers with the same
    /// ACL error whether or not the name asked for exists inside it. The
    /// final node's own ACL is the caller's to check.
    fn resolve_as(&self, path: &str, session: &Session) -> Result<&Node, TreeError> {
        self.walk(path, Some(session))
    }

    fn walk(&self, path: &str, session: Option<&Session>) -> Result<&Node, TreeError> {
        check_path(path)?;
        let mut current = self.nodes.get(ROOT_ID).ok_or(TreeError::NotFound)?;
        for segment in path.split('/').filter(|s| !s.is_empty()) {
            // Before looking up children, hop through any alias — an alias
            // has no children of its own, so the walk continues in the
            // target's children map. We hop here (not at the terminal
            // result) so that a path landing on an alias still returns the
            // alias node itself; callers use `resolve_through_alias` when
            // they want the target instead.
            let walkable = if current.kind == NodeKind::Alias {
                let target = resolve_through_alias(self, current)?;
                if let Some(s) = session {
                    // The hop lands elsewhere in the tree: the target's own
                    // ancestors gate what's inside it too.
                    self.check_node_readable(target, s)?;
                }
                target
            } else {
                if let Some(s) = session {
                    if current.kind.is_folder() {
                        check_read_node(current, s)?;
                    }
                }
                current
            };
            current = self
                .child_nodes(&walkable.id)
                .find(|n| n.name == *segment)
                .ok_or(TreeError::NotFound)?;
        }
        Ok(current)
    }

    fn child_nodes<'a>(&'a self, id: &str) -> impl Iterator<Item = &'a Node> + 'a {
        self.children
            .get(id)
            .into_iter()
            .flatten()
            .filter_map(|c| self.nodes.get(c))
    }

    fn parent_of(&self, node: &Node) -> Result<&Node, TreeError> {
        node.parent_id
            .as_deref()
            .and_then(|id| self.nodes.get(id))
            .ok_or(TreeError::NotFound)
    }

    fn name_taken(&self, parent_id: &str, name: &str) -> bool {
        self.child_nodes(parent_id).any(|n| n.name == name)
    }

    /// `start`, its parent, …, the root — walked iteratively and bounded by
    /// the node count, so neither a deep chain nor corrupt parent links can
    /// overflow or hang. A chain that doesn't end at the root fails closed.
    fn ancestry<'a>(&'a self, start: &'a Node) -> Result<Vec<&'a Node>, TreeError> {
        let mut chain = vec![start];
        let mut node = start;
        while let Some(pid) = &node.parent_id {
            if chain.len() > self.nodes.len() {
                return Err(TreeError::NotFound); // parent links loop
            }
            node = self.nodes.get(pid).ok_or(TreeError::NotFound)?;
            chain.push(node);
        }
        if node.id != ROOT_ID {
            return Err(TreeError::NotFound); // detached from the root
        }
        Ok(chain)
    }

    /// The inherited read gate on `folder`'s contents: `check_read` must
    /// pass on `folder` and on every folder above it. Checked from the root
    /// down, so the error names the outermost folder that refuses.
    fn check_read_chain(&self, folder: &Node, s: &Session) -> Result<(), TreeError> {
        for node in self.ancestry(folder)?.iter().rev() {
            check_read_node(node, s)?;
        }
        Ok(())
    }

    /// May `s` read `node` — list it if it's a folder, download it or see
    /// its info if it's a file?
    fn check_node_readable(&self, node: &Node, s: &Session) -> Result<(), TreeError> {
        if node.kind.is_folder() {
            self.check_read_chain(node, s)
        } else {
            self.check_read_chain(self.parent_of(node)?, s)
        }
    }

    /// May `s` put a new entry into the folder `dest`? Every folder above
    /// `dest` must be readable (a drop box or class gate higher up covers
    /// the whole subtree), and `dest` itself must pass its write gate.
    /// `manage` marks a tree operation (new folder, alias, move-into) rather
    /// than an upload: inside a drop box those are owner/admin only.
    fn check_place_into(&self, dest: &Node, s: &Session, manage: bool) -> Result<(), TreeError> {
        if dest.parent_id.is_some() {
            self.check_read_chain(self.parent_of(dest)?, s)?;
        }
        check_write_node(dest, s)?;
        if manage
            && acl::is_drop_box(dest.kind, dest.access_item)
            && s.class < BaseClass::Admin
            && dest.owner.as_deref() != Some(s.username.as_str())
        {
            return Err(AclError::OwnerOnly.into());
        }
        Ok(())
    }

    /// Would placing a subtree `height` levels tall, whose longest path
    /// below `parent` is `rel_len` bytes (counting each `/`), under
    /// `parent` stay within `limits::MAX_TREE_DEPTH` and
    /// `limits::MAX_PATH_LEN`? For a single new entry: `height` 0,
    /// `rel_len` = 1 + its name's length.
    fn check_room(&self, parent: &Node, height: usize, rel_len: usize) -> Result<(), TreeError> {
        let chain = self.ancestry(parent)?;
        let depth = chain.len() - 1;
        let path_len: usize = chain
            .iter()
            .filter(|n| n.parent_id.is_some())
            .map(|n| 1 + n.name.len())
            .sum();
        if depth + 1 + height > limits::MAX_TREE_DEPTH {
            return Err(TreeError::TooDeep);
        }
        if path_len + rel_len > limits::MAX_PATH_LEN {
            return Err(TreeError::InvalidPath("path is too long"));
        }
        Ok(())
    }

    /// Height of `top`'s subtree (0 for a leaf) and the byte length of its
    /// longest path measured from `top`'s parent (`/top/…`). Iterative.
    fn subtree_extent(&self, top: &Node) -> Result<(usize, usize), TreeError> {
        let (mut height, mut rel_len) = (0, 0);
        let mut stack = vec![(top, 0usize, 1 + top.name.len())];
        let mut visited = 0usize;
        while let Some((node, h, len)) = stack.pop() {
            visited += 1;
            if visited > self.nodes.len() {
                return Err(TreeError::NotFound); // child links loop: corrupt
            }
            height = height.max(h);
            rel_len = rel_len.max(len);
            for child in self.child_nodes(&node.id) {
                stack.push((child, h + 1, len + 1 + child.name.len()));
            }
        }
        Ok((height, rel_len))
    }

    /// Every node in `top`'s subtree, children before parents (the order
    /// the rows must be deleted in), plus the storage paths of its files —
    /// after checking `s` may remove each one. Deleting a folder empties it
    /// first, so every folder in the subtree must pass its own removal rule
    /// and, if it has contents, be readable. Iterative.
    fn collect_subtree_for_delete(
        &self,
        top: &Node,
        s: &Session,
    ) -> Result<(Vec<String>, Vec<String>), TreeError> {
        let mut preorder = Vec::new();
        let mut storage_paths = Vec::new();
        let mut stack = vec![top];
        while let Some(node) = stack.pop() {
            if preorder.len() >= self.nodes.len() {
                return Err(TreeError::NotFound); // child links loop: corrupt
            }
            if node.kind.is_folder() {
                check_remove_from(node, s)?;
                let before = stack.len();
                stack.extend(self.child_nodes(&node.id));
                if stack.len() > before {
                    check_read_node(node, s)?;
                }
            }
            if let Some(sp) = &node.storage_path {
                storage_paths.push(sp.clone());
            }
            preorder.push(node.id.clone());
        }
        preorder.reverse();
        Ok((preorder, storage_paths))
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

    fn admin() -> Session {
        sess(BaseClass::Admin)
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
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::PowerUser, None, &admin())
            .await
            .unwrap();
        tree.create_folder("/pub", "docs", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
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
        tree.create_folder("/", "drop", NodeKind::DropBox, BaseClass::Guest, BaseClass::User, None, &admin())
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
            &admin(),
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
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();
        tree.create_folder("/pub", "docs", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();
        let parent = tree.resolve("/pub/docs").await.unwrap();
        tree.add_file(&parent.id, "a.txt", 1, &[0u8; 32], "/tmp/none")
            .await
            .unwrap();

        // Removing /pub from the root needs the root's write class
        // (PowerUser by default) and FILE_DELETE + FILE_MANAGE_TREE; /pub's
        // own write class (User) and its contents' are no obstacle.
        assert!(tree.delete("/pub", &sess(BaseClass::User)).await.is_err());
        tree.delete("/pub", &sess(BaseClass::PowerUser)).await.unwrap();
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
        tree.create_folder("/", "staff", NodeKind::Directory, BaseClass::Guest, BaseClass::Admin, None, &admin())
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
        tree.create_folder("/", "inbox [DB]", NodeKind::Directory, BaseClass::Guest, BaseClass::User, Some("bob"), &admin())
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
        tree.create_folder("/", "uploads [UL]", NodeKind::Directory, BaseClass::Guest, BaseClass::Guest, None, &admin())
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
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
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
            BaseClass::Admin, None, &admin())
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
        tree.create_folder("/", "drop", NodeKind::DropBox, BaseClass::Guest, BaseClass::User, None, &admin())
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
        tree.create_folder("/", "a", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();
        tree.create_folder("/", "b", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();
        let a = tree.resolve("/a").await.unwrap();
        tree.add_file(&a.id, "doc.txt", 3, &[0u8; 32], "/tmp/x")
            .await
            .unwrap();
        tree.create_folder("/a", "sub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();

        // Taking /a out of the root needs the root's write class.
        tree.move_node("/a", "/b", &sess(BaseClass::PowerUser)).await.unwrap();

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
        tree.create_folder("/", "x", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();
        tree.create_folder("/", "y", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();

        let u = sess(BaseClass::PowerUser);
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
        tree.create_folder("/", "a", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();
        tree.create_folder("/a", "sub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();

        // Can't move a folder into its own descendant.
        assert!(matches!(
            tree.move_node("/a", "/a/sub", &sess(BaseClass::PowerUser)).await,
            Err(TreeError::WouldCreateCycle)
        ));
        // Can't move a folder into itself.
        assert!(matches!(
            tree.move_node("/a", "/a", &sess(BaseClass::PowerUser)).await,
            Err(TreeError::WouldCreateCycle)
        ));
        // Root is not a movable entry.
        assert!(tree.move_node("/", "/a", &sess(BaseClass::Admin)).await.is_err());

        // Name collision at the destination is refused. (Root's default write
        // class is PowerUser, so use that here — this assertion is about the
        // collision check, not the ACL check exercised above.)
        tree.create_folder("/", "sub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
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
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();
        let pub_dir = tree.resolve("/pub").await.unwrap();
        tree.add_file(&pub_dir.id, "a.txt", 42, &[0u8; 32], "/tmp/a")
            .await
            .unwrap();
        tree.create_folder("/", "aliases", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
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
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();
        let pub_dir = tree.resolve("/pub").await.unwrap();
        let file = tree
            .add_file(&pub_dir.id, "readme.txt", 10, &[0u8; 32], "/tmp/readme")
            .await
            .unwrap();
        tree.create_folder("/", "aliases", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
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
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();
        let pub_dir = tree.resolve("/pub").await.unwrap();
        tree.add_file(&pub_dir.id, "readme.txt", 5, &[0u8; 32], "/tmp/r")
            .await
            .unwrap();
        tree.create_folder("/", "links", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
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
            BaseClass::Admin, None, &admin())
        .await
        .unwrap();
        let vault = tree.resolve("/vault").await.unwrap();
        tree.add_file(&vault.id, "secret.txt", 1, &[0u8; 32], "/tmp/s")
            .await
            .unwrap();

        // The permissive folder anyone can read.
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::Admin, None, &admin())
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
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();
        tree.create_folder("/", "aliases", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
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
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();
        let pub_dir = tree.resolve("/pub").await.unwrap();
        tree.add_file(&pub_dir.id, "a.txt", 1, &[0u8; 32], "/tmp/a")
            .await
            .unwrap();
        tree.create_folder("/", "aliases", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
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
        tree.create_folder("/", "drop", NodeKind::DropBox, BaseClass::Guest, BaseClass::Admin, None, &admin())
            .await
            .unwrap();
        tree.create_folder("/", "src", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
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
        tree.create_folder("/", "movable", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();
        tree.create_folder("/", "vault", NodeKind::Directory, BaseClass::Guest, BaseClass::Admin, None, &admin())
            .await
            .unwrap();
        tree.create_folder(
            "/",
            "locked",
            NodeKind::Directory,
            BaseClass::Guest,
            BaseClass::Admin, None, &admin())
        .await
        .unwrap();

        // A plain user can't move into an admin-only destination...
        assert!(tree.move_node("/movable", "/vault", &sess(BaseClass::User)).await.is_err());
        // ...nor move a node they can't write to in the first place.
        assert!(tree.move_node("/locked", "/", &sess(BaseClass::User)).await.is_err());
        // An admin can do both.
        assert!(tree.move_node("/movable", "/vault", &sess(BaseClass::Admin)).await.is_ok());
    }

    // ---- hardening regressions (FILES-1..13) -------------------------------

    fn named(class: BaseClass, username: &str) -> Session {
        let mut s = sess(class);
        s.username = username.into();
        s
    }

    /// `/drop` (kind DropBox, owner bob, writable by Users) holding `a.txt`.
    async fn drop_box_with_file(tree: &FileTree) {
        tree.create_folder(
            "/",
            "drop",
            NodeKind::DropBox,
            BaseClass::Guest,
            BaseClass::User,
            Some("bob"),
            &admin(),
        )
        .await
        .unwrap();
        let drop = tree.resolve("/drop").await.unwrap();
        tree.add_file(&drop.id, "a.txt", 1, &[0u8; 32], "/tmp/none")
            .await
            .unwrap();
    }

    /// `/vault` (read+write Admin) holding `payroll.csv`.
    async fn vault_with_file(tree: &FileTree) {
        tree.create_folder("/", "vault", NodeKind::Directory, BaseClass::Admin, BaseClass::Admin, None, &admin())
            .await
            .unwrap();
        let vault = tree.resolve("/vault").await.unwrap();
        tree.add_file(&vault.id, "payroll.csv", 1, &[0u8; 32], "/tmp/none")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn files1_cannot_move_out_of_drop_box_or_restricted_folder() {
        let (tree, _dir) = tree().await;
        drop_box_with_file(&tree).await;
        vault_with_file(&tree).await;
        tree.create_folder("/", "inbox [db]", NodeKind::Directory, BaseClass::Guest, BaseClass::User, Some("bob"), &admin())
            .await
            .unwrap();
        let inbox = tree.resolve("/inbox [db]").await.unwrap();
        tree.add_file(&inbox.id, "b.txt", 1, &[0u8; 32], "/tmp/none")
            .await
            .unwrap();

        let alice = named(BaseClass::PowerUser, "alice");
        for path in ["/drop/a.txt", "/inbox [db]/b.txt", "/vault/payroll.csv"] {
            assert!(
                matches!(tree.move_node(path, "/", &alice).await, Err(TreeError::Acl(_))),
                "{path} moved out by a non-owner"
            );
            assert!(tree.resolve(path).await.is_ok());
        }
        // The owner may move their own drop box's contents; so may an admin.
        let bob = named(BaseClass::PowerUser, "bob");
        tree.move_node("/drop/a.txt", "/", &bob).await.unwrap();
        tree.move_node("/vault/payroll.csv", "/", &admin()).await.unwrap();
    }

    #[tokio::test]
    async fn files1_moving_into_someone_elses_drop_box_is_refused() {
        let (tree, _dir) = tree().await;
        drop_box_with_file(&tree).await;
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();
        let alice = named(BaseClass::PowerUser, "alice");
        assert!(matches!(
            tree.move_node("/pub", "/drop", &alice).await,
            Err(TreeError::Acl(AclError::OwnerOnly))
        ));
    }

    #[tokio::test]
    async fn files2_read_acl_is_inherited_from_every_ancestor() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "staff", NodeKind::Directory, BaseClass::PowerUser, BaseClass::Admin, None, &admin())
            .await
            .unwrap();
        // Created with the dialog's default (Guest) read class.
        tree.create_folder("/staff", "pay", NodeKind::Directory, BaseClass::Guest, BaseClass::Admin, None, &admin())
            .await
            .unwrap();
        let pay = tree.resolve("/staff/pay").await.unwrap();
        tree.add_file(&pay.id, "2026.xlsx", 1, &[0u8; 32], "/tmp/none")
            .await
            .unwrap();

        let user = sess(BaseClass::User);
        assert!(matches!(tree.list("/staff/pay", &user).await, Err(TreeError::Acl(_))));
        assert!(matches!(
            tree.open_for_read("/staff/pay/2026.xlsx", &user).await,
            Err(TreeError::Acl(_))
        ));
        assert!(matches!(tree.info("/staff/pay/2026.xlsx", &user).await, Err(TreeError::Acl(_))));
        let power = sess(BaseClass::PowerUser);
        assert!(tree.list("/staff/pay", &power).await.is_ok());
        assert!(tree.open_for_read("/staff/pay/2026.xlsx", &power).await.is_ok());

        // The catalog carries the highest class on the way down.
        tree.generate_catalog().await;
        let user_hits = tree.search("", BaseClass::User, 50).await.unwrap();
        assert!(user_hits.iter().all(|e| !e.path.starts_with("/staff")), "{user_hits:?}");
        let power_hits = tree.search("", BaseClass::PowerUser, 50).await.unwrap();
        assert!(power_hits.iter().any(|e| e.path == "/staff/pay/2026.xlsx"));
    }

    #[tokio::test]
    async fn files2_a_drop_box_covers_its_whole_subtree_even_through_aliases() {
        let (tree, _dir) = tree().await;
        drop_box_with_file(&tree).await;
        tree.create_folder("/drop", "sub", NodeKind::Directory, BaseClass::Guest, BaseClass::Guest, None, &admin())
            .await
            .unwrap();
        let sub = tree.resolve("/drop/sub").await.unwrap();
        tree.add_file(&sub.id, "s.txt", 1, &[0u8; 32], "/tmp/none")
            .await
            .unwrap();
        tree.create_folder("/", "links", NodeKind::Directory, BaseClass::Guest, BaseClass::Admin, None, &admin())
            .await
            .unwrap();
        tree.create_alias("/drop/sub", "/links", &admin()).await.unwrap();

        let guest = sess(BaseClass::Guest);
        assert!(matches!(tree.list("/drop/sub", &guest).await, Err(TreeError::Acl(_))));
        assert!(matches!(tree.list("/links/sub", &guest).await, Err(TreeError::Acl(_))));
        assert!(matches!(
            tree.open_for_read("/links/sub/s.txt", &guest).await,
            Err(TreeError::Acl(_))
        ));
        // Uploading *into* the box is its purpose; into anything below it isn't.
        let user = sess(BaseClass::User);
        assert!(tree.prepare_upload("/drop", "new.bin", &user).await.is_ok());
        assert!(matches!(
            tree.prepare_upload("/drop/sub", "new.bin", &user).await,
            Err(TreeError::Acl(_))
        ));
        // The owner and admins still get in.
        let bob = named(BaseClass::User, "bob");
        assert!(tree.list("/drop/sub", &bob).await.is_ok());
        assert!(tree.open_for_read("/links/sub/s.txt", &admin()).await.is_ok());
    }

    #[tokio::test]
    async fn files4_delete_follows_the_containing_folders_rules() {
        let (tree, _dir) = tree().await;
        drop_box_with_file(&tree).await;
        // Readable by all, writable only by admins.
        tree.create_folder("/", "software", NodeKind::Directory, BaseClass::Guest, BaseClass::Admin, None, &admin())
            .await
            .unwrap();
        let software = tree.resolve("/software").await.unwrap();
        tree.add_file(&software.id, "app.zip", 1, &[0u8; 32], "/tmp/none")
            .await
            .unwrap();
        // An upload folder by kind, without a `[ul]` suffix.
        tree.create_folder("/", "incoming", NodeKind::UploadFolder, BaseClass::Guest, BaseClass::Guest, None, &admin())
            .await
            .unwrap();
        let incoming = tree.resolve("/incoming").await.unwrap();
        tree.add_file(&incoming.id, "up.bin", 1, &[0u8; 32], "/tmp/none")
            .await
            .unwrap();

        let alice = named(BaseClass::PowerUser, "alice");
        for path in ["/drop/a.txt", "/software/app.zip", "/incoming/up.bin"] {
            assert!(
                matches!(tree.delete(path, &alice).await, Err(TreeError::Acl(_))),
                "{path} deleted by a power user"
            );
            assert!(tree.resolve(path).await.is_ok());
        }
        let bob = named(BaseClass::PowerUser, "bob");
        tree.delete("/drop/a.txt", &bob).await.unwrap();
        tree.delete("/software/app.zip", &admin()).await.unwrap();
        tree.delete("/incoming/up.bin", &admin()).await.unwrap();
    }

    #[tokio::test]
    async fn files5_recursive_delete_checks_every_descendant() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "Public", NodeKind::Directory, BaseClass::Guest, BaseClass::PowerUser, None, &admin())
            .await
            .unwrap();
        tree.create_folder("/Public", "Inbox [db]", NodeKind::Directory, BaseClass::Guest, BaseClass::Guest, Some("bob"), &admin())
            .await
            .unwrap();
        tree.create_folder("/Public", "Uploads [UL]", NodeKind::Directory, BaseClass::Guest, BaseClass::Guest, None, &admin())
            .await
            .unwrap();
        tree.create_folder("/Public", "vault", NodeKind::Directory, BaseClass::Guest, BaseClass::Admin, None, &admin())
            .await
            .unwrap();
        for folder in ["/Public/Inbox [db]", "/Public/Uploads [UL]", "/Public/vault"] {
            let f = tree.resolve(folder).await.unwrap();
            tree.add_file(&f.id, "f", 1, &[0u8; 32], "/tmp/none").await.unwrap();
        }

        let alice = named(BaseClass::PowerUser, "alice");
        // Each protected child alone blocks the whole delete.
        for protected in ["/Public/Inbox [db]", "/Public/Uploads [UL]", "/Public/vault"] {
            assert!(
                matches!(tree.delete("/Public", &alice).await, Err(TreeError::Acl(_))),
                "delete went through with {protected} inside"
            );
            assert!(tree.resolve(&format!("{protected}/f")).await.is_ok());
            tree.delete(protected, &admin()).await.unwrap();
        }
        tree.delete("/Public", &alice).await.unwrap();
    }

    #[tokio::test]
    async fn files6_create_folder_checks_parent_acl_kind_and_requested_rights() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "locked", NodeKind::Directory, BaseClass::Guest, BaseClass::Admin, None, &admin())
            .await
            .unwrap();
        drop_box_with_file(&tree).await;
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();
        tree.create_alias("/pub", "/locked", &admin()).await.unwrap();

        let alice = named(BaseClass::PowerUser, "alice");
        let mk = |parent: &'static str, owner: Option<&'static str>| {
            let alice = alice.clone();
            let tree = &tree;
            async move {
                tree.create_folder(parent, "x", NodeKind::Directory, BaseClass::Guest, BaseClass::Guest, owner, &alice)
                    .await
            }
        };
        // No write access to the parent.
        assert!(matches!(mk("/locked", None).await, Err(TreeError::Acl(_))));
        assert!(matches!(tree.resolve("/locked/x").await, Err(TreeError::NotFound)));
        // Inside someone else's drop box.
        assert!(matches!(mk("/drop", None).await, Err(TreeError::Acl(AclError::OwnerOnly))));
        // Under a file, or under an alias (which would make an unreachable child).
        tree.add_file(&tree.resolve("/pub").await.unwrap().id, "f.txt", 1, &[0u8; 32], "/tmp/none")
            .await
            .unwrap();
        assert!(matches!(mk("/pub/f.txt", None).await, Err(TreeError::NotAFolder)));
        assert!(matches!(
            tree.create_folder("/locked/pub", "x", NodeKind::Directory, BaseClass::Guest, BaseClass::Guest, None, &admin())
                .await,
            Err(TreeError::NotAFolder)
        ));
        // Only an account admin may name someone else as owner.
        assert!(matches!(mk("/pub", Some("bob")).await, Err(TreeError::Acl(AclError::ForeignOwner))));
        let own = mk("/pub", Some("alice")).await.unwrap();
        assert_eq!(own.owner.as_deref(), Some("alice"));
        let by_admin = tree
            .create_folder("/pub", "for-bob", NodeKind::DropBox, BaseClass::Guest, BaseClass::Guest, Some("bob"), &admin())
            .await
            .unwrap();
        assert_eq!(by_admin.owner.as_deref(), Some("bob"));

        // Requested classes above the caller's own are clamped to it.
        let high = tree
            .create_folder("/pub", "high", NodeKind::Directory, BaseClass::Admin, BaseClass::Admin, None, &alice)
            .await
            .unwrap();
        assert_eq!(high.min_class_read, BaseClass::PowerUser);
        assert_eq!(high.min_class_write, BaseClass::PowerUser);
        // The bob-owned drop box's owner may build inside it.
        let bob = named(BaseClass::PowerUser, "bob");
        tree.create_folder("/drop", "sorted", NodeKind::Directory, BaseClass::Guest, BaseClass::Guest, None, &bob)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn files7_delete_needs_file_delete_and_manage_tree_for_folders() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();
        let pub_dir = tree.resolve("/pub").await.unwrap();
        tree.add_file(&pub_dir.id, "a.txt", 1, &[0u8; 32], "/tmp/none")
            .await
            .unwrap();

        let mut no_delete = sess(BaseClass::PowerUser);
        no_delete.privileges -= Privileges::FILE_DELETE;
        assert!(matches!(
            tree.delete("/pub/a.txt", &no_delete).await,
            Err(TreeError::Acl(AclError::PrivilegeRequired("FILE_DELETE")))
        ));
        // A User granted FILE_DELETE may delete a file where their class may
        // write, but not a folder without FILE_MANAGE_TREE.
        let mut user = sess(BaseClass::User);
        user.privileges |= Privileges::FILE_DELETE;
        let mut power_no_tree = sess(BaseClass::PowerUser);
        power_no_tree.privileges -= Privileges::FILE_MANAGE_TREE;
        assert!(matches!(
            tree.delete("/pub", &power_no_tree).await,
            Err(TreeError::Acl(AclError::PrivilegeRequired("FILE_MANAGE_TREE")))
        ));
        tree.delete("/pub/a.txt", &user).await.unwrap();
    }

    #[tokio::test]
    async fn files9_catalog_skips_db_folder_contents() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "inbox [db]", NodeKind::Directory, BaseClass::Guest, BaseClass::Guest, Some("bob"), &admin())
            .await
            .unwrap();
        let inbox = tree.resolve("/inbox [db]").await.unwrap();
        tree.add_file(&inbox.id, "secret.zip", 5, &[0u8; 32], "/tmp/none")
            .await
            .unwrap();
        tree.generate_catalog().await;
        for class in [BaseClass::Guest, BaseClass::Admin] {
            let hits = tree.search("", class, 50).await.unwrap();
            assert!(hits.iter().any(|e| e.name == "inbox [db]"));
            assert!(hits.iter().all(|e| e.name != "secret.zip"), "{class:?}: {hits:?}");
        }
    }

    #[test]
    fn files10_validate_name_rules() {
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "/",
            "nul\0byte",
            "tab\there",
            "c1\u{0085}",
            "spoof\u{202E}txt.exe",
            "iso\u{2067}late",
            " lead",
            "trail ",
            "trail\u{00A0}",
        ] {
            assert!(
                matches!(validate_name(bad), Err(TreeError::InvalidName(_))),
                "{bad:?} accepted"
            );
        }
        assert!(validate_name(&"n".repeat(limits::MAX_FILE_NAME_LEN)).is_ok());
        assert!(validate_name(&"n".repeat(limits::MAX_FILE_NAME_LEN + 1)).is_err());
        for good in ["readme.txt", "My Docs [db]", "...", ".hidden", "日本語", "a\\b", "x\u{200D}y"] {
            assert!(validate_name(good).is_ok(), "{good:?} refused");
        }
    }

    #[tokio::test]
    async fn files10_names_are_validated_on_upload_create_and_add() {
        let (tree, _dir) = tree().await;
        let admin = admin();
        for bad in ["", "a/b", "..", "x\u{202E}"] {
            assert!(matches!(
                tree.prepare_upload("/", bad, &admin).await,
                Err(TreeError::InvalidName(_))
            ));
            assert!(matches!(
                tree.create_folder("/", bad, NodeKind::Directory, BaseClass::Guest, BaseClass::Guest, None, &admin)
                    .await,
                Err(TreeError::InvalidName(_))
            ));
            assert!(matches!(
                tree.add_file(ROOT_ID, bad, 1, &[0u8; 32], "/tmp/none").await,
                Err(TreeError::InvalidName(_))
            ));
        }
        // Paths: bounded, no control characters.
        assert!(matches!(tree.list("/a\u{1}b", &admin).await, Err(TreeError::InvalidPath(_))));
        let long = "/x".repeat(limits::MAX_PATH_LEN);
        assert!(matches!(tree.resolve(&long).await, Err(TreeError::InvalidPath(_))));
        assert!(tree.list("/", &admin).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn files3_depth_and_path_length_are_capped() {
        let (tree, _dir) = tree().await;
        let admin = admin();
        let mut path = String::new();
        for _ in 0..limits::MAX_TREE_DEPTH {
            tree.create_folder(if path.is_empty() { "/" } else { &path }, "d", NodeKind::Directory, BaseClass::Guest, BaseClass::Guest, None, &admin)
                .await
                .unwrap();
            path.push_str("/d");
        }
        // One more level is refused, for folders, uploads and aliases alike.
        assert!(matches!(
            tree.create_folder(&path, "d", NodeKind::Directory, BaseClass::Guest, BaseClass::Guest, None, &admin)
                .await,
            Err(TreeError::TooDeep)
        ));
        assert!(matches!(tree.prepare_upload(&path, "f", &admin).await, Err(TreeError::TooDeep)));
        tree.create_folder("/", "src", NodeKind::Directory, BaseClass::Guest, BaseClass::Guest, None, &admin)
            .await
            .unwrap();
        assert!(matches!(tree.create_alias("/src", &path, &admin).await, Err(TreeError::TooDeep)));

        // A move counts the moved subtree's height: /src/sub is 2 levels.
        tree.create_folder("/src", "sub", NodeKind::Directory, BaseClass::Guest, BaseClass::Guest, None, &admin)
            .await
            .unwrap();
        let near_bottom = "/d".repeat(limits::MAX_TREE_DEPTH - 1);
        assert!(matches!(tree.move_node("/src", &near_bottom, &admin).await, Err(TreeError::TooDeep)));
        let fits = "/d".repeat(limits::MAX_TREE_DEPTH - 2);
        tree.move_node("/src", &fits, &admin).await.unwrap();

        // Long names hit the path cap long before the depth cap.
        let name = "n".repeat(limits::MAX_FILE_NAME_LEN);
        let mut long_path = String::new();
        loop {
            let parent = if long_path.is_empty() { "/".to_owned() } else { long_path.clone() };
            match tree
                .create_folder(&parent, &name, NodeKind::Directory, BaseClass::Guest, BaseClass::Guest, None, &admin)
                .await
            {
                Ok(_) => long_path = format!("{long_path}/{name}"),
                Err(e) => {
                    assert!(matches!(e, TreeError::InvalidPath(_)), "{e:?}");
                    break;
                }
            }
        }
        assert!(long_path.len() <= limits::MAX_PATH_LEN);
        assert!(long_path.len() + 1 + name.len() > limits::MAX_PATH_LEN);
    }

    /// Run `f` to completion on a fresh thread with only `stack` bytes of
    /// stack — a recursive walk over a deep chain would overflow it (and
    /// abort the test binary).
    fn on_small_stack<F, Fut>(stack: usize, f: F)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()>,
    {
        std::thread::Builder::new()
            .stack_size(stack)
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(Box::pin(f()));
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn files3_deep_chain_from_storage_is_walked_without_recursion() {
        const CHAIN: usize = 3000;
        on_small_stack(192 * 1024, || async {
            let dir = tempfile::tempdir().unwrap();
            let pool = kdx_storage::connect(&dir.path().join("t.db")).await.unwrap();
            // An older build allowed unbounded nesting; such a chain may
            // already be in the database.
            let mut parent = ROOT_ID.to_owned();
            for i in 0..CHAIN {
                parent = file_tree::create_folder(&pool, &parent, &format!("d{i}"), 0, 0, 2, None)
                    .await
                    .unwrap()
                    .id;
            }
            let tree = FileTree::load(pool.clone()).await.unwrap();
            let admin = sess(BaseClass::Admin);

            // The catalog walk is iterative and stops at the path cap.
            let indexed = tree.generate_catalog().await;
            assert!(indexed > 0 && indexed < CHAIN, "{indexed}");

            // Moving the chain is refused (too deep), not a crash.
            tree.create_folder("/", "elsewhere", NodeKind::Directory, BaseClass::Guest, BaseClass::Guest, None, &admin)
                .await
                .unwrap();
            assert!(matches!(
                tree.move_node("/d0", "/elsewhere", &admin).await,
                Err(TreeError::TooDeep)
            ));
            // Moving into the chain (cycle check + depth) is refused too.
            let deep: String = (0..limits::MAX_TREE_DEPTH).map(|i| format!("/d{i}")).collect();
            assert!(matches!(
                tree.move_node("/elsewhere", &deep, &admin).await,
                Err(TreeError::TooDeep)
            ));

            // Deleting the whole chain works, in one transaction.
            tree.delete("/d0", &admin).await.unwrap();
            assert_eq!(file_tree::all(&pool).await.unwrap().len(), 2); // root + elsewhere
            let left = tree.list("/", &admin).await.unwrap();
            assert_eq!(left.len(), 1);
            assert_eq!(left[0].name, "elsewhere");
        });
    }

    #[tokio::test]
    async fn files11_failed_delete_leaves_db_memory_and_bytes_intact() {
        let (tree, dir) = tree().await;
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();
        let pub_dir = tree.resolve("/pub").await.unwrap();
        let blob = dir.path().join("blob");
        std::fs::write(&blob, b"x").unwrap();
        tree.add_file(&pub_dir.id, "a.txt", 1, &[0u8; 32], &blob.display().to_string())
            .await
            .unwrap();
        // A child row the in-memory tree doesn't know about (e.g. inserted
        // by a racing writer): the folder's own DELETE hits the FK.
        file_tree::create_folder(&tree.pool, &pub_dir.id, "unseen", 0, 0, 2, None)
            .await
            .unwrap();

        let err = tree.delete("/pub", &admin()).await.unwrap_err();
        assert!(matches!(err, TreeError::Storage(_)), "{err:?}");
        assert_eq!(err.client_message(), "storage error"); // no SQL text for clients
        let rows = file_tree::all(&tree.pool).await.unwrap();
        assert!(rows.iter().any(|r| r.name == "a.txt"), "rolled back");
        assert!(rows.iter().any(|r| r.name == "pub"));
        assert!(blob.exists(), "bytes only go once the rows are gone");
        assert!(tree.resolve("/pub/a.txt").await.is_ok());

        // Once the tree knows the whole subtree, the delete goes through and
        // the bytes are removed.
        let tree = FileTree::load(tree.pool.clone()).await.unwrap();
        tree.delete("/pub", &admin()).await.unwrap();
        assert!(!blob.exists());
        assert_eq!(file_tree::all(&tree.pool).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn files11_add_file_rechecks_parent_and_name_under_the_lock() {
        let (tree, _dir) = tree().await;
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();
        let parent = tree
            .prepare_upload("/pub", "up.bin", &sess(BaseClass::User))
            .await
            .unwrap();
        // Same name filed meanwhile → Exists.
        tree.add_file(&parent.id, "up.bin", 1, &[0u8; 32], "/tmp/1").await.unwrap();
        assert!(matches!(
            tree.add_file(&parent.id, "up.bin", 1, &[0u8; 32], "/tmp/2").await,
            Err(TreeError::Exists)
        ));
        // Parent deleted meanwhile → NotFound.
        tree.delete("/pub", &admin()).await.unwrap();
        assert!(matches!(
            tree.add_file(&parent.id, "late.bin", 1, &[0u8; 32], "/tmp/3").await,
            Err(TreeError::NotFound)
        ));
        // A row the memory check can't see still maps to Exists, not a raw
        // SQL error.
        file_tree::create_folder(&tree.pool, ROOT_ID, "ghost", 0, 0, 2, None)
            .await
            .unwrap();
        assert!(matches!(
            tree.create_folder("/", "ghost", NodeKind::Directory, BaseClass::Guest, BaseClass::Guest, None, &admin())
                .await,
            Err(TreeError::Exists)
        ));
    }

    #[tokio::test]
    async fn files13_unreadable_paths_answer_uniformly_and_aliases_need_read() {
        let (tree, _dir) = tree().await;
        vault_with_file(&tree).await;
        drop_box_with_file(&tree).await;
        tree.create_folder("/", "pub", NodeKind::Directory, BaseClass::Guest, BaseClass::User, None, &admin())
            .await
            .unwrap();

        let guest = sess(BaseClass::Guest);
        let existing = tree.info("/vault/payroll.csv", &guest).await.unwrap_err();
        let missing = tree.info("/vault/nope.csv", &guest).await.unwrap_err();
        assert_eq!(existing.to_string(), missing.to_string());
        let alice = named(BaseClass::PowerUser, "alice");
        let existing = tree.open_for_read("/drop/a.txt", &alice).await.unwrap_err();
        let missing = tree.open_for_read("/drop/zz.txt", &alice).await.unwrap_err();
        assert_eq!(existing.to_string(), missing.to_string());

        // Aliasing something you can't read is refused (no probing, no
        // publishing hidden names).
        for source in ["/drop/a.txt", "/vault/payroll.csv", "/vault"] {
            assert!(
                matches!(tree.create_alias(source, "/pub", &alice).await, Err(TreeError::Acl(_))),
                "{source}"
            );
        }
        // An admin's alias to a hidden file doesn't show its size to others.
        tree.create_alias("/vault/payroll.csv", "/pub", &admin()).await.unwrap();
        let seen = tree.list("/pub", &guest).await.unwrap();
        assert_eq!(seen[0].size, 0);
        let seen = tree.list("/pub", &admin()).await.unwrap();
        assert_eq!(seen[0].size, 1);
    }
}
