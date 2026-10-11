use std::{collections::HashSet, fmt::Display, time::Duration};

use futures_util::Stream;
use kolimi_chunk::Hash;
use kolimi_db::{Db, Node as DbNode};
use kolimi_store::{BlobStore, SweepStats};

use crate::{Access, Perm, error::VfsError, path};

/// Whether a node is a directory or a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// A collection.
    Dir,
    /// A regular file.
    File,
}

/// A resolved node with typed fields.
#[derive(Debug, Clone)]
pub struct Node {
    /// Primary key.
    pub id: i64,
    /// Parent directory id (`None` for the root).
    pub parent_id: Option<i64>,
    /// Name (empty for the root).
    pub name: String,
    /// Directory or file.
    pub kind: NodeKind,
    /// Content manifest identity for files.
    pub content_id: Option<Hash>,
    /// Content size in bytes.
    pub size: u64,
    /// Creation time in Unix milliseconds.
    pub created_at: i64,
    /// Last modification time in Unix milliseconds.
    pub modified_at: i64,
    /// Whether the node is in the trash.
    pub trashed: bool,
    /// Path at trash time.
    pub original_path: Option<String>,
}

impl Node {
    /// Whether this node is a collection.
    pub fn is_dir(&self) -> bool {
        self.kind == NodeKind::Dir
    }

    /// ETag for this node: content id for files, modification time for dirs.
    pub fn etag(&self) -> String {
        match self.content_id {
            Some(hash) => format!("\"{}\"", hash.to_hex()),
            None => format!("\"d{}\"", self.modified_at),
        }
    }

    pub(crate) fn from_db(node: DbNode) -> Result<Self, VfsError> {
        let kind = match node.kind.as_str() {
            "dir" => NodeKind::Dir,
            _ => NodeKind::File,
        };
        let content_id = match (&node.content_id, kind) {
            (Some(bytes), NodeKind::File) => {
                let arr: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| VfsError::Conflict("stored content id has wrong length".into()))?;
                Some(Hash::from_bytes(arr))
            }
            _ => None,
        };
        Ok(Self {
            id: node.id,
            parent_id: node.parent_id,
            name: node.name,
            kind,
            content_id,
            size: node.size.max(0) as u64,
            created_at: node.created_at,
            modified_at: node.modified_at,
            trashed: node.trashed_at.is_some(),
            original_path: node.original_path,
        })
    }
}

/// The virtual filesystem: a per-user tree over the database and blob store.
#[derive(Debug, Clone)]
pub struct Vfs {
    pub(crate) db: Db,
    pub(crate) store: BlobStore,
}

impl Vfs {
    /// Creates a filesystem over the given database and blob store.
    pub fn new(db: Db, store: BlobStore) -> Self {
        Self { db, store }
    }

    /// The underlying database handle.
    /// The underlying blob store (used by the background scrubber).
    pub fn store(&self) -> &BlobStore {
        &self.store
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Returns the root directory for a user.
    pub async fn root(&self, user_id: i64) -> Result<Node, VfsError> {
        Node::from_db(self.db.root_node(user_id).await?)
    }

    /// Resolves a raw path to a node. `/` and `""` resolve to the root.
    pub async fn resolve(&self, user_id: i64, raw: &str) -> Result<Node, VfsError> {
        let segments = path::parse(raw)?;
        let mut node = self.root(user_id).await?;
        for segment in &segments {
            let child = self.db.find_child(user_id, node.id, segment).await?;
            node = Node::from_db(child.ok_or(VfsError::NotFound)?)?;
        }
        Ok(node)
    }

    /// Like [`Vfs::resolve`], but returns `None` instead of `NotFound`.
    pub async fn stat(&self, user_id: i64, raw: &str) -> Result<Option<Node>, VfsError> {
        match self.resolve(user_id, raw).await {
            Ok(node) => Ok(Some(node)),
            Err(VfsError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Lists the dead (user-defined) properties of a path.
    pub async fn dead_props(
        &self,
        user_id: i64,
        raw: &str,
    ) -> Result<Vec<kolimi_db::DeadProp>, VfsError> {
        let node = self.resolve(user_id, raw).await?;
        Ok(self.db.dead_props(user_id, node.id).await?)
    }

    /// Applies PROPPATCH operations to a path in document order.
    pub async fn apply_proppatch(
        &self,
        user_id: i64,
        raw: &str,
        ops: &[kolimi_db::DeadPropOp],
    ) -> Result<(), VfsError> {
        let node = self.resolve(user_id, raw).await?;
        if !self.db.apply_dead_prop_ops(user_id, node.id, ops).await? {
            return Err(VfsError::NotFound);
        }
        Ok(())
    }

    /// Lists the children of a directory.
    pub async fn list(&self, user_id: i64, raw: &str) -> Result<Vec<Node>, VfsError> {
        let node = self.resolve(user_id, raw).await?;
        if !node.is_dir() {
            return Err(VfsError::ParentNotCollection);
        }
        let children = self.db.children(user_id, node.id).await?;
        children.into_iter().map(Node::from_db).collect()
    }

    /// Creates a directory.
    pub async fn mkdir(&self, user_id: i64, raw: &str) -> Result<Node, VfsError> {
        let (parent, name) = self.resolve_parent(user_id, raw).await?;
        self.mkdir_at(user_id, parent.id, &name).await
    }

    pub(crate) async fn mkdir_at(
        &self,
        user_id: i64,
        parent_id: i64,
        name: &str,
    ) -> Result<Node, VfsError> {
        if self
            .db
            .find_child(user_id, parent_id, name)
            .await?
            .is_some()
        {
            return Err(VfsError::AlreadyExists);
        }
        let now = kolimi_db::now_millis();
        let node = self
            .db
            .insert_node(user_id, Some(parent_id), name, "dir", None, 0, now)
            .await?;
        let path = self.change_path(user_id, parent_id, name).await?;
        self.db
            .record_change(user_id, &path, "upsert", None, 0, now, None)
            .await?;
        Node::from_db(node)
    }

    /// Stores a whole byte buffer as a file, creating or replacing it.
    pub async fn put_bytes(&self, user_id: i64, raw: &str, data: &[u8]) -> Result<Node, VfsError> {
        let (parent, name) = self.resolve_parent(user_id, raw).await?;
        let existing = self.db.find_child(user_id, parent.id, &name).await?;
        if existing.as_ref().is_some_and(|n| n.kind != "file") {
            return Err(VfsError::IsCollection);
        }
        let (quota, used) = self.quota_state(user_id).await?;
        if quota > 0 && used.saturating_add(data.len() as u64) > quota {
            return Err(quota_error(quota));
        }
        let manifest = self.store.ingest_bytes(user_id, data).await?;
        self.record_usage(user_id, data.len() as u64).await?;
        self.finalize_put_at(user_id, parent.id, &name, existing, &manifest)
            .await
    }

    /// The effective quota (bytes; `0` = unlimited) and current usage for a
    /// user's storage. The per-user override wins over the server default.
    pub(crate) async fn quota_state(&self, user_id: i64) -> Result<(u64, u64), VfsError> {
        match self.db.get_user(user_id).await? {
            Some(user) => {
                let quota = match user.quota_bytes {
                    Some(q) if q > 0 => q as u64,
                    Some(_) => 0,
                    None => self.store.default_quota(),
                };
                Ok((quota, user.used_bytes.max(0) as u64))
            }
            None => Ok((0, 0)),
        }
    }

    /// Caps a requested upload size to the user's remaining quota, returning
    /// `QuotaExceeded` when no room remains.
    pub(crate) async fn quota_cap(&self, user_id: i64, requested: u64) -> Result<u64, VfsError> {
        let (quota, used) = self.quota_state(user_id).await?;
        if quota == 0 {
            return Ok(requested);
        }
        let remaining = quota.saturating_sub(used);
        if remaining == 0 {
            return Err(quota_error(quota));
        }
        Ok(requested.min(remaining))
    }

    /// Adds newly-written bytes to a user's usage counter.
    pub(crate) async fn record_usage(&self, user_id: i64, new_bytes: u64) -> Result<(), VfsError> {
        if new_bytes > 0 {
            self.db.add_used_bytes(user_id, new_bytes as i64).await?;
        }
        Ok(())
    }

    /// Streams a body into a file, creating or replacing it.
    pub async fn put_stream<B, E>(
        &self,
        user_id: i64,
        raw: &str,
        stream: impl Stream<Item = Result<B, E>> + Unpin,
        max_bytes: u64,
    ) -> Result<Node, VfsError>
    where
        B: AsRef<[u8]>,
        E: Display,
    {
        let (parent, name) = self.resolve_parent(user_id, raw).await?;
        self.put_stream_at(user_id, parent.id, &name, stream, max_bytes)
            .await
    }

    pub(crate) async fn put_stream_at<B, E>(
        &self,
        user_id: i64,
        parent_id: i64,
        name: &str,
        stream: impl Stream<Item = Result<B, E>> + Unpin,
        max_bytes: u64,
    ) -> Result<Node, VfsError>
    where
        B: AsRef<[u8]>,
        E: Display,
    {
        let existing = self.db.find_child(user_id, parent_id, name).await?;
        if existing.as_ref().is_some_and(|n| n.kind != "file") {
            return Err(VfsError::IsCollection);
        }
        let max_bytes = self.quota_cap(user_id, max_bytes).await?;
        let (manifest, _size, new_bytes) =
            self.store.ingest_stream(user_id, stream, max_bytes).await?;
        self.record_usage(user_id, new_bytes).await?;
        self.finalize_put_at(user_id, parent_id, name, existing, &manifest)
            .await
    }

    pub(crate) async fn finalize_put_at(
        &self,
        user_id: i64,
        parent_id: i64,
        name: &str,
        existing: Option<DbNode>,
        manifest: &kolimi_chunk::Manifest,
    ) -> Result<Node, VfsError> {
        let now = kolimi_db::now_millis();
        let content_id = manifest.content_id();
        let (node, path) = match existing {
            Some(node) => {
                self.db
                    .update_file_versioned(
                        user_id,
                        &node,
                        content_id.as_bytes(),
                        manifest.size as i64,
                        now,
                    )
                    .await?;
                let updated = self
                    .db
                    .node_by_id(user_id, node.id)
                    .await?
                    .ok_or(VfsError::NotFound)?;
                let path = self
                    .db
                    .node_path(user_id, node.id)
                    .await?
                    .unwrap_or_else(|| format!("/{name}"));
                (updated, path)
            }
            None => {
                let node = self
                    .db
                    .insert_node(
                        user_id,
                        Some(parent_id),
                        name,
                        "file",
                        Some(content_id.as_bytes()),
                        manifest.size as i64,
                        now,
                    )
                    .await?;
                let path = self.change_path(user_id, parent_id, name).await?;
                (node, path)
            }
        };
        self.db
            .record_change(
                user_id,
                &path,
                "upsert",
                Some(content_id.as_bytes()),
                manifest.size as i64,
                now,
                None,
            )
            .await?;
        Node::from_db(node)
    }

    /// The change-feed path of `parent_id`/`name` in the owner's tree.
    pub(crate) async fn change_path(
        &self,
        user_id: i64,
        parent_id: i64,
        name: &str,
    ) -> Result<String, VfsError> {
        let parent = self
            .db
            .node_path(user_id, parent_id)
            .await?
            .unwrap_or_else(|| "/".to_string());
        Ok(if parent == "/" {
            format!("/{name}")
        } else {
            format!("{parent}/{name}")
        })
    }

    /// Reads a file's content.
    pub async fn read(&self, user_id: i64, raw: &str) -> Result<(Node, Vec<u8>), VfsError> {
        let node = self.resolve(user_id, raw).await?;
        let data = self.read_node_content(user_id, &node).await?;
        Ok((node, data))
    }

    /// Reads at most `max_bytes` from the head of a file.
    pub async fn read_head(
        &self,
        user_id: i64,
        raw: &str,
        max_bytes: usize,
    ) -> Result<(Node, Vec<u8>), VfsError> {
        let node = self.resolve(user_id, raw).await?;
        let data = self.read_node_head(user_id, &node, max_bytes).await?;
        Ok((node, data))
    }

    /// Reads at most `max_bytes` from the head of a file through the
    /// permission engine.
    pub async fn read_access_head(
        &self,
        caller_id: i64,
        raw: &str,
        max_bytes: usize,
    ) -> Result<(Access, Vec<u8>), VfsError> {
        let access = self.resolve_access(caller_id, raw).await?;
        access.perm.require(Perm::Read)?;
        let data = self
            .read_node_head(access.owner_id, &access.node, max_bytes)
            .await?;
        Ok((access, data))
    }

    pub(crate) async fn read_node_head(
        &self,
        owner_id: i64,
        node: &Node,
        max_bytes: usize,
    ) -> Result<Vec<u8>, VfsError> {
        if node.is_dir() {
            return Err(VfsError::IsCollection);
        }
        let content_id = node.content_id.ok_or(VfsError::NotFound)?;
        let manifest = self.store.get_manifest(owner_id, &content_id).await?;
        let mut out = Vec::new();
        for chunk in &manifest.chunks {
            if out.len() >= max_bytes {
                break;
            }
            let data = self.store.get_chunk(owner_id, &chunk.hash).await?;
            let take = data.len().min(max_bytes - out.len());
            out.extend_from_slice(&data[..take]);
        }
        Ok(out)
    }

    /// Returns the manifest of a file (for delta download).
    pub async fn manifest_of(
        &self,
        user_id: i64,
        raw: &str,
    ) -> Result<kolimi_chunk::Manifest, VfsError> {
        // Mount-aware: shared files live in the owner's store.
        let access = self.resolve_access(user_id, raw).await?;
        if access.node.is_dir() {
            return Err(VfsError::IsCollection);
        }
        let content_id = access.node.content_id.ok_or(VfsError::NotFound)?;
        Ok(self
            .store
            .get_manifest(access.owner_id, &content_id)
            .await?)
    }

    /// Returns a manifest by content id (for delta download).
    pub async fn manifest(
        &self,
        user_id: i64,
        content_id: &Hash,
    ) -> Result<kolimi_chunk::Manifest, VfsError> {
        Ok(self.store.get_manifest(user_id, content_id).await?)
    }

    /// Reads a chunk by hash (for delta download).
    pub async fn read_chunk(&self, user_id: i64, hash: &Hash) -> Result<Vec<u8>, VfsError> {
        Ok(self.store.get_chunk(user_id, hash).await?)
    }

    /// Stores a chunk uploaded via the sync API.
    pub async fn write_chunk(
        &self,
        user_id: i64,
        hash: &Hash,
        data: &[u8],
    ) -> Result<(), VfsError> {
        let (quota, used) = self.quota_state(user_id).await?;
        if quota > 0 && used.saturating_add(data.len() as u64) > quota {
            return Err(quota_error(quota));
        }
        if self.store.put_chunk(user_id, hash, data).await? {
            self.record_usage(user_id, data.len() as u64).await?;
        }
        Ok(())
    }

    /// Commits a client-built manifest as a file's new content.
    ///
    /// Every referenced chunk must already exist; the manifest itself is
    /// stored server-side. `expected` is the caller's view of the current
    /// content id (`None` = file must not exist), for conflict detection.
    pub async fn commit_manifest(
        &self,
        user_id: i64,
        raw: &str,
        manifest: &kolimi_chunk::Manifest,
        expected: Option<&str>,
    ) -> Result<Option<Node>, VfsError> {
        let current = self.stat(user_id, raw).await?;
        let current_id = current
            .as_ref()
            .and_then(|node| node.content_id)
            .map(|hash| hash.to_hex());
        if current_id.as_deref() != expected {
            return Ok(None);
        }
        for chunk in &manifest.chunks {
            if !self.store.has_chunk(user_id, &chunk.hash).await? {
                return Err(VfsError::MissingChunk(chunk.hash));
            }
        }
        // The manifest itself must be persisted server-side before the
        // node can reference it.
        self.store.put_manifest(user_id, manifest).await?;
        let (parent, name) = self.resolve_parent(user_id, raw).await?;
        let existing = match &current {
            Some(_) => self.db.find_child(user_id, parent.id, &name).await?,
            None => None,
        };
        let node = self
            .finalize_put_at(user_id, parent.id, &name, existing, manifest)
            .await?;
        Ok(Some(node))
    }

    /// Deletes a file or directory by moving it to the trash.
    pub async fn delete(&self, user_id: i64, raw: &str) -> Result<(), VfsError> {
        let node = self.resolve(user_id, raw).await?;
        if node.parent_id.is_none() {
            return Err(VfsError::Root);
        }
        self.trash_node_at(user_id, &node).await
    }

    pub(crate) async fn trash_node_at(&self, user_id: i64, node: &Node) -> Result<(), VfsError> {
        let now = kolimi_db::now_millis();
        let path = self
            .db
            .node_path(user_id, node.id)
            .await?
            .unwrap_or_else(|| format!("/{}", node.name));
        self.db.trash_node(user_id, node.id, &path, now).await?;
        self.db
            .record_change(user_id, &path, "delete", None, 0, now, None)
            .await?;
        Ok(())
    }

    /// Moves a node. Returns `true` if the target did not previously exist.
    pub async fn move_node(
        &self,
        user_id: i64,
        from: &str,
        to: &str,
        overwrite: bool,
    ) -> Result<bool, VfsError> {
        self.transfer(user_id, from, to, overwrite, false).await
    }

    /// Copies a node (recursively for directories). Returns `true` if the
    /// target did not previously exist.
    pub async fn copy_node(
        &self,
        user_id: i64,
        from: &str,
        to: &str,
        overwrite: bool,
    ) -> Result<bool, VfsError> {
        self.transfer(user_id, from, to, overwrite, true).await
    }

    async fn transfer(
        &self,
        user_id: i64,
        from: &str,
        to: &str,
        overwrite: bool,
        copy: bool,
    ) -> Result<bool, VfsError> {
        let src = self.resolve(user_id, from).await?;
        if src.parent_id.is_none() {
            return Err(VfsError::Root);
        }
        let (dst_parent, dst_name) = self.resolve_parent(user_id, to).await?;
        self.transfer_at(user_id, &src, dst_parent.id, &dst_name, overwrite, copy)
            .await
    }

    pub(crate) async fn transfer_at(
        &self,
        user_id: i64,
        src: &Node,
        dst_parent_id: i64,
        dst_name: &str,
        overwrite: bool,
        copy: bool,
    ) -> Result<bool, VfsError> {
        if src.is_dir() {
            let mut cursor = Some(dst_parent_id);
            while let Some(id) = cursor {
                if id == src.id {
                    return Err(VfsError::Conflict(
                        "cannot move or copy a collection into itself".into(),
                    ));
                }
                let parent = self.db.node_by_id(user_id, id).await?;
                cursor = parent.and_then(|node| node.parent_id);
            }
        }

        let existing = self.db.find_child(user_id, dst_parent_id, dst_name).await?;
        if let Some(existing) = &existing {
            if !overwrite {
                return Err(VfsError::AlreadyExists);
            }
            // Overwritten targets are recoverable: they go to the trash.
            let now = kolimi_db::now_millis();
            let existing_path = self
                .db
                .node_path(user_id, existing.id)
                .await?
                .unwrap_or_else(|| format!("/{dst_name}"));
            self.db
                .trash_node(user_id, existing.id, &existing_path, now)
                .await?;
        }

        let now = kolimi_db::now_millis();
        if copy {
            self.db
                .copy_subtree(user_id, &to_db(src), dst_parent_id, dst_name, now)
                .await?;
            let path = self.change_path(user_id, dst_parent_id, dst_name).await?;
            self.db
                .record_change(user_id, &path, "upsert", None, 0, now, None)
                .await?;
        } else {
            let from_path = self
                .db
                .node_path(user_id, src.id)
                .await?
                .unwrap_or_default();
            self.db
                .move_node(user_id, src.id, dst_parent_id, dst_name, now)
                .await?;
            let path = self.change_path(user_id, dst_parent_id, dst_name).await?;
            self.db
                .record_change(user_id, &path, "move", None, 0, now, Some(&from_path))
                .await?;
        }
        Ok(existing.is_none())
    }

    // ---- versions ------------------------------------------------------

    /// Lists a file's version history (newest first).
    pub async fn versions(
        &self,
        user_id: i64,
        raw: &str,
    ) -> Result<Vec<kolimi_db::VersionRow>, VfsError> {
        let node = self.resolve(user_id, raw).await?;
        if node.is_dir() {
            return Err(VfsError::IsCollection);
        }
        Ok(self.db.list_versions(user_id, node.id).await?)
    }

    /// Restores a version as the file's current content (pushing the
    /// current content into the history).
    pub async fn restore_version(
        &self,
        user_id: i64,
        raw: &str,
        version_id: i64,
    ) -> Result<Node, VfsError> {
        let node = self.resolve(user_id, raw).await?;
        if node.is_dir() {
            return Err(VfsError::IsCollection);
        }
        let version = self
            .db
            .version_by_id(user_id, version_id)
            .await?
            .filter(|version| version.node_id == node.id)
            .ok_or(VfsError::NotFound)?;
        let arr: [u8; 32] = version
            .content_id
            .as_slice()
            .try_into()
            .map_err(|_| VfsError::Conflict("stored content id has wrong length".into()))?;
        let content_id = Hash::from_bytes(arr);
        let manifest = self.store.get_manifest(user_id, &content_id).await?;
        let db_node = self
            .db
            .node_by_id(user_id, node.id)
            .await?
            .ok_or(VfsError::NotFound)?;
        let now = kolimi_db::now_millis();
        self.db
            .update_file_versioned(
                user_id,
                &db_node,
                content_id.as_bytes(),
                manifest.size as i64,
                now,
            )
            .await?;
        self.db
            .record_change(
                user_id,
                raw,
                "upsert",
                Some(content_id.as_bytes()),
                manifest.size as i64,
                now,
                None,
            )
            .await?;
        let node = self
            .db
            .node_by_id(user_id, node.id)
            .await?
            .ok_or(VfsError::NotFound)?;
        Node::from_db(node)
    }

    // ---- trash ---------------------------------------------------------

    /// Lists trashed nodes (recoverable deletions).
    pub async fn trash(&self, user_id: i64) -> Result<Vec<Node>, VfsError> {
        let rows = self.db.list_trash(user_id).await?;
        rows.into_iter().map(Node::from_db).collect()
    }

    /// Restores a trashed node to its original location (or the root when
    /// that location is gone), renaming on name conflicts.
    pub async fn restore_from_trash(&self, user_id: i64, node_id: i64) -> Result<Node, VfsError> {
        let node = self
            .db
            .node_by_id(user_id, node_id)
            .await?
            .filter(|node| node.trashed_at.is_some())
            .ok_or(VfsError::NotFound)?;

        let dest_parent = match node.parent_id {
            Some(parent_id) => match self.db.node_by_id(user_id, parent_id).await? {
                Some(parent) if parent.trashed_at.is_none() => parent,
                _ => self.db.root_node(user_id).await?,
            },
            None => self.db.root_node(user_id).await?,
        };

        let now = kolimi_db::now_millis();
        let name = if self
            .db
            .find_child(user_id, dest_parent.id, &node.name)
            .await?
            .is_some()
        {
            let mut candidate = String::new();
            let mut found = false;
            for attempt in 1..=100 {
                candidate = if attempt == 1 {
                    format!("{} (restored)", node.name)
                } else {
                    format!("{} (restored {attempt})", node.name)
                };
                if self
                    .db
                    .find_child(user_id, dest_parent.id, &candidate)
                    .await?
                    .is_none()
                {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(VfsError::Conflict("too many name conflicts".into()));
            }
            candidate
        } else {
            node.name.clone()
        };

        if node.parent_id != Some(dest_parent.id) || name != node.name {
            self.db
                .move_node(user_id, node_id, dest_parent.id, &name, now)
                .await?;
        }
        self.db.restore_node(user_id, node_id).await?;

        let restored = self
            .db
            .node_by_id(user_id, node_id)
            .await?
            .ok_or(VfsError::NotFound)?;
        let path = self
            .db
            .node_path(user_id, node_id)
            .await?
            .unwrap_or_default();
        self.db
            .record_change(user_id, &path, "upsert", None, 0, now, None)
            .await?;
        Node::from_db(restored)
    }

    /// Permanently deletes a trashed node.
    pub async fn purge_from_trash(&self, user_id: i64, node_id: i64) -> Result<(), VfsError> {
        let node = self
            .db
            .node_by_id(user_id, node_id)
            .await?
            .filter(|node| node.trashed_at.is_some())
            .ok_or(VfsError::NotFound)?;
        let now = kolimi_db::now_millis();
        self.db.delete_node(user_id, node_id).await?;
        self.db
            .record_change(
                user_id,
                node.original_path.as_deref().unwrap_or(&node.name),
                "delete",
                None,
                0,
                now,
                None,
            )
            .await?;
        Ok(())
    }

    // ---- maintenance ---------------------------------------------------

    /// Removes blobs no longer referenced by any node or version.
    /// Removes all blob data for a deleted user.
    ///
    /// Unlike garbage collection, this does not require the user to still
    /// exist, so it is what makes account deletion leave nothing behind.
    pub async fn remove_user_data(&self, user_id: i64) -> Result<(), VfsError> {
        Ok(self.store.remove_user(user_id).await?)
    }

    pub async fn collect_garbage(
        &self,
        user_id: i64,
        grace: Duration,
    ) -> Result<SweepStats, VfsError> {
        let content_ids = self.db.referenced_content_ids(user_id).await?;
        let mut keep_manifests: HashSet<Hash> = HashSet::new();
        let mut keep_chunks: HashSet<Hash> = HashSet::new();
        for bytes in content_ids {
            let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) else {
                continue;
            };
            let content_id = Hash::from_bytes(arr);
            keep_manifests.insert(content_id);
            if let Ok(manifest) = self.store.get_manifest(user_id, &content_id).await {
                for chunk in &manifest.chunks {
                    keep_chunks.insert(chunk.hash);
                }
            }
            // Corrupt or missing manifests keep their content id pinned but
            // expose no chunks; under-deletion is the safe failure mode.
        }
        let stats = self
            .store
            .sweep(user_id, &keep_manifests, &keep_chunks, grace)
            .await?;
        // Reclaimed bytes come off the usage counter (clamped at zero).
        if stats.bytes_freed > 0 {
            self.db
                .add_used_bytes(user_id, -(stats.bytes_freed as i64))
                .await?;
        }
        Ok(stats)
    }

    /// Verifies all manifests referenced by a user's files and versions.
    pub async fn verify_all(&self, user_id: i64) -> Result<(u64, u64), VfsError> {
        let content_ids = self.db.referenced_content_ids(user_id).await?;
        let mut checked = 0;
        let mut bytes = 0;
        for raw in content_ids {
            let Ok(arr) = <[u8; 32]>::try_from(raw.as_slice()) else {
                continue;
            };
            let content_id = Hash::from_bytes(arr);
            let stats = self.store.verify_manifest(user_id, &content_id).await?;
            checked += stats.chunks_checked;
            bytes += stats.bytes;
        }
        Ok((checked, bytes))
    }

    pub(crate) async fn resolve_parent(
        &self,
        user_id: i64,
        raw: &str,
    ) -> Result<(Node, String), VfsError> {
        let segments = path::parse(raw)?;
        let name = segments.last().cloned().ok_or_else(|| {
            VfsError::InvalidPath(crate::error::PathError::Segment(String::new()))
        })?;
        let mut parent = self.root(user_id).await?;
        let root_id = parent.id;
        for segment in &segments[..segments.len() - 1] {
            let child = self.db.find_child(user_id, parent.id, segment).await?;
            parent = Node::from_db(child.ok_or(VfsError::ParentNotCollection)?)?;
            if !parent.is_dir() {
                return Err(VfsError::ParentNotCollection);
            }
        }
        // The virtual shared root and the DAV namespace roots are reserved
        // at the top level of every user's tree.
        if parent.id == root_id && crate::authz::RESERVED_ROOT_NAMES.contains(&name.as_str()) {
            return Err(VfsError::Conflict("reserved name".to_string()));
        }
        Ok((parent, name))
    }
}

/// Builds the storage-quota error.
fn quota_error(limit: u64) -> VfsError {
    VfsError::Store(kolimi_store::StoreError::QuotaExceeded { limit })
}

pub(crate) fn to_db(node: &Node) -> DbNode {
    DbNode {
        id: node.id,
        user_id: 0,
        parent_id: node.parent_id,
        name: node.name.clone(),
        kind: match node.kind {
            NodeKind::Dir => "dir".to_string(),
            NodeKind::File => "file".to_string(),
        },
        content_id: node.content_id.map(|hash| hash.as_bytes().to_vec()),
        size: node.size as i64,
        created_at: node.created_at,
        modified_at: node.modified_at,
        trashed_at: None,
        original_path: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PathError;

    async fn setup() -> (tempfile::TempDir, Vfs, i64) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(&dir.path().join("test.db")).await.unwrap();
        let store = BlobStore::open(dir.path().join("blobs")).await.unwrap();
        let user = db.create_user("alice", "hash").await.unwrap();
        (dir, Vfs::new(db, store), user.id)
    }

    #[tokio::test]
    async fn mkdir_put_read_roundtrip() {
        let (_dir, vfs, user) = setup().await;
        vfs.mkdir(user, "/docs").await.unwrap();
        let node = vfs
            .put_bytes(user, "/docs/hello.txt", b"hello")
            .await
            .unwrap();
        assert_eq!(node.size, 5);
        assert_eq!(node.kind, NodeKind::File);

        let (node, data) = vfs.read(user, "/docs/hello.txt").await.unwrap();
        assert_eq!(data, b"hello");
        assert_eq!(node.etag(), node.etag());
        assert!(node.etag().starts_with('"'));
    }

    #[tokio::test]
    async fn per_user_quota_is_enforced_and_counted() {
        let (_dir, vfs, user) = setup().await;
        vfs.db().set_quota_bytes(user, Some(1024)).await.unwrap();

        vfs.put_bytes(user, "/small.txt", &vec![1u8; 800])
            .await
            .unwrap();
        let used = vfs.db().get_user(user).await.unwrap().unwrap().used_bytes;
        assert!(used >= 800, "usage counter tracks writes, got {used}");

        // The next write would exceed the quota.
        let result = vfs.put_bytes(user, "/big.txt", &vec![2u8; 800]).await;
        assert!(
            matches!(
                &result,
                Err(VfsError::Store(kolimi_store::StoreError::QuotaExceeded {
                    limit: 1024
                }))
            ),
            "{result:?}"
        );

        // Raising the quota lets it through.
        vfs.db().set_quota_bytes(user, Some(10_000)).await.unwrap();
        vfs.put_bytes(user, "/big.txt", &vec![2u8; 800])
            .await
            .unwrap();

        // `0` means unlimited.
        vfs.db().set_quota_bytes(user, Some(0)).await.unwrap();
        vfs.put_bytes(user, "/huge.txt", &vec![3u8; 5000])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn multi_chunk_roundtrip() {
        let (_dir, vfs, user) = setup().await;
        let mut state = 0x1234_5678_9abc_def0u64;
        let data: Vec<u8> = (0..6 * 1024 * 1024)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect();
        vfs.put_bytes(user, "/big.bin", &data).await.unwrap();
        let manifest = vfs.manifest_of(user, "/big.bin").await.unwrap();
        assert!(manifest.chunks.len() > 1);
        let (_, read) = vfs.read(user, "/big.bin").await.unwrap();
        assert_eq!(read, data);
    }

    #[tokio::test]
    async fn overwriting_pushes_versions() {
        let (_dir, vfs, user) = setup().await;
        vfs.put_bytes(user, "/a.txt", b"one").await.unwrap();
        vfs.put_bytes(user, "/a.txt", b"two").await.unwrap();
        vfs.put_bytes(user, "/a.txt", b"three").await.unwrap();

        let versions = vfs.versions(user, "/a.txt").await.unwrap();
        assert_eq!(versions.len(), 2);

        // Identical content does not create a version.
        vfs.put_bytes(user, "/a.txt", b"three").await.unwrap();
        assert_eq!(vfs.versions(user, "/a.txt").await.unwrap().len(), 2);

        // Restore the oldest version.
        let oldest = versions.last().unwrap().id;
        let restored = vfs.restore_version(user, "/a.txt", oldest).await.unwrap();
        assert_eq!(restored.size, 3);
        assert_eq!(vfs.read(user, "/a.txt").await.unwrap().1, b"one");
        assert_eq!(vfs.versions(user, "/a.txt").await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn version_retention_keeps_ten() {
        let (_dir, vfs, user) = setup().await;
        for i in 0..15 {
            vfs.put_bytes(user, "/a.txt", format!("v{i}").as_bytes())
                .await
                .unwrap();
        }
        assert_eq!(vfs.versions(user, "/a.txt").await.unwrap().len(), 10);
    }

    #[tokio::test]
    async fn delete_moves_to_trash_and_restores() {
        let (_dir, vfs, user) = setup().await;
        vfs.mkdir(user, "/docs").await.unwrap();
        vfs.put_bytes(user, "/docs/a.txt", b"content")
            .await
            .unwrap();

        vfs.delete(user, "/docs/a.txt").await.unwrap();
        assert!(vfs.stat(user, "/docs/a.txt").await.unwrap().is_none());
        assert_eq!(vfs.list(user, "/docs").await.unwrap().len(), 0);

        let trash = vfs.trash(user).await.unwrap();
        assert_eq!(trash.len(), 1);
        assert_eq!(trash[0].original_path.as_deref(), Some("/docs/a.txt"));

        let restored = vfs.restore_from_trash(user, trash[0].id).await.unwrap();
        assert_eq!(restored.name, "a.txt");
        assert_eq!(vfs.read(user, "/docs/a.txt").await.unwrap().1, b"content");
        assert!(vfs.trash(user).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn restore_renames_on_conflict() {
        let (_dir, vfs, user) = setup().await;
        vfs.put_bytes(user, "/a.txt", b"old").await.unwrap();
        vfs.delete(user, "/a.txt").await.unwrap();
        vfs.put_bytes(user, "/a.txt", b"new").await.unwrap();

        let trash = vfs.trash(user).await.unwrap();
        let restored = vfs.restore_from_trash(user, trash[0].id).await.unwrap();
        assert_eq!(restored.name, "a.txt (restored)");
        assert_eq!(vfs.read(user, "/a.txt").await.unwrap().1, b"new");
        assert_eq!(vfs.read(user, "/a.txt (restored)").await.unwrap().1, b"old");
    }

    #[tokio::test]
    async fn deleting_a_directory_trashes_the_subtree() {
        let (_dir, vfs, user) = setup().await;
        vfs.mkdir(user, "/docs").await.unwrap();
        vfs.put_bytes(user, "/docs/a.txt", b"a").await.unwrap();
        vfs.delete(user, "/docs").await.unwrap();

        assert!(vfs.stat(user, "/docs").await.unwrap().is_none());
        assert_eq!(vfs.trash(user).await.unwrap().len(), 1);

        let trash = vfs.trash(user).await.unwrap();
        vfs.restore_from_trash(user, trash[0].id).await.unwrap();
        assert_eq!(vfs.read(user, "/docs/a.txt").await.unwrap().1, b"a");
    }

    #[tokio::test]
    async fn purge_removes_trashed_nodes_permanently() {
        let (_dir, vfs, user) = setup().await;
        vfs.put_bytes(user, "/a.txt", b"gone").await.unwrap();
        vfs.delete(user, "/a.txt").await.unwrap();
        let trash = vfs.trash(user).await.unwrap();
        vfs.purge_from_trash(user, trash[0].id).await.unwrap();
        assert!(vfs.trash(user).await.unwrap().is_empty());
        assert!(matches!(
            vfs.purge_from_trash(user, trash[0].id).await,
            Err(VfsError::NotFound)
        ));
    }

    #[tokio::test]
    async fn overwrite_replaces_target_into_trash() {
        let (_dir, vfs, user) = setup().await;
        vfs.put_bytes(user, "/a.txt", b"old").await.unwrap();
        vfs.put_bytes(user, "/b.txt", b"new").await.unwrap();
        vfs.move_node(user, "/b.txt", "/a.txt", true).await.unwrap();
        assert_eq!(vfs.read(user, "/a.txt").await.unwrap().1, b"new");
        let trash = vfs.trash(user).await.unwrap();
        assert_eq!(trash.len(), 1);
        assert_eq!(trash[0].name, "a.txt");
    }

    #[tokio::test]
    async fn changes_feed_records_lifecycle() {
        let (_dir, vfs, user) = setup().await;
        vfs.mkdir(user, "/docs").await.unwrap();
        vfs.put_bytes(user, "/docs/a.txt", b"one").await.unwrap();
        vfs.move_node(user, "/docs/a.txt", "/docs/b.txt", false)
            .await
            .unwrap();
        vfs.delete(user, "/docs/b.txt").await.unwrap();

        let changes = vfs.db.changes_since(user, 0, 100).await.unwrap();
        let ops: Vec<&str> = changes.iter().map(|c| c.op.as_str()).collect();
        assert_eq!(ops, vec!["upsert", "upsert", "move", "delete"]);
        assert_eq!(changes[2].from_path.as_deref(), Some("/docs/a.txt"));
        assert_eq!(changes[2].path, "/docs/b.txt");

        let since = changes[1].seq;
        let later = vfs.db.changes_since(user, since, 100).await.unwrap();
        assert_eq!(later.len(), 2);
    }

    #[tokio::test]
    async fn commit_manifest_detects_conflicts_and_missing_chunks() {
        let (_dir, vfs, user) = setup().await;
        vfs.put_bytes(user, "/a.txt", b"one").await.unwrap();
        let node = vfs.resolve(user, "/a.txt").await.unwrap();
        let current = node.content_id.unwrap().to_hex();

        // Wrong expected content id: conflict.
        let manifest = vfs.manifest_of(user, "/a.txt").await.unwrap();
        assert!(
            vfs.commit_manifest(user, "/a.txt", &manifest, Some("bogus"))
                .await
                .unwrap()
                .is_none()
        );

        // Correct expected id: accepted (idempotent).
        assert!(
            vfs.commit_manifest(user, "/a.txt", &manifest, Some(&current))
                .await
                .unwrap()
                .is_some()
        );

        // Manifest with a chunk that was never uploaded: rejected.
        let missing = kolimi_chunk::Manifest {
            version: 1,
            size: 4,
            chunks: vec![kolimi_chunk::ChunkRef {
                hash: Hash::of(b"nope"),
                len: 4,
            }],
        };
        assert!(matches!(
            vfs.commit_manifest(user, "/a.txt", &missing, Some(&current))
                .await,
            Err(VfsError::MissingChunk(_))
        ));

        // Commit genuinely different content with all chunks present.
        let edited = b"one plus more";
        let stored = vfs.store.ingest_bytes(user, edited).await.unwrap();
        let node = vfs
            .commit_manifest(user, "/a.txt", &stored, Some(&current))
            .await
            .unwrap()
            .expect("commit with fresh chunks must succeed");
        assert_eq!(vfs.read(user, "/a.txt").await.unwrap().1, edited);
        assert_eq!(node.size, edited.len() as u64);
        assert_eq!(vfs.versions(user, "/a.txt").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn garbage_collection_reclaims_only_unreferenced() {
        let (_dir, vfs, user) = setup().await;
        let kept = vfs.put_bytes(user, "/keep.txt", b"keep").await.unwrap();
        let old_content = vfs.put_bytes(user, "/tmp.txt", b"old").await.unwrap();
        vfs.put_bytes(user, "/tmp.txt", b"new").await.unwrap();
        vfs.delete(user, "/tmp.txt").await.unwrap();

        // Old content is still referenced by the version history and trash.
        let stats = vfs.collect_garbage(user, Duration::ZERO).await.unwrap();
        assert_eq!(stats.chunks_deleted, 0);
        assert_eq!(stats.manifests_deleted, 0);
        assert!(
            vfs.store
                .has_manifest(user, &old_content.content_id.unwrap())
                .await
                .unwrap()
        );

        // Purging the trash and the version makes the old manifest garbage.
        let trash = vfs.trash(user).await.unwrap();
        vfs.purge_from_trash(user, trash[0].id).await.unwrap();
        let versions = vfs.versions(user, "/keep.txt").await.unwrap();
        assert!(versions.is_empty());
        assert!(
            vfs.store
                .has_manifest(user, &kept.content_id.unwrap())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn rejects_traversal_and_root_mutations() {
        let (_dir, vfs, user) = setup().await;
        assert!(matches!(
            vfs.put_bytes(user, "/../escape.txt", b"x").await,
            Err(VfsError::InvalidPath(PathError::Segment(_)))
        ));
        assert!(matches!(vfs.delete(user, "/").await, Err(VfsError::Root)));
        assert!(matches!(
            vfs.put_bytes(user, "/", b"x").await,
            Err(VfsError::InvalidPath(_))
        ));
    }

    #[tokio::test]
    async fn put_into_missing_parent_fails() {
        let (_dir, vfs, user) = setup().await;
        assert!(matches!(
            vfs.put_bytes(user, "/nope/file.txt", b"x").await,
            Err(VfsError::ParentNotCollection)
        ));
    }

    #[tokio::test]
    async fn put_over_directory_is_rejected() {
        let (_dir, vfs, user) = setup().await;
        vfs.mkdir(user, "/docs").await.unwrap();
        assert!(matches!(
            vfs.put_bytes(user, "/docs", b"x").await,
            Err(VfsError::IsCollection)
        ));
    }

    #[tokio::test]
    async fn mkdir_conflicts() {
        let (_dir, vfs, user) = setup().await;
        vfs.mkdir(user, "/docs").await.unwrap();
        assert!(matches!(
            vfs.mkdir(user, "/docs").await,
            Err(VfsError::AlreadyExists)
        ));
        assert!(matches!(
            vfs.mkdir(user, "/x/docs").await,
            Err(VfsError::ParentNotCollection)
        ));
    }

    #[tokio::test]
    async fn move_and_copy_with_overwrite_rules() {
        let (_dir, vfs, user) = setup().await;
        vfs.mkdir(user, "/docs").await.unwrap();
        vfs.put_bytes(user, "/docs/a.txt", b"a").await.unwrap();
        vfs.put_bytes(user, "/target.txt", b"t").await.unwrap();

        assert!(matches!(
            vfs.move_node(user, "/docs/a.txt", "/target.txt", false)
                .await,
            Err(VfsError::AlreadyExists)
        ));

        let created = vfs
            .move_node(user, "/docs/a.txt", "/target.txt", true)
            .await
            .unwrap();
        assert!(!created);
        assert_eq!(vfs.read(user, "/target.txt").await.unwrap().1, b"a");
        assert!(vfs.stat(user, "/docs/a.txt").await.unwrap().is_none());

        let created = vfs
            .copy_node(user, "/target.txt", "/docs/b.txt", false)
            .await
            .unwrap();
        assert!(created);
        assert_eq!(vfs.read(user, "/docs/b.txt").await.unwrap().1, b"a");
        assert!(vfs.stat(user, "/target.txt").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn cannot_move_directory_into_itself() {
        let (_dir, vfs, user) = setup().await;
        vfs.mkdir(user, "/a").await.unwrap();
        vfs.mkdir(user, "/a/b").await.unwrap();
        assert!(matches!(
            vfs.move_node(user, "/a", "/a/b/a", false).await,
            Err(VfsError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn copy_directory_is_recursive() {
        let (_dir, vfs, user) = setup().await;
        vfs.mkdir(user, "/src").await.unwrap();
        vfs.mkdir(user, "/src/nested").await.unwrap();
        vfs.put_bytes(user, "/src/nested/file.txt", b"deep")
            .await
            .unwrap();

        vfs.copy_node(user, "/src", "/dst", false).await.unwrap();
        assert_eq!(
            vfs.read(user, "/dst/nested/file.txt").await.unwrap().1,
            b"deep"
        );
        assert!(
            vfs.stat(user, "/src/nested/file.txt")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn delete_removes_subtree() {
        let (_dir, vfs, user) = setup().await;
        vfs.mkdir(user, "/a").await.unwrap();
        vfs.mkdir(user, "/a/b").await.unwrap();
        vfs.put_bytes(user, "/a/b/c.txt", b"c").await.unwrap();
        vfs.delete(user, "/a").await.unwrap();
        assert!(vfs.stat(user, "/a").await.unwrap().is_none());
        assert_eq!(vfs.list(user, "/").await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn streaming_upload_via_put_stream() {
        let (_dir, vfs, user) = setup().await;
        let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
            vec![Ok(b"stream".to_vec()), Ok(b"ed".to_vec())];
        let stream = futures_util::stream::iter(chunks);
        let node = vfs.put_stream(user, "/s.bin", stream, 1024).await.unwrap();
        assert_eq!(node.size, 8);
        assert_eq!(vfs.read(user, "/s.bin").await.unwrap().1, b"streamed");
    }

    #[tokio::test]
    async fn users_are_isolated() {
        let (dir, vfs, alice) = setup().await;
        let db = Db::connect(&dir.path().join("test.db")).await.unwrap();
        let bob = db.create_user("bob", "hash").await.unwrap();
        vfs.put_bytes(alice, "/secret.txt", b"alice only")
            .await
            .unwrap();
        assert!(vfs.stat(bob.id, "/secret.txt").await.unwrap().is_none());
        assert!(vfs.read(bob.id, "/secret.txt").await.is_err());
    }
}
