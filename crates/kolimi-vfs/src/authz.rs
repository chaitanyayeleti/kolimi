//! The single permission engine (ROADMAP §3.2).
//!
//! Every surface that touches another user's data — WebDAV, the sync API,
//! public links, and the web UI — resolves paths through this module.
//! Divergent permission checks are Nextcloud's #1 bug class; there is
//! exactly one evaluation here.
//!
//! Received shares are exposed as **mounts**: a share on a node makes that
//! node (and its whole subtree) reachable at `/Shared with me/<name>`.
//! Inheritance is therefore by mount; per-node evaluation only considers
//! shares on the node itself, and the strongest matching share wins.

use kolimi_chunk::{Hash, Manifest};
use kolimi_db::ReceivedShare;

use crate::{Node, NodeKind, PathError, Vfs, VfsError, path};

/// Name of the virtual directory where received shares are mounted.
pub const SHARED_MOUNT: &str = "Shared with me";

/// Names reserved at the root of every user's own tree (virtual or
/// DAV-protocol namespaces).
pub const RESERVED_ROOT_NAMES: &[&str] = &[SHARED_MOUNT, "principals", "calendars", "addressbooks"];

/// A permission level. `Write` implies `Read`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Perm {
    /// Read-only access.
    Read,
    /// Read and modify access.
    Write,
}

impl Perm {
    /// Parses `"read"`/`"write"` (anything else is read).
    pub fn parse(value: &str) -> Self {
        if value == "write" {
            Self::Write
        } else {
            Self::Read
        }
    }

    /// The wire representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }

    /// Whether this permission satisfies `required`.
    pub fn allows(self, required: Self) -> bool {
        match (self, required) {
            (Self::Write, _) => true,
            (Self::Read, Self::Read) => true,
            (Self::Read, Self::Write) => false,
        }
    }

    /// Returns [`VfsError::Forbidden`] unless this permission satisfies
    /// `required`.
    pub fn require(self, required: Self) -> Result<(), VfsError> {
        if self.allows(required) {
            Ok(())
        } else {
            Err(VfsError::Forbidden)
        }
    }
}

/// A received share, ready to be mounted.
#[derive(Debug, Clone)]
pub struct Mount {
    /// Share primary key.
    pub share_id: i64,
    /// Owner of the underlying node.
    pub owner_id: i64,
    /// Owner's username.
    pub owner_username: String,
    /// Node id in the owner's tree.
    pub node_id: i64,
    /// Unique mount name (deduplicated with numeric suffixes).
    pub name: String,
    /// Directory or file.
    pub kind: NodeKind,
    /// Content id for files.
    pub content_id: Option<Hash>,
    /// Content size in bytes.
    pub size: u64,
    /// Node modification time in Unix milliseconds.
    pub modified_at: i64,
    /// Effective permission granted by the share.
    pub permission: Perm,
}

impl Mount {
    /// A synthetic node for listings and PROPFIND.
    pub fn to_node(&self) -> Node {
        Node {
            id: self.node_id,
            parent_id: None,
            name: self.name.clone(),
            kind: self.kind,
            content_id: self.content_id,
            size: self.size,
            created_at: 0,
            modified_at: self.modified_at,
            trashed: false,
            original_path: None,
        }
    }
}

/// A resolved path plus the caller's access to it.
#[derive(Debug, Clone)]
pub struct Access {
    /// Owner of the tree containing the node (blob-store namespace).
    pub owner_id: i64,
    /// Authenticated caller.
    pub caller_id: i64,
    /// Effective permission of the caller on the node.
    pub perm: Perm,
    /// Whether the node is the root of a received share (recipients may
    /// not rename or delete it).
    pub is_mount_root: bool,
    /// The resolved node.
    pub node: Node,
}

impl Vfs {
    /// Lists the caller's received shares as deduplicated mounts, ordered
    /// by share id. Multiple shares on the same node merge (strongest
    /// permission wins); identical names get ` (2)`, ` (3)`, … suffixes.
    pub async fn received_mounts(&self, caller_id: i64) -> Result<Vec<Mount>, VfsError> {
        let rows = self.db.received_shares(caller_id).await?;
        let mut mounts: Vec<Mount> = Vec::new();
        for row in rows {
            if let Some(existing) = mounts
                .iter_mut()
                .find(|m| m.owner_id == row.owner_id && m.node_id == row.node_id)
            {
                if row.permission == "write" {
                    existing.permission = Perm::Write;
                }
                continue;
            }
            mounts.push(mount_from_row(&row)?);
        }
        let mut used: Vec<String> = Vec::with_capacity(mounts.len());
        for mount in mounts.iter_mut() {
            let base = mount.name.clone();
            let mut name = base.clone();
            let mut suffix = 1;
            while used.contains(&name) {
                suffix += 1;
                name = format!("{base} ({suffix})");
            }
            used.push(name.clone());
            mount.name = name;
        }
        Ok(mounts)
    }

    /// Resolves a caller path, honouring `/Shared with me` mounts.
    ///
    /// Own-tree paths yield [`Perm::Write`] (owner authority); mount paths
    /// yield the share's permission. The virtual shared root itself is
    /// reported as [`VfsError::SharedRoot`].
    pub async fn resolve_access(&self, caller_id: i64, raw: &str) -> Result<Access, VfsError> {
        let segments = path::parse(raw)?;
        let Some(rest) = shared_suffix(&segments) else {
            let node = self.resolve(caller_id, raw).await?;
            return Ok(Access {
                owner_id: caller_id,
                caller_id,
                perm: Perm::Write,
                is_mount_root: false,
                node,
            });
        };
        if rest.is_empty() {
            return Err(VfsError::SharedRoot);
        }
        let mounts = self.received_mounts(caller_id).await?;
        let mount = mounts
            .iter()
            .find(|mount| mount.name == rest[0])
            .ok_or(VfsError::NotFound)?;
        let node = self.walk(mount.owner_id, mount.node_id, &rest[1..]).await?;
        Ok(Access {
            owner_id: mount.owner_id,
            caller_id,
            perm: mount.permission,
            is_mount_root: rest.len() == 1,
            node,
        })
    }

    /// Like [`Vfs::resolve_access`], but returns `None` instead of
    /// `NotFound`.
    pub async fn stat_access(&self, caller_id: i64, raw: &str) -> Result<Option<Access>, VfsError> {
        match self.resolve_access(caller_id, raw).await {
            Ok(access) => Ok(Some(access)),
            Err(VfsError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Resolves the parent directory of a caller path plus the final name.
    /// The parent must be writable for the caller.
    pub async fn resolve_parent_access(
        &self,
        caller_id: i64,
        raw: &str,
    ) -> Result<(Access, String), VfsError> {
        let segments = path::parse(raw)?;
        let name = segments
            .last()
            .cloned()
            .ok_or_else(|| VfsError::InvalidPath(PathError::Segment(String::new())))?;
        let Some(rest) = shared_suffix(&segments) else {
            let (parent, name) = self.resolve_parent(caller_id, raw).await?;
            return Ok((
                Access {
                    owner_id: caller_id,
                    caller_id,
                    perm: Perm::Write,
                    is_mount_root: false,
                    node: parent,
                },
                name,
            ));
        };
        if rest.is_empty() {
            return Err(VfsError::SharedRoot);
        }
        if rest.len() == 1 {
            // Creating directly inside the virtual root is not allowed.
            return Err(VfsError::SharedRoot);
        }
        let mounts = self.received_mounts(caller_id).await?;
        let mount = mounts
            .iter()
            .find(|mount| mount.name == rest[0])
            .ok_or(VfsError::NotFound)?;
        let parent = self
            .walk(mount.owner_id, mount.node_id, &rest[1..rest.len() - 1])
            .await?;
        if !parent.is_dir() {
            return Err(VfsError::ParentNotCollection);
        }
        Ok((
            Access {
                owner_id: mount.owner_id,
                caller_id,
                perm: mount.permission,
                is_mount_root: rest.len() - 1 == 1,
                node: parent,
            },
            name,
        ))
    }

    /// Reads a file through the permission engine.
    pub async fn read_access(
        &self,
        caller_id: i64,
        raw: &str,
    ) -> Result<(Access, Vec<u8>), VfsError> {
        let access = self.resolve_access(caller_id, raw).await?;
        access.perm.require(Perm::Read)?;
        if access.node.is_dir() {
            return Err(VfsError::IsCollection);
        }
        let content_id = access.node.content_id.ok_or(VfsError::NotFound)?;
        let manifest = self
            .store
            .get_manifest(access.owner_id, &content_id)
            .await?;
        let data = self.store.read_content(access.owner_id, &manifest).await?;
        Ok((access, data))
    }

    /// Resolves a file through the permission engine and returns its
    /// manifest, without loading the content into memory. Used by WebDAV to
    /// stream and range-serve large files.
    pub async fn read_manifest_access(
        &self,
        caller_id: i64,
        raw: &str,
    ) -> Result<(Access, Manifest), VfsError> {
        let access = self.resolve_access(caller_id, raw).await?;
        access.perm.require(Perm::Read)?;
        if access.node.is_dir() {
            return Err(VfsError::IsCollection);
        }
        let content_id = access.node.content_id.ok_or(VfsError::NotFound)?;
        let manifest = self
            .store
            .get_manifest(access.owner_id, &content_id)
            .await?;
        Ok((access, manifest))
    }

    /// Lists a directory through the permission engine.
    pub async fn list_access(
        &self,
        caller_id: i64,
        raw: &str,
    ) -> Result<(Access, Vec<Node>), VfsError> {
        let access = self.resolve_access(caller_id, raw).await?;
        access.perm.require(Perm::Read)?;
        if !access.node.is_dir() {
            return Err(VfsError::ParentNotCollection);
        }
        let children = self.db.children(access.owner_id, access.node.id).await?;
        let children = children
            .into_iter()
            .map(Node::from_db)
            .collect::<Result<_, _>>()?;
        Ok((access, children))
    }

    /// Reads dead properties through the permission engine.
    pub async fn dead_props_access(
        &self,
        caller_id: i64,
        raw: &str,
    ) -> Result<Vec<kolimi_db::DeadProp>, VfsError> {
        let access = self.resolve_access(caller_id, raw).await?;
        access.perm.require(Perm::Read)?;
        Ok(self.db.dead_props(access.owner_id, access.node.id).await?)
    }

    /// Applies PROPPATCH operations through the permission engine.
    pub async fn apply_proppatch_access(
        &self,
        caller_id: i64,
        raw: &str,
        ops: &[kolimi_db::DeadPropOp],
    ) -> Result<(), VfsError> {
        let access = self.resolve_access(caller_id, raw).await?;
        access.perm.require(Perm::Write)?;
        if !self
            .db
            .apply_dead_prop_ops(access.owner_id, access.node.id, ops)
            .await?
        {
            return Err(VfsError::NotFound);
        }
        Ok(())
    }

    /// Creates a directory through the permission engine.
    pub async fn mkdir_access(&self, caller_id: i64, raw: &str) -> Result<Node, VfsError> {
        let (parent, name) = self.resolve_parent_access(caller_id, raw).await?;
        parent.perm.require(Perm::Write)?;
        self.mkdir_at(parent.owner_id, parent.node.id, &name).await
    }

    /// Streams a body into a file through the permission engine.
    ///
    /// Writing into a shared folder requires write on the folder; writing
    /// over a received file share requires write on the file itself.
    pub async fn put_stream_access<B, E>(
        &self,
        caller_id: i64,
        raw: &str,
        stream: impl futures_util::Stream<Item = Result<B, E>> + Unpin,
        max_bytes: u64,
    ) -> Result<Node, VfsError>
    where
        B: AsRef<[u8]>,
        E: std::fmt::Display,
    {
        let existing = self.stat_access(caller_id, raw).await?;
        if let Some(access) = &existing
            && access.is_mount_root
        {
            access.perm.require(Perm::Write)?;
            if access.node.is_dir() {
                return Err(VfsError::IsCollection);
            }
            let parent_id = access.node.parent_id.ok_or(VfsError::Root)?;
            let max_bytes = self.quota_cap(access.owner_id, max_bytes).await?;
            let (manifest, _, new_bytes) = self
                .store
                .ingest_stream(access.owner_id, stream, max_bytes)
                .await?;
            self.record_usage(access.owner_id, new_bytes).await?;
            return self
                .finalize_put_at(
                    access.owner_id,
                    parent_id,
                    &access.node.name,
                    Some(crate::vfs::to_db(&access.node)),
                    &manifest,
                )
                .await;
        }
        let (parent, name) = self.resolve_parent_access(caller_id, raw).await?;
        parent.perm.require(Perm::Write)?;
        self.put_stream_at(parent.owner_id, parent.node.id, &name, stream, max_bytes)
            .await
    }

    /// Deletes through the permission engine. Recipients may not delete the
    /// mount root itself (only the owner can).
    pub async fn delete_access(&self, caller_id: i64, raw: &str) -> Result<(), VfsError> {
        let access = self.resolve_access(caller_id, raw).await?;
        access.perm.require(Perm::Write)?;
        if access.is_mount_root {
            return Err(VfsError::Forbidden);
        }
        if access.node.parent_id.is_none() {
            return Err(VfsError::Root);
        }
        self.trash_node_at(access.owner_id, &access.node).await
    }

    /// Moves or copies through the permission engine.
    ///
    /// Moving requires write on the source and on the destination parent;
    /// copying requires read on the source and write on the destination
    /// parent. Cross-owner transfers are rejected (M3).
    pub async fn transfer_access(
        &self,
        caller_id: i64,
        from: &str,
        to: &str,
        overwrite: bool,
        copy: bool,
    ) -> Result<bool, VfsError> {
        let src = self.resolve_access(caller_id, from).await?;
        src.perm.require(Perm::Read)?;
        if src.is_mount_root && !copy {
            return Err(VfsError::Forbidden);
        }
        if !copy {
            src.perm.require(Perm::Write)?;
        }
        let (dst_parent, dst_name) = self.resolve_parent_access(caller_id, to).await?;
        dst_parent.perm.require(Perm::Write)?;
        if src.owner_id != dst_parent.owner_id {
            return Err(VfsError::Conflict(
                "moving or copying between users is not supported".to_string(),
            ));
        }
        self.transfer_at(
            src.owner_id,
            &src.node,
            dst_parent.node.id,
            &dst_name,
            overwrite,
            copy,
        )
        .await
    }

    /// Resolves a path relative to a node (public links, UI helpers).
    ///
    /// The caller must have already established access to the node (for
    /// public links, via the token).
    pub async fn link_node(
        &self,
        owner_id: i64,
        node_id: i64,
        raw: &str,
    ) -> Result<Node, VfsError> {
        let segments = path::parse(raw)?;
        self.walk(owner_id, node_id, &segments).await
    }

    /// Lists a directory node in its owner's tree (public links).
    pub async fn list_node(&self, owner_id: i64, node: &Node) -> Result<Vec<Node>, VfsError> {
        if !node.is_dir() {
            return Err(VfsError::ParentNotCollection);
        }
        let children = self.db.children(owner_id, node.id).await?;
        children.into_iter().map(Node::from_db).collect()
    }

    /// Reads a file node's content from its owner's store (public links).
    pub async fn read_node_content(&self, owner_id: i64, node: &Node) -> Result<Vec<u8>, VfsError> {
        if node.is_dir() {
            return Err(VfsError::IsCollection);
        }
        let content_id = node.content_id.ok_or(VfsError::NotFound)?;
        let manifest = self.store.get_manifest(owner_id, &content_id).await?;
        Ok(self.store.read_content(owner_id, &manifest).await?)
    }

    /// Walks from a mount root down `segments` inside the owner's tree.
    pub(crate) async fn walk(
        &self,
        owner_id: i64,
        root_id: i64,
        segments: &[String],
    ) -> Result<Node, VfsError> {
        let root = self
            .db
            .node_by_id(owner_id, root_id)
            .await?
            .filter(|node| node.trashed_at.is_none())
            .ok_or(VfsError::NotFound)?;
        let mut node = Node::from_db(root)?;
        for segment in segments {
            if !node.is_dir() {
                return Err(VfsError::ParentNotCollection);
            }
            let child = self.db.find_child(owner_id, node.id, segment).await?;
            node = Node::from_db(child.ok_or(VfsError::NotFound)?)?;
        }
        Ok(node)
    }
}

fn shared_suffix(segments: &[String]) -> Option<&[String]> {
    if segments.first().map(String::as_str) == Some(SHARED_MOUNT) {
        Some(&segments[1..])
    } else {
        None
    }
}

fn mount_from_row(row: &ReceivedShare) -> Result<Mount, VfsError> {
    let kind = if row.kind == "dir" {
        NodeKind::Dir
    } else {
        NodeKind::File
    };
    let content_id = match (&row.content_id, kind) {
        (Some(bytes), NodeKind::File) => {
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| VfsError::Conflict("stored content id has wrong length".into()))?;
            Some(Hash::from_bytes(arr))
        }
        _ => None,
    };
    Ok(Mount {
        share_id: row.share_id,
        owner_id: row.owner_id,
        owner_username: row.owner_username.clone(),
        node_id: row.node_id,
        name: row.name.clone(),
        kind,
        content_id,
        size: row.size.max(0) as u64,
        modified_at: row.modified_at,
        permission: Perm::parse(&row.permission),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PathError, VfsError};
    use kolimi_db::Db;
    use kolimi_store::BlobStore;

    async fn setup() -> (tempfile::TempDir, Vfs, i64, i64) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(&dir.path().join("test.db")).await.unwrap();
        let store = BlobStore::open(dir.path().join("blobs")).await.unwrap();
        let alice = db.create_user("alice", "hash").await.unwrap();
        let bob = db.create_user("bob", "hash").await.unwrap();
        (dir, Vfs::new(db, store), alice.id, bob.id)
    }

    async fn share(
        vfs: &Vfs,
        owner: i64,
        node: i64,
        kind: &str,
        user: Option<i64>,
        group: Option<i64>,
        permission: &str,
    ) -> i64 {
        vfs.db
            .create_share(owner, node, kind, user, group, permission, None, None, None)
            .await
            .unwrap()
            .id
    }

    fn stream(
        data: &'static [u8],
    ) -> impl futures_util::Stream<Item = Result<Vec<u8>, std::io::Error>> + Unpin {
        futures_util::stream::iter(vec![Ok(data.to_vec())])
    }

    #[tokio::test]
    async fn read_share_mounts_and_denies_writes() {
        let (_dir, vfs, alice, bob) = setup().await;
        vfs.mkdir(alice, "/docs").await.unwrap();
        vfs.put_bytes(alice, "/docs/a.txt", b"hello").await.unwrap();
        let docs = vfs.resolve(alice, "/docs").await.unwrap();
        share(&vfs, alice, docs.id, "user", Some(bob), None, "read").await;

        let mounts = vfs.received_mounts(bob).await.unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].name, "docs");
        assert_eq!(mounts[0].owner_username, "alice");
        assert_eq!(mounts[0].permission, Perm::Read);
        assert_eq!(mounts[0].kind, NodeKind::Dir);

        let (access, data) = vfs
            .read_access(bob, "/Shared with me/docs/a.txt")
            .await
            .unwrap();
        assert_eq!(data, b"hello");
        assert_eq!(access.owner_id, alice);

        let (_, children) = vfs.list_access(bob, "/Shared with me/docs").await.unwrap();
        assert_eq!(children.len(), 1);

        assert!(matches!(
            vfs.mkdir_access(bob, "/Shared with me/docs/sub").await,
            Err(VfsError::Forbidden)
        ));
        assert!(matches!(
            vfs.put_stream_access(bob, "/Shared with me/docs/new.txt", stream(b"x"), 1024)
                .await,
            Err(VfsError::Forbidden)
        ));
        assert!(matches!(
            vfs.delete_access(bob, "/Shared with me/docs/a.txt").await,
            Err(VfsError::Forbidden)
        ));
        assert!(matches!(
            vfs.apply_proppatch_access(
                bob,
                "/Shared with me/docs",
                &[kolimi_db::DeadPropOp::Set {
                    namespace: "x".into(),
                    name: "y".into(),
                    value: "z".into()
                }]
            )
            .await,
            Err(VfsError::Forbidden)
        ));
    }

    #[tokio::test]
    async fn write_share_allows_mutations_and_records_owner_changes() {
        let (_dir, vfs, alice, bob) = setup().await;
        vfs.mkdir(alice, "/proj").await.unwrap();
        vfs.put_bytes(alice, "/proj/a.txt", b"one").await.unwrap();
        let proj = vfs.resolve(alice, "/proj").await.unwrap();
        share(&vfs, alice, proj.id, "user", Some(bob), None, "write").await;

        let before = vfs.db.latest_change_seq(alice).await.unwrap();
        vfs.mkdir_access(bob, "/Shared with me/proj/sub")
            .await
            .unwrap();
        vfs.put_stream_access(bob, "/Shared with me/proj/sub/b.txt", stream(b"two"), 1024)
            .await
            .unwrap();
        vfs.delete_access(bob, "/Shared with me/proj/a.txt")
            .await
            .unwrap();

        assert_eq!(vfs.read(alice, "/proj/sub/b.txt").await.unwrap().1, b"two");
        assert!(vfs.stat(alice, "/proj/a.txt").await.unwrap().is_none());

        let changes = vfs.db.changes_since(alice, before, 100).await.unwrap();
        let paths: Vec<&str> = changes.iter().map(|c| c.path.as_str()).collect();
        assert_eq!(paths, vec!["/proj/sub", "/proj/sub/b.txt", "/proj/a.txt"]);
        assert_eq!(changes[2].op, "delete");
        // Bob's own feed stays clean.
        assert!(vfs.db.changes_since(bob, 0, 100).await.unwrap().is_empty());

        // The mount root itself cannot be deleted or moved by the recipient.
        assert!(matches!(
            vfs.delete_access(bob, "/Shared with me/proj").await,
            Err(VfsError::Forbidden)
        ));
        assert!(matches!(
            vfs.transfer_access(bob, "/Shared with me/proj", "/renamed", true, false)
                .await,
            Err(VfsError::Forbidden)
        ));
    }

    #[tokio::test]
    async fn group_shares_follow_membership() {
        let (_dir, vfs, alice, bob) = setup().await;
        vfs.put_bytes(alice, "/secret.txt", b"group data")
            .await
            .unwrap();
        let node = vfs.resolve(alice, "/secret.txt").await.unwrap();
        let group = vfs.db.create_group("Team").await.unwrap();

        share(&vfs, alice, node.id, "group", None, Some(group.id), "read").await;
        assert!(vfs.received_mounts(bob).await.unwrap().is_empty());
        assert!(matches!(
            vfs.read_access(bob, "/Shared with me/secret.txt").await,
            Err(VfsError::NotFound)
        ));

        vfs.db.add_group_member(group.id, bob).await.unwrap();
        assert_eq!(vfs.received_mounts(bob).await.unwrap().len(), 1);
        assert_eq!(
            vfs.read_access(bob, "/Shared with me/secret.txt")
                .await
                .unwrap()
                .1,
            b"group data"
        );

        vfs.db.remove_group_member(group.id, bob).await.unwrap();
        assert!(vfs.received_mounts(bob).await.unwrap().is_empty());
        assert!(matches!(
            vfs.read_access(bob, "/Shared with me/secret.txt").await,
            Err(VfsError::NotFound)
        ));
    }

    #[tokio::test]
    async fn strongest_share_wins_and_duplicate_names_deduplicate() {
        let (_dir, vfs, alice, bob) = setup().await;
        vfs.mkdir(alice, "/d1").await.unwrap();
        vfs.mkdir(alice, "/d2").await.unwrap();
        vfs.put_bytes(alice, "/d1/x.txt", b"one").await.unwrap();
        vfs.put_bytes(alice, "/d2/x.txt", b"two").await.unwrap();
        let d1 = vfs.resolve(alice, "/d1/x.txt").await.unwrap();
        let d2 = vfs.resolve(alice, "/d2/x.txt").await.unwrap();
        share(&vfs, alice, d1.id, "user", Some(bob), None, "read").await;
        share(&vfs, alice, d2.id, "user", Some(bob), None, "read").await;
        // A stronger group share on d1 merges with the direct share.
        let group = vfs.db.create_group("Team").await.unwrap();
        vfs.db.add_group_member(group.id, bob).await.unwrap();
        share(&vfs, alice, d1.id, "group", None, Some(group.id), "write").await;

        let mounts = vfs.received_mounts(bob).await.unwrap();
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].name, "x.txt");
        assert_eq!(mounts[1].name, "x.txt (2)");
        assert_eq!(mounts[0].permission, Perm::Write);
        assert_eq!(mounts[1].permission, Perm::Read);
    }

    #[tokio::test]
    async fn revoking_a_share_removes_the_mount() {
        let (_dir, vfs, alice, bob) = setup().await;
        vfs.put_bytes(alice, "/f.txt", b"x").await.unwrap();
        let node = vfs.resolve(alice, "/f.txt").await.unwrap();
        let share_id = share(&vfs, alice, node.id, "user", Some(bob), None, "read").await;
        assert_eq!(vfs.received_mounts(bob).await.unwrap().len(), 1);

        vfs.db.delete_share(share_id).await.unwrap();
        assert!(vfs.received_mounts(bob).await.unwrap().is_empty());
        assert!(matches!(
            vfs.read_access(bob, "/Shared with me/f.txt").await,
            Err(VfsError::NotFound)
        ));
    }

    #[tokio::test]
    async fn trashing_the_shared_node_hides_the_mount() {
        let (_dir, vfs, alice, bob) = setup().await;
        vfs.put_bytes(alice, "/f.txt", b"x").await.unwrap();
        let node = vfs.resolve(alice, "/f.txt").await.unwrap();
        share(&vfs, alice, node.id, "user", Some(bob), None, "read").await;
        vfs.delete(alice, "/f.txt").await.unwrap();
        assert!(vfs.received_mounts(bob).await.unwrap().is_empty());
        assert!(matches!(
            vfs.read_access(bob, "/Shared with me/f.txt").await,
            Err(VfsError::NotFound)
        ));
    }

    #[tokio::test]
    async fn file_share_root_can_be_overwritten_with_write() {
        let (_dir, vfs, alice, bob) = setup().await;
        vfs.put_bytes(alice, "/note.txt", b"v1").await.unwrap();
        let node = vfs.resolve(alice, "/note.txt").await.unwrap();
        share(&vfs, alice, node.id, "user", Some(bob), None, "write").await;

        let updated = vfs
            .put_stream_access(bob, "/Shared with me/note.txt", stream(b"v2"), 1024)
            .await
            .unwrap();
        assert_eq!(updated.size, 2);
        assert_eq!(vfs.read(alice, "/note.txt").await.unwrap().1, b"v2");
        assert_eq!(vfs.versions(alice, "/note.txt").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn cross_owner_transfers_are_rejected() {
        let (_dir, vfs, alice, bob) = setup().await;
        vfs.mkdir(alice, "/proj").await.unwrap();
        vfs.put_bytes(alice, "/proj/f.txt", b"data").await.unwrap();
        let proj = vfs.resolve(alice, "/proj").await.unwrap();
        share(&vfs, alice, proj.id, "user", Some(bob), None, "write").await;

        assert!(matches!(
            vfs.transfer_access(bob, "/Shared with me/proj/f.txt", "/stolen.txt", true, true)
                .await,
            Err(VfsError::Conflict(_))
        ));
        assert!(matches!(
            vfs.transfer_access(bob, "/Shared with me/proj/f.txt", "/moved.txt", true, false)
                .await,
            Err(VfsError::Conflict(_))
        ));
        // Same-owner transfers inside the share are fine.
        vfs.transfer_access(
            bob,
            "/Shared with me/proj/f.txt",
            "/Shared with me/proj/g.txt",
            true,
            true,
        )
        .await
        .unwrap();
        assert_eq!(vfs.read(alice, "/proj/g.txt").await.unwrap().1, b"data");
    }

    #[tokio::test]
    async fn virtual_root_and_reserved_name_are_rejected() {
        let (_dir, vfs, _alice, bob) = setup().await;
        assert!(matches!(
            vfs.resolve_access(bob, "/Shared with me").await,
            Err(VfsError::SharedRoot)
        ));
        assert!(matches!(
            vfs.mkdir_access(bob, "/Shared with me/x").await,
            Err(VfsError::SharedRoot)
        ));
        assert!(matches!(
            vfs.mkdir_access(bob, "/Shared with me").await,
            Err(VfsError::SharedRoot)
        ));
        assert!(matches!(
            vfs.mkdir(bob, "/Shared with me").await,
            Err(VfsError::Conflict(_))
        ));
        // The reserved name is only special at the root of the own tree.
        vfs.mkdir(bob, "/sub").await.unwrap();
        vfs.mkdir(bob, "/sub/Shared with me").await.unwrap();
        assert!(
            vfs.stat(bob, "/sub/Shared with me")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn shared_dead_props_are_stored_on_the_owner_node() {
        let (_dir, vfs, alice, bob) = setup().await;
        vfs.mkdir(alice, "/proj").await.unwrap();
        let proj = vfs.resolve(alice, "/proj").await.unwrap();
        share(&vfs, alice, proj.id, "user", Some(bob), None, "write").await;

        vfs.apply_proppatch_access(
            bob,
            "/Shared with me/proj",
            &[kolimi_db::DeadPropOp::Set {
                namespace: "urn:x".into(),
                name: "color".into(),
                value: "blue".into(),
            }],
        )
        .await
        .unwrap();

        let props = vfs.dead_props(alice, "/proj").await.unwrap();
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].name, "color");
        assert_eq!(props[0].value, "blue");
        let via_bob = vfs
            .dead_props_access(bob, "/Shared with me/proj")
            .await
            .unwrap();
        assert_eq!(via_bob.len(), 1);
    }

    #[tokio::test]
    async fn inaccessible_paths_do_not_leak_existence() {
        let (_dir, vfs, alice, bob) = setup().await;
        vfs.put_bytes(alice, "/private.txt", b"x").await.unwrap();
        assert!(matches!(
            vfs.resolve_access(bob, "/Shared with me/private.txt").await,
            Err(VfsError::NotFound)
        ));
        assert!(matches!(
            vfs.read_access(bob, "/Shared with me/nope/deep.txt").await,
            Err(VfsError::NotFound)
        ));
        assert!(matches!(
            vfs.resolve_access(bob, "/private.txt").await,
            Err(VfsError::NotFound)
        ));
    }

    #[tokio::test]
    async fn parse_errors_are_reported_before_resolution() {
        let (_dir, vfs, _alice, bob) = setup().await;
        assert!(matches!(
            vfs.resolve_access(bob, "/Shared with me/../etc").await,
            Err(VfsError::InvalidPath(PathError::Segment(_)))
        ));
    }
}
