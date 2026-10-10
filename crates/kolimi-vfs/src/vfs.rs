use std::fmt::Display;

use futures_util::Stream;
use kolimi_chunk::Hash;
use kolimi_db::{Db, Node as DbNode};
use kolimi_store::BlobStore;

use crate::{error::VfsError, path};

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
    /// Content hash for files.
    pub content_id: Option<Hash>,
    /// Content size in bytes.
    pub size: u64,
    /// Creation time in Unix milliseconds.
    pub created_at: i64,
    /// Last modification time in Unix milliseconds.
    pub modified_at: i64,
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

    fn from_db(node: DbNode) -> Result<Self, VfsError> {
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
        })
    }
}

/// The virtual filesystem: a per-user tree over the database and blob store.
#[derive(Debug, Clone)]
pub struct Vfs {
    db: Db,
    store: BlobStore,
}

impl Vfs {
    /// Creates a filesystem over the given database and blob store.
    pub fn new(db: Db, store: BlobStore) -> Self {
        Self { db, store }
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

    /// Like [`Vfs::resolve`], but returns `None` instead of `NotFound`.
    pub async fn stat(&self, user_id: i64, raw: &str) -> Result<Option<Node>, VfsError> {
        match self.resolve(user_id, raw).await {
            Ok(node) => Ok(Some(node)),
            Err(VfsError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
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
        if self
            .db
            .find_child(user_id, parent.id, &name)
            .await?
            .is_some()
        {
            return Err(VfsError::AlreadyExists);
        }
        let node = self
            .db
            .insert_node(
                user_id,
                Some(parent.id),
                &name,
                "dir",
                None,
                0,
                kolimi_db::now_millis(),
            )
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
        let hash = self.store.put_bytes(user_id, data).await?;
        self.upsert(user_id, parent.id, &name, existing, hash, data.len() as u64)
            .await
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
        let existing = self.db.find_child(user_id, parent.id, &name).await?;
        if existing.as_ref().is_some_and(|n| n.kind != "file") {
            return Err(VfsError::IsCollection);
        }
        let (hash, size) = self.store.put_stream(user_id, stream, max_bytes).await?;
        self.upsert(user_id, parent.id, &name, existing, hash, size)
            .await
    }

    /// Reads a file's content.
    pub async fn read(&self, user_id: i64, raw: &str) -> Result<(Node, Vec<u8>), VfsError> {
        let node = self.resolve(user_id, raw).await?;
        if node.is_dir() {
            return Err(VfsError::IsCollection);
        }
        let hash = node.content_id.ok_or(VfsError::NotFound)?;
        let data = self.store.get(user_id, &hash).await?;
        Ok((node, data))
    }

    /// Deletes a file or directory (recursively for directories).
    pub async fn delete(&self, user_id: i64, raw: &str) -> Result<(), VfsError> {
        let node = self.resolve(user_id, raw).await?;
        if node.parent_id.is_none() {
            return Err(VfsError::Root);
        }
        self.db.delete_node(user_id, node.id).await?;
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

        if src.is_dir() {
            let mut cursor = Some(dst_parent.id);
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

        let existing = self
            .db
            .find_child(user_id, dst_parent.id, &dst_name)
            .await?;
        if let Some(existing) = &existing {
            if !overwrite {
                return Err(VfsError::AlreadyExists);
            }
            self.db.delete_node(user_id, existing.id).await?;
        }

        let now = kolimi_db::now_millis();
        if copy {
            self.db
                .copy_subtree(user_id, &to_db(&src), dst_parent.id, &dst_name, now)
                .await?;
        } else {
            self.db
                .move_node(user_id, src.id, dst_parent.id, &dst_name, now)
                .await?;
        }
        Ok(existing.is_none())
    }

    async fn upsert(
        &self,
        user_id: i64,
        parent_id: i64,
        name: &str,
        existing: Option<DbNode>,
        hash: Hash,
        size: u64,
    ) -> Result<Node, VfsError> {
        let now = kolimi_db::now_millis();
        let node = match existing {
            Some(node) => {
                self.db
                    .update_file(user_id, node.id, hash.as_bytes(), size as i64, now)
                    .await?;
                self.db
                    .node_by_id(user_id, node.id)
                    .await?
                    .ok_or(VfsError::NotFound)?
            }
            None => {
                self.db
                    .insert_node(
                        user_id,
                        Some(parent_id),
                        name,
                        "file",
                        Some(hash.as_bytes()),
                        size as i64,
                        now,
                    )
                    .await?
            }
        };
        Node::from_db(node)
    }

    async fn resolve_parent(&self, user_id: i64, raw: &str) -> Result<(Node, String), VfsError> {
        let segments = path::parse(raw)?;
        let name = segments.last().cloned().ok_or_else(|| {
            VfsError::InvalidPath(crate::error::PathError::Segment(String::new()))
        })?;
        let mut parent = self.root(user_id).await?;
        for segment in &segments[..segments.len() - 1] {
            let child = self.db.find_child(user_id, parent.id, segment).await?;
            parent = Node::from_db(child.ok_or(VfsError::ParentNotCollection)?)?;
            if !parent.is_dir() {
                return Err(VfsError::ParentNotCollection);
            }
        }
        Ok((parent, name))
    }
}

fn to_db(node: &Node) -> DbNode {
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
    async fn overwriting_changes_content_id() {
        let (_dir, vfs, user) = setup().await;
        let first = vfs.put_bytes(user, "/a.txt", b"one").await.unwrap();
        let second = vfs.put_bytes(user, "/a.txt", b"two").await.unwrap();
        assert_ne!(first.etag(), second.etag());
        assert_eq!(vfs.read(user, "/a.txt").await.unwrap().1, b"two");
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
