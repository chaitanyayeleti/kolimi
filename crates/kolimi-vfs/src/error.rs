/// Errors returned by the virtual filesystem.
#[derive(Debug, thiserror::Error)]
pub enum VfsError {
    /// The path or one of its parents does not exist.
    #[error("not found")]
    NotFound,
    /// The parent path exists but is not a directory.
    #[error("parent is not a collection")]
    ParentNotCollection,
    /// The target already exists and overwrite was not requested.
    #[error("already exists")]
    AlreadyExists,
    /// An operation targeted a file but a collection was expected, or
    /// PUT targeted a collection.
    #[error("is a collection")]
    IsCollection,
    /// The path is syntactically unacceptable.
    #[error("invalid path: {0}")]
    InvalidPath(#[from] PathError),
    /// The operation would corrupt the tree (e.g. move into own subtree).
    #[error("conflict: {0}")]
    Conflict(String),
    /// The root collection cannot be modified.
    #[error("cannot modify the root collection")]
    Root,
    /// Database failure.
    #[error("database error: {0}")]
    Db(#[from] kolimi_db::DbError),
    /// Blob store failure.
    #[error("storage error: {0}")]
    Store(#[from] kolimi_store::StoreError),
}

/// Errors from path parsing.
#[derive(Debug, thiserror::Error)]
pub enum PathError {
    /// A segment was empty, `.`, `..`, a control character, too long,
    /// or contained a `/` after percent-decoding.
    #[error("invalid path segment {0:?}")]
    Segment(String),
    /// The path has more than 256 segments.
    #[error("path is too deep")]
    TooDeep,
}
