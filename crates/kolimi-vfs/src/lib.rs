//! Path-safe virtual filesystem over the Kolimi database and blob store.
//!
//! Every path that enters the system goes through [`path::parse`], which
//! rejects `.`, `..`, control characters, and over-long segments. All
//! operations are scoped to a user id; there is no ambient authority.

mod authz;
pub mod error;
pub mod path;
mod vfs;

pub use authz::{Access, Mount, Perm, SHARED_MOUNT};
pub use error::{PathError, VfsError};
pub use kolimi_db::{DeadProp, DeadPropOp};
pub use vfs::{Node, NodeKind, Vfs};
