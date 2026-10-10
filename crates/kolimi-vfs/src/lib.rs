//! Path-safe virtual filesystem over the Kolimi database and blob store.
//!
//! Every path that enters the system goes through [`path::parse`], which
//! rejects `.`, `..`, control characters, and over-long segments. All
//! operations are scoped to a user id; there is no ambient authority.

pub mod error;
pub mod path;
mod vfs;

pub use error::{PathError, VfsError};
pub use vfs::{Node, NodeKind, Vfs};
