//! Preview generation in a locked-down worker process.
//!
//! Previews are produced by re-executing the server binary as
//! `preview-worker`, which applies, in order:
//!
//! 1. **rlimits** — address space, CPU seconds, file size, open files
//! 2. **landlock** — filesystem access restricted to reading the single
//!    input file (plus `no_new_privs`)
//! 3. **seccomp** — a syscall allowlist; everything else (notably all
//!    networking) fails with `EPERM`
//!
//! The parent enforces a wall-clock timeout and `kill_on_drop`, so a
//! crashed, hung, or exploited worker can never take the server down.

pub mod sandbox;
pub mod worker;

pub use worker::{decode_thumbnail, text_head};

/// Errors from preview generation.
#[derive(Debug, thiserror::Error)]
pub enum PreviewError {
    /// Filesystem failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Image decoding or encoding failure.
    #[error("image error: {0}")]
    Image(#[from] image::ImageError),
    /// The payload is not a supported image.
    #[error("unsupported preview format")]
    Unsupported,
    /// The worker exited unsuccessfully.
    #[error("preview worker failed: {0}")]
    Worker(String),
}
