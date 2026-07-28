#![forbid(unsafe_code)]

//! The only crate allowed to mutate the filesystem for microcode deployment.
//!
//! Every mutation is driven by a typed [`ucode_policy::Plan`]. The CLI must not
//! write files directly.

pub mod apply;
pub mod journal;
pub mod preflight;

pub use apply::{ApplyOptions, ApplyReport, ApplyResult, apply_plan};
pub use journal::{Journal, JournalEntry};
pub use preflight::{PreflightReport, preflight};

use std::path::PathBuf;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, TransactionError>;

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("preflight failed: {0}")]
    Preflight(String),

    #[error("refusing to write through symlink: {path}")]
    Symlink { path: PathBuf },

    #[error("path escapes confinement root: {path}")]
    PathEscape { path: PathBuf },

    #[error("boot build failed: {0}")]
    Boot(#[from] ucode_boot::BootError),

    #[error("policy error: {0}")]
    Policy(#[from] ucode_policy::PolicyError),

    #[error("{0}")]
    Other(String),
}
