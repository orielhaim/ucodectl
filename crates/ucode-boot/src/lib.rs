#![forbid(unsafe_code)]

//! Boot-artifact inspection for early microcode.
//!
//! Responsibilities:
//!   * find the leading uncompressed newc CPIO on an initrd;
//!   * extract `kernel/x86/microcode/{GenuineIntel,AuthenticAMD}.bin`;
//!   * inspect UKI PE sections, especially `.ucode`;
//!   * never mutate a signed UKI.

pub mod early;
pub mod initrd;
pub mod uki;

pub use early::{EarlyBuildInput, EarlyBuildResult, build_early_cpio};
pub use initrd::{EmbeddedBlob, InitrdInspection, extract_embedded_microcode, inspect_initrd};
pub use uki::{UkiInspection, UkiSectionInfo, inspect_uki, looks_like_uki};

use std::path::PathBuf;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, BootError>;

#[derive(Debug, Error)]
pub enum BootError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("archive error: {0}")]
    Archive(#[from] ucode_archive::ArchiveError),

    #[error("catalog error: {0}")]
    Catalog(#[from] ucode_catalog::CatalogError),

    #[error("{0}")]
    Malformed(String),

    #[error("resource limit exceeded: {0}")]
    LimitExceeded(&'static str),

    #[error("PE/UKI parse error: {0}")]
    Pe(String),
}
