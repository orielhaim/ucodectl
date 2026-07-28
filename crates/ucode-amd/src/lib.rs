#![forbid(unsafe_code)]

//! AMD microcode container support.
//!
//! Container layout (all little-endian):
//!
//! ```text
//! 0x00  magic  "DMA\0"  (0x00414d44)
//! 0x04  section type = 0 (equivalence table)
//! 0x08  section size
//! 0x0c  equivalence table: N × 16 bytes, zero-terminated
//!       { installed_cpu:u32, fixed_errata_mask:u32,
//!         fixed_errata_compare:u32, equiv_cpu:u16, res:u16 }
//! ...   repeated { type = 1 (patch), size, 64-byte patch header + payload }
//! ```
//!
//! A file may contain several concatenated containers (linux-firmware ships
//! per-family containers that distributions cat together).
//!
//! **Minimum base revision.** AMD publishes, for some patches, a minimum
//! currently-loaded revision required before the patch will be accepted. That
//! value is *not* present anywhere in the container; it is documented in
//! `linux-firmware/amd-ucode/README`. We therefore never synthesise it here —
//! see `ucode_catalog::sidecar` for ingestion of that metadata.

pub mod container;
pub mod header;
pub mod validate;
pub mod writer;

pub use container::{AmdContainer, AmdPatch, EquivalenceEntry, EquivalenceTable};
pub use header::{AmdPatchHeader, PATCH_HEADER_SIZE, UCODE_MAGIC};
pub use validate::max_patch_size_for_family;
pub use writer::{AmdContainerBuilder, write_container};

use thiserror::Error;

pub type Result<T> = core::result::Result<T, AmdError>;

#[derive(Debug, Error)]
pub enum AmdError {
    #[error("not an AMD microcode container (missing DMA\\0 magic)")]
    NotAmdFormat,

    #[error("input truncated at offset {offset}: need {need} bytes, have {have}")]
    Truncated {
        offset: u64,
        need: usize,
        have: usize,
    },

    #[error("malformed container at offset {offset}: {reason}")]
    Malformed { offset: u64, reason: String },

    #[error("resource limit exceeded: {0}")]
    LimitExceeded(&'static str),

    #[error(transparent)]
    Core(#[from] ucode_core::CoreError),
}
