//! Hard resource limits. Every parser must honour these so that hostile or
//! corrupt input can never cause unbounded allocation or quadratic work.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Largest single blob (bundle or container) we will parse.
    pub max_blob_bytes: u64,
    /// Largest single microcode patch.
    pub max_patch_bytes: u32,
    /// Maximum number of patches in one blob.
    pub max_patches: u32,
    /// Maximum number of extended-signature / equivalence entries per patch.
    pub max_signatures_per_patch: u32,
    /// Maximum number of CPIO entries when reading an archive.
    pub max_archive_entries: u32,
    /// Maximum number of files ingested in one catalog build.
    pub max_catalog_files: u32,
    /// Maximum directory recursion depth during ingestion.
    pub max_directory_depth: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_blob_bytes: 256 * 1024 * 1024,
            max_patch_bytes: 8 * 1024 * 1024,
            max_patches: 65_536,
            max_signatures_per_patch: 4096,
            max_archive_entries: 65_536,
            max_catalog_files: 262_144,
            max_directory_depth: 32,
        }
    }
}

impl Limits {
    /// Very small limits, useful for fuzzing harnesses and tests.
    pub const fn tiny() -> Self {
        Self {
            max_blob_bytes: 1 << 20,
            max_patch_bytes: 1 << 18,
            max_patches: 256,
            max_signatures_per_patch: 64,
            max_archive_entries: 256,
            max_catalog_files: 256,
            max_directory_depth: 4,
        }
    }
}
