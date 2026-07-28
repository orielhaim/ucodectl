#![forbid(unsafe_code)]

//! Turns files, directories and release trees into a normalised, deduplicated,
//! deterministically ordered catalog of microcode patches.

pub mod diff;
pub mod ingest;
pub mod manifest;
pub mod sidecar;

pub use diff::{CatalogDiff, DiffEntry, DiffKind, diff_catalogs};
pub use ingest::{
    DetectedFormat, IngestOptions, SourceBlob, detect_format, ingest_bytes, ingest_path,
};
pub use manifest::{Manifest, ManifestEntry};
pub use sidecar::AmdSidecar;

use std::collections::BTreeMap;
use std::path::PathBuf;

use thiserror::Error;
use ucode_amd::EquivalenceEntry;
use ucode_core::{
    CpuIdentity, CpuSignature, PatchMeta, SelectionOutcome, ValidationReport, Vendor,
};

pub type Result<T> = core::result::Result<T, CatalogError>;

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{path}: unrecognised microcode format")]
    UnknownFormat { path: PathBuf },

    #[error("{path}: {source}")]
    Intel {
        path: PathBuf,
        #[source]
        source: ucode_intel::IntelError,
    },

    #[error("{path}: {source}")]
    Amd {
        path: PathBuf,
        #[source]
        source: ucode_amd::AmdError,
    },

    #[error("resource limit exceeded: {0}")]
    LimitExceeded(&'static str),

    #[error("{path}: refusing to follow symlink")]
    Symlink { path: PathBuf },

    #[error("sidecar metadata error: {0}")]
    Sidecar(String),
}

/// A normalised collection of patches from one or more sources.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    /// Patches, deterministically ordered by
    /// `(vendor, signature, platform_mask, revision, source, offset)`.
    pub patches: Vec<PatchMeta>,
    /// Raw bytes for each patch, keyed by index into `patches`. Kept separate
    /// so that inspection-only workflows can drop them.
    pub payloads: Vec<Vec<u8>>,
    /// Findings that concern whole files rather than individual patches.
    pub report: ValidationReport,
    /// Every source blob that contributed, in ingestion order.
    pub sources: Vec<SourceBlob>,
    /// Sources that failed to parse, with the reason.
    pub failures: Vec<(PathBuf, String)>,
    /// AMD equivalence-table entries collected during ingestion, used when
    /// rebuilding AuthenticAMD.bin containers for early boot.
    pub amd_equivalence: Vec<EquivalenceEntry>,
}

impl Catalog {
    pub fn len(&self) -> usize {
        self.patches.len()
    }

    pub fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PatchMeta, &[u8])> {
        self.patches
            .iter()
            .zip(self.payloads.iter().map(|v| v.as_slice()))
    }

    pub fn vendors(&self) -> Vec<Vendor> {
        let mut v: Vec<Vendor> = self.patches.iter().map(|p| p.vendor).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Sort into the canonical order and drop byte-identical duplicates.
    pub fn normalise(&mut self) {
        let mut zipped: Vec<(PatchMeta, Vec<u8>)> = self
            .patches
            .drain(..)
            .zip(self.payloads.drain(..))
            .collect();

        zipped.sort_by(|a, b| {
            let (pa, pb) = (&a.0, &b.0);
            let ma = pa.primary_match();
            let mb = pb.primary_match();
            pa.vendor
                .cmp(&pb.vendor)
                .then_with(|| ma.map(|m| m.signature).cmp(&mb.map(|m| m.signature)))
                .then_with(|| {
                    ma.map(|m| m.platform_mask)
                        .cmp(&mb.map(|m| m.platform_mask))
                })
                .then_with(|| pa.revision.cmp(&pb.revision))
                .then_with(|| pa.origin.source.cmp(&pb.origin.source))
                .then_with(|| pa.origin.offset.cmp(&pb.origin.offset))
        });

        // Deduplicate on content hash + identity. Keeps the first occurrence,
        // which after sorting is the lexicographically smallest source.
        let mut seen: BTreeMap<([u8; 32], u32), usize> = BTreeMap::new();
        let mut patches = Vec::with_capacity(zipped.len());
        let mut payloads = Vec::with_capacity(zipped.len());

        for (meta, payload) in zipped {
            let key = (meta.sha256.unwrap_or([0u8; 32]), meta.revision);
            if meta.sha256.is_some()
                && let Some(_first) = seen.get(&key)
            {
                continue;
            }
            seen.insert(key, patches.len());
            patches.push(meta);
            payloads.push(payload);
        }

        self.patches = patches;
        self.payloads = payloads;
    }

    /// All patches applicable to a given CPU, best first.
    pub fn select(&self, cpu: &CpuIdentity) -> SelectionOutcome<'_> {
        ucode_core::select_for_cpu(self.patches.iter(), cpu)
    }

    /// Index of a patch by identity, for payload retrieval.
    pub fn payload_for(&self, meta: &PatchMeta) -> Option<&[u8]> {
        let idx = self.patches.iter().position(|p| {
            p.origin == meta.origin && p.revision == meta.revision && p.vendor == meta.vendor
        })?;
        self.payloads.get(idx).map(|v| v.as_slice())
    }

    /// Group patches by target signature. Useful for `list` output.
    pub fn by_signature(&self) -> BTreeMap<(Vendor, CpuSignature), Vec<&PatchMeta>> {
        let mut map: BTreeMap<(Vendor, CpuSignature), Vec<&PatchMeta>> = BTreeMap::new();
        for p in &self.patches {
            for m in &p.matches {
                map.entry((p.vendor, m.signature)).or_default().push(p);
            }
        }
        map
    }

    /// Apply out-of-band AMD minimum-base-revision metadata.
    pub fn apply_sidecar(&mut self, sidecar: &sidecar::AmdSidecar) -> usize {
        let mut applied = 0;
        for p in &mut self.patches {
            if p.vendor == Vendor::Amd
                && let Some(min) = sidecar.min_base_revision(p.revision)
            {
                p.min_base_revision = Some(min);
                applied += 1;
            }
        }
        applied
    }
}
