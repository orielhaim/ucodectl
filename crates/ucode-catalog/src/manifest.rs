use serde::{Deserialize, Serialize};
use ucode_core::{PatchMeta, Vendor};

use crate::Catalog;

/// Machine-readable description of a produced artifact or an ingested set.
/// This is part of the stable JSON contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub manifest_version: u32,
    pub generator: String,
    pub entries: Vec<ManifestEntry>,
    pub totals: ManifestTotals,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestTotals {
    pub patch_count: usize,
    pub byte_count: u64,
    pub vendors: Vec<Vendor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub vendor: Vendor,
    pub signature: String,
    pub platform_mask: String,
    pub revision: String,
    pub date: Option<String>,
    pub size: u32,
    pub sha256: Option<String>,
    pub source: String,
    pub offset: u64,
    /// Extra signatures beyond the primary one.
    pub additional_signatures: Vec<String>,
    pub min_base_revision: Option<String>,
    pub min_runtime_revision: Option<String>,
}

pub fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

impl ManifestEntry {
    pub fn from_meta(meta: &PatchMeta) -> Self {
        let primary = meta.primary_match();
        let additional: Vec<String> = meta
            .matches
            .iter()
            .filter(|m| !m.primary)
            .map(|m| format!("{}:{}", m.signature, m.platform_mask))
            .collect();

        let min_runtime = match meta.runtime_update {
            ucode_core::RuntimeUpdatePolicy::RequiresBaseRevision(v) => Some(format!("0x{v:08x}")),
            ucode_core::RuntimeUpdatePolicy::Unspecified => None,
        };

        Self {
            vendor: meta.vendor,
            signature: primary.map(|m| m.signature.to_string()).unwrap_or_default(),
            platform_mask: primary
                .map(|m| m.platform_mask.to_string())
                .unwrap_or_default(),
            revision: format!("0x{:08x}", meta.revision),
            date: meta.date.map(|d| d.to_string()),
            size: meta.total_size,
            sha256: meta.sha256.as_ref().map(hex32),
            source: meta.origin.source.clone(),
            offset: meta.origin.offset,
            additional_signatures: additional,
            min_base_revision: meta.min_base_revision.map(|v| format!("0x{v:08x}")),
            min_runtime_revision: min_runtime,
        }
    }
}

impl Manifest {
    pub fn from_catalog(catalog: &Catalog, generator: &str) -> Self {
        let entries: Vec<ManifestEntry> = catalog
            .patches
            .iter()
            .map(ManifestEntry::from_meta)
            .collect();
        let byte_count = catalog.patches.iter().map(|p| p.total_size as u64).sum();
        Self {
            manifest_version: 1,
            generator: generator.to_string(),
            totals: ManifestTotals {
                patch_count: entries.len(),
                byte_count,
                vendors: catalog.vendors(),
            },
            entries,
        }
    }
}
