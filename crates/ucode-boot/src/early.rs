use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ucode_amd::{AmdContainerBuilder, EquivalenceEntry};
use ucode_archive::CpioBuilder;
use ucode_catalog::Catalog;
use ucode_core::{CpuIdentity, PatchMeta, Vendor};

use crate::{BootError, Result};

/// Inputs for building an early-load CPIO.
#[derive(Debug, Clone)]
pub struct EarlyBuildInput<'a> {
    pub catalog: &'a Catalog,
    /// When set, only emit patches that match these CPUs.
    pub filter_cpus: Option<&'a [CpuIdentity]>,
    /// Emit parent directory records in the CPIO.
    pub emit_parent_dirs: bool,
    /// Prefer highest revision only (default true).
    pub best_only: bool,
}

/// Result of an early CPIO build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarlyBuildResult {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub intel_patches: usize,
    pub amd_patches: usize,
    pub size: u64,
    pub paths: Vec<String>,
}

/// Build a deterministic early microcode CPIO from a catalog.
pub fn build_early_cpio(input: EarlyBuildInput<'_>) -> Result<EarlyBuildResult> {
    let mut intel_payloads: BTreeMap<(u32, u32, u32), (PatchMeta, Vec<u8>)> = BTreeMap::new();
    let mut amd_selected: Vec<(PatchMeta, Vec<u8>)> = Vec::new();

    for (meta, payload) in input.catalog.iter() {
        if !meta.is_loadable() {
            continue;
        }
        if payload.is_empty() {
            continue;
        }
        if let Some(cpus) = input.filter_cpus
            && !cpus.iter().any(|c| meta.applies_to(c))
        {
            // When platform is unknown, still allow signature-only match for
            // offline build with explicit filter that lacks platform masks.
            let sig_ok = cpus.iter().any(|c| {
                c.vendor == meta.vendor && meta.matches.iter().any(|m| m.signature == c.signature)
            });
            if !sig_ok {
                continue;
            }
        }

        match meta.vendor {
            Vendor::Intel => {
                let key = meta
                    .primary_match()
                    .map(|m| (m.signature.raw(), m.platform_mask.raw(), meta.revision))
                    .unwrap_or((0, 0, meta.revision));
                let identity_key = (key.0, key.1);
                if input.best_only {
                    // Keep only highest revision per (sig, pf).
                    let better = intel_payloads
                        .iter()
                        .filter(|((s, p, _), _)| (*s, *p) == identity_key)
                        .map(|((_, _, r), _)| *r)
                        .max()
                        .unwrap_or(0);
                    if meta.revision < better {
                        continue;
                    }
                    // Drop older same-identity entries.
                    intel_payloads
                        .retain(|(s, p, r), _| (*s, *p) != identity_key || *r == meta.revision);
                }
                intel_payloads.insert(key, (meta.clone(), payload.to_vec()));
            }
            Vendor::Amd => {
                if input.best_only
                    && let Some(m) = meta.primary_match()
                    && let Some(existing) = amd_selected
                        .iter()
                        .position(|(e, _)| e.matches.iter().any(|em| em.signature == m.signature))
                {
                    if amd_selected[existing].0.revision >= meta.revision {
                        continue;
                    }
                    amd_selected.remove(existing);
                }
                amd_selected.push((meta.clone(), payload.to_vec()));
            }
        }
    }

    // Intel: concatenate in deterministic order (already BTreeMap-sorted).
    let mut intel_blob = Vec::new();
    let mut intel_count = 0usize;
    for (_meta, payload) in intel_payloads.values() {
        intel_blob.extend_from_slice(payload);
        intel_count += 1;
    }

    // AMD: rebuild a proper DMA container with equivalence table.
    let mut amd_blob = Vec::new();
    let mut amd_count = 0usize;
    if !amd_selected.is_empty() {
        let mut builder = AmdContainerBuilder::new();
        let mut used_equiv: BTreeMap<u16, EquivalenceEntry> = BTreeMap::new();

        for (meta, payload) in &amd_selected {
            let equiv_id = meta
                .matches
                .iter()
                .find_map(|m| m.equivalence_id)
                .unwrap_or(0);
            for m in &meta.matches {
                let eid = m.equivalence_id.unwrap_or(equiv_id);
                if eid != 0 {
                    used_equiv.entry(eid).or_insert_with(|| {
                        // Prefer a full equivalence entry from the catalog.
                        input
                            .catalog
                            .amd_equivalence
                            .iter()
                            .find(|e| e.equiv_id == eid && e.installed_cpu == m.signature)
                            .copied()
                            .unwrap_or(EquivalenceEntry {
                                installed_cpu: m.signature,
                                fixed_errata_mask: 0,
                                fixed_errata_compare: 0,
                                equiv_id: eid,
                                reserved: 0,
                                offset: 0,
                            })
                    });
                    // Also pull every catalog entry for this equiv id.
                    for e in &input.catalog.amd_equivalence {
                        if e.equiv_id == eid {
                            used_equiv.insert(
                                // dedupe by packing - builder dedupes properly
                                e.equiv_id, *e,
                            );
                        }
                    }
                }
            }
            builder.add_patch(equiv_id, meta.revision, payload.clone());
            amd_count += 1;
        }

        for e in used_equiv.into_values() {
            builder.add_equivalence(e);
        }
        // Also add any mapping we synthesised per match.
        for (meta, _) in &amd_selected {
            for m in &meta.matches {
                if let Some(eid) = m.equivalence_id {
                    builder.add_equivalence_mapping(m.signature, eid);
                }
            }
        }

        amd_blob = builder
            .build()
            .map_err(|e| BootError::Malformed(e.to_string()))?;
    }

    let mut cpio = CpioBuilder::new().emit_parent_dirs(input.emit_parent_dirs);
    let mut paths = Vec::new();

    if !intel_blob.is_empty() {
        let path = Vendor::Intel.early_cpio_path().to_string();
        paths.push(path.clone());
        cpio.add_file(path, intel_blob)?;
    }
    if !amd_blob.is_empty() {
        let path = Vendor::Amd.early_cpio_path().to_string();
        paths.push(path.clone());
        cpio.add_file(path, amd_blob)?;
    }

    if cpio.is_empty() {
        return Err(BootError::Malformed(
            "no microcode patches selected for early CPIO".to_string(),
        ));
    }

    let bytes = cpio.build()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let sha256 = digest.iter().map(|b| format!("{b:02x}")).collect();

    Ok(EarlyBuildResult {
        size: bytes.len() as u64,
        bytes,
        sha256,
        intel_patches: intel_count,
        amd_patches: amd_count,
        paths,
    })
}
