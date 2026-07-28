use std::collections::BTreeMap;

use ucode_core::CpuSignature;

use crate::header::{
    EQUIV_ENTRY_SIZE, SECTION_TYPE_EQUIV_TABLE, SECTION_TYPE_PATCH, UCODE_MAGIC_BYTES,
};
use crate::{AmdError, EquivalenceEntry, Result};

/// Builds a deterministic AMD container from selected patches.
///
/// Determinism rules:
///   * equivalence entries are emitted sorted by `(equiv_id, installed_cpu)`;
///   * patches are emitted sorted by `(equiv_id, patch_id)`;
///   * the table is always zero-terminated, as the kernel requires.
#[derive(Debug, Default)]
pub struct AmdContainerBuilder {
    equivalence: BTreeMap<(u16, u32), EquivalenceEntry>,
    patches: Vec<(u16, u32, Vec<u8>)>,
}

impl AmdContainerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_equivalence(&mut self, entry: EquivalenceEntry) -> &mut Self {
        self.equivalence
            .insert((entry.equiv_id, entry.installed_cpu.0), entry);
        self
    }

    pub fn add_equivalence_mapping(&mut self, sig: CpuSignature, equiv_id: u16) -> &mut Self {
        self.add_equivalence(EquivalenceEntry {
            installed_cpu: sig,
            fixed_errata_mask: 0,
            fixed_errata_compare: 0,
            equiv_id,
            reserved: 0,
            offset: 0,
        })
    }

    /// `payload` must be the 64-byte patch header followed by its data, i.e.
    /// exactly what sits after the section header in a container.
    pub fn add_patch(&mut self, equiv_id: u16, patch_id: u32, payload: Vec<u8>) -> &mut Self {
        self.patches.push((equiv_id, patch_id, payload));
        self
    }

    pub fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    pub fn build(mut self) -> Result<Vec<u8>> {
        if self.patches.is_empty() {
            return Err(AmdError::Malformed {
                offset: 0,
                reason: "refusing to build an empty AMD container".to_string(),
            });
        }
        self.patches
            .sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        self.patches
            .dedup_by(|a, b| a.0 == b.0 && a.1 == b.1 && a.2 == b.2);

        let entries: Vec<&EquivalenceEntry> = self.equivalence.values().collect();
        let table_size = (entries.len() + 1) * EQUIV_ENTRY_SIZE;

        let mut out = Vec::with_capacity(
            12 + table_size + self.patches.iter().map(|p| p.2.len() + 8).sum::<usize>(),
        );

        out.extend_from_slice(&UCODE_MAGIC_BYTES);
        out.extend_from_slice(&SECTION_TYPE_EQUIV_TABLE.to_le_bytes());
        out.extend_from_slice(&(table_size as u32).to_le_bytes());
        for e in entries {
            out.extend_from_slice(&e.raw_bytes());
        }
        out.extend_from_slice(&[0u8; EQUIV_ENTRY_SIZE]); // terminator

        for (_, _, payload) in &self.patches {
            out.extend_from_slice(&SECTION_TYPE_PATCH.to_le_bytes());
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(payload);
        }

        Ok(out)
    }
}

/// Convenience wrapper for the common "one blob out of these patches" case.
pub fn write_container(builder: AmdContainerBuilder) -> Result<Vec<u8>> {
    builder.build()
}
