use sha2::{Digest, Sha256};
use ucode_core::limits::Limits;
use ucode_core::{
    CpuSignature, Finding, FindingCode, HeaderKind, PatchMeta, PatchOrigin, ProcessorMatch,
    RuntimeUpdatePolicy, UcodeDate, ValidationReport, Vendor,
};
use zerocopy::FromBytes;

use crate::header::{
    CONTAINER_HEADER_SIZE, EQUIV_ENTRY_SIZE, PATCH_HEADER_SIZE, RawEquivEntry, SECTION_HEADER_SIZE,
    SECTION_TYPE_EQUIV_TABLE, SECTION_TYPE_PATCH, UCODE_MAGIC_BYTES,
};
use crate::validate::validate_patch;
use crate::{AmdError, AmdPatchHeader, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EquivalenceEntry {
    pub installed_cpu: CpuSignature,
    pub fixed_errata_mask: u32,
    pub fixed_errata_compare: u32,
    pub equiv_id: u16,
    pub reserved: u16,
    /// Offset of this entry within the file.
    pub offset: u64,
}

impl EquivalenceEntry {
    pub fn raw_bytes(&self) -> [u8; EQUIV_ENTRY_SIZE] {
        use zerocopy::IntoBytes;
        use zerocopy::byteorder::little_endian::{U16, U32};
        let raw = RawEquivEntry {
            installed_cpu: U32::new(self.installed_cpu.0),
            fixed_errata_mask: U32::new(self.fixed_errata_mask),
            fixed_errata_compare: U32::new(self.fixed_errata_compare),
            equiv_cpu: U16::new(self.equiv_id),
            reserved: U16::new(self.reserved),
        };
        let mut out = [0u8; EQUIV_ENTRY_SIZE];
        out.copy_from_slice(raw.as_bytes());
        out
    }
}

#[derive(Debug, Clone, Default)]
pub struct EquivalenceTable {
    pub entries: Vec<EquivalenceEntry>,
}

impl EquivalenceTable {
    /// Kernel `find_equiv_id()`: exact match on the raw CPUID value.
    pub fn equiv_id_for(&self, sig: CpuSignature) -> Option<u16> {
        self.entries
            .iter()
            .find(|e| e.installed_cpu == sig && e.equiv_id != 0)
            .map(|e| e.equiv_id)
    }

    pub fn signatures_for(&self, equiv_id: u16) -> Vec<CpuSignature> {
        let mut out: Vec<CpuSignature> = self
            .entries
            .iter()
            .filter(|e| e.equiv_id == equiv_id)
            .map(|e| e.installed_cpu)
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

#[derive(Debug, Clone)]
pub struct AmdPatch {
    pub header: AmdPatchHeader,
    /// Offset of the patch *payload* (i.e. of the 64-byte patch header),
    /// excluding the 8-byte section header.
    pub offset: u64,
    /// Declared section size = header + payload.
    pub size: u32,
    /// CPU signatures resolved through the equivalence table.
    pub signatures: Vec<CpuSignature>,
    pub report: ValidationReport,
    pub sha256: [u8; 32],
}

impl AmdPatch {
    pub fn bytes<'b>(&self, blob: &'b [u8]) -> Option<&'b [u8]> {
        let start = usize::try_from(self.offset).ok()?;
        let end = start.checked_add(self.size as usize)?;
        blob.get(start..end)
    }

    pub fn to_meta(&self, source: &str) -> PatchMeta {
        let matches: Vec<ProcessorMatch> = if self.signatures.is_empty() {
            Vec::new()
        } else {
            self.signatures
                .iter()
                .map(|s| ProcessorMatch::amd(*s, self.header.processor_rev_id))
                .collect()
        };

        PatchMeta {
            vendor: Vendor::Amd,
            kind: HeaderKind::Microcode,
            revision: self.header.patch_id,
            date: UcodeDate::from_packed_bcd(self.header.date_raw),
            total_size: self.size,
            data_size: self.size.saturating_sub(PATCH_HEADER_SIZE as u32),
            matches,
            // AMD does not publish an in-container runtime-update gate.
            runtime_update: RuntimeUpdatePolicy::Unspecified,
            min_base_revision: None,
            origin: PatchOrigin {
                source: source.to_string(),
                offset: self.offset,
                length: self.size,
            },
            sha256: Some(self.sha256),
        }
    }
}

/// One `DMA\0` container. A file may hold several.
#[derive(Debug, Clone)]
pub struct AmdContainer {
    pub offset: u64,
    pub length: u64,
    pub equivalence: EquivalenceTable,
    pub patches: Vec<AmdPatch>,
    pub report: ValidationReport,
}

impl AmdContainer {
    pub fn looks_like_amd(bytes: &[u8]) -> bool {
        bytes.get(..4) == Some(&UCODE_MAGIC_BYTES[..])
    }

    /// Parse every container present in `bytes`.
    pub fn parse_all(bytes: &[u8], limits: &Limits) -> Result<Vec<AmdContainer>> {
        if bytes.len() as u64 > limits.max_blob_bytes {
            return Err(AmdError::LimitExceeded("blob larger than max_blob_bytes"));
        }
        if !Self::looks_like_amd(bytes) {
            return Err(AmdError::NotAmdFormat);
        }

        let mut containers = Vec::new();
        let mut cursor: usize = 0;
        let mut total_patches: u64 = 0;

        while cursor < bytes.len() {
            if bytes.get(cursor..cursor + 4) != Some(&UCODE_MAGIC_BYTES[..]) {
                // Trailing bytes that are not a new container.
                if let Some(last) = containers.last_mut() {
                    let c: &mut AmdContainer = last;
                    let tail = bytes.len() - cursor;
                    if !bytes
                        .get(cursor..)
                        .unwrap_or_default()
                        .iter()
                        .all(|b| *b == 0)
                    {
                        c.report.push(Finding::new(
                            FindingCode::TrailingGarbage,
                            cursor as u64,
                            format!("{tail} trailing bytes are not a new container"),
                        ));
                    }
                }
                break;
            }

            let (container, consumed) = Self::parse_one(bytes, cursor, limits)?;
            total_patches += container.patches.len() as u64;
            if total_patches > limits.max_patches as u64 {
                return Err(AmdError::LimitExceeded("too many patches"));
            }
            containers.push(container);
            if consumed == 0 {
                return Err(AmdError::Malformed {
                    offset: cursor as u64,
                    reason: "container consumed zero bytes".to_string(),
                });
            }
            cursor += consumed;
        }

        if containers.is_empty() {
            return Err(AmdError::NotAmdFormat);
        }
        Ok(containers)
    }

    fn parse_one(bytes: &[u8], start: usize, limits: &Limits) -> Result<(AmdContainer, usize)> {
        let mut report = ValidationReport::default();

        let head = bytes.get(start..).ok_or(AmdError::Truncated {
            offset: start as u64,
            need: CONTAINER_HEADER_SIZE,
            have: 0,
        })?;
        if head.len() < CONTAINER_HEADER_SIZE {
            return Err(AmdError::Truncated {
                offset: start as u64,
                need: CONTAINER_HEADER_SIZE,
                have: head.len(),
            });
        }

        let table_type = read_u32(head, 4)?;
        let table_len = read_u32(head, 8)?;

        if table_type != SECTION_TYPE_EQUIV_TABLE {
            return Err(AmdError::Malformed {
                offset: start as u64 + 4,
                reason: format!("first section type is 0x{table_type:08x}, expected 0"),
            });
        }

        let table_start = start + CONTAINER_HEADER_SIZE;
        let table_end =
            table_start
                .checked_add(table_len as usize)
                .ok_or_else(|| AmdError::Malformed {
                    offset: start as u64 + 8,
                    reason: "equivalence table length overflows".to_string(),
                })?;
        if table_end > bytes.len() {
            return Err(AmdError::Truncated {
                offset: table_start as u64,
                need: table_len as usize,
                have: bytes.len().saturating_sub(table_start),
            });
        }
        if table_len as usize % EQUIV_ENTRY_SIZE != 0 {
            report.push(Finding::new(
                FindingCode::BadTotalSize,
                start as u64 + 8,
                format!("equivalence table length {table_len} is not a multiple of 16"),
            ));
        }

        let equivalence = parse_equivalence_table(bytes, table_start, table_end, &mut report)?;

        // --- patch sections ---------------------------------------------
        let mut patches = Vec::new();
        let mut cursor = table_end;

        while cursor < bytes.len() {
            if bytes.get(cursor..cursor + 4) == Some(&UCODE_MAGIC_BYTES[..]) {
                break; // next container
            }
            if bytes.len() - cursor < SECTION_HEADER_SIZE {
                if !bytes
                    .get(cursor..)
                    .unwrap_or_default()
                    .iter()
                    .all(|b| *b == 0)
                {
                    report.push(Finding::new(
                        FindingCode::TrailingGarbage,
                        cursor as u64,
                        "incomplete section header at end of container",
                    ));
                }
                cursor = bytes.len();
                break;
            }

            let section = bytes.get(cursor..).unwrap_or_default();
            let sec_type = read_u32(section, 0)?;
            let sec_size = read_u32(section, 4)?;

            if sec_type != SECTION_TYPE_PATCH {
                report.push(Finding::new(
                    FindingCode::UnknownSectionType,
                    cursor as u64,
                    format!("unknown section type 0x{sec_type:08x}; stopping"),
                ));
                break;
            }
            if sec_size > limits.max_patch_bytes {
                return Err(AmdError::LimitExceeded("patch larger than max_patch_bytes"));
            }
            let payload_start = cursor + SECTION_HEADER_SIZE;
            let payload_end = payload_start
                .checked_add(sec_size as usize)
                .ok_or_else(|| AmdError::Malformed {
                    offset: cursor as u64 + 4,
                    reason: "patch size overflows".to_string(),
                })?;
            if payload_end > bytes.len() {
                return Err(AmdError::Truncated {
                    offset: payload_start as u64,
                    need: sec_size as usize,
                    have: bytes.len().saturating_sub(payload_start),
                });
            }
            if (sec_size as usize) < PATCH_HEADER_SIZE {
                return Err(AmdError::Malformed {
                    offset: cursor as u64 + 4,
                    reason: format!("patch size {sec_size} is smaller than the 64-byte header"),
                });
            }

            let payload = bytes.get(payload_start..payload_end).unwrap_or_default();
            let header = AmdPatchHeader::parse(payload)?;
            let signatures = equivalence.signatures_for(header.processor_rev_id);

            let mut patch_report =
                validate_patch(&header, sec_size, payload_start as u64, &signatures);
            patch_report.extend(ValidationReport::default());

            let mut hasher = Sha256::new();
            hasher.update(payload);
            let digest: [u8; 32] = hasher.finalize().into();

            patches.push(AmdPatch {
                header,
                offset: payload_start as u64,
                size: sec_size,
                signatures,
                report: patch_report,
                sha256: digest,
            });

            cursor = payload_end;
        }

        let container = AmdContainer {
            offset: start as u64,
            length: (cursor - start) as u64,
            equivalence,
            patches,
            report,
        };
        Ok((container, cursor - start))
    }
}

fn parse_equivalence_table(
    bytes: &[u8],
    start: usize,
    end: usize,
    report: &mut ValidationReport,
) -> Result<EquivalenceTable> {
    let mut entries: Vec<EquivalenceEntry> = Vec::new();
    let mut terminated = false;
    let mut off = start;

    while off + EQUIV_ENTRY_SIZE <= end {
        let slice = bytes.get(off..off + EQUIV_ENTRY_SIZE).unwrap_or_default();
        let (raw, _) = RawEquivEntry::read_from_prefix(slice).map_err(|_| AmdError::Truncated {
            offset: off as u64,
            need: EQUIV_ENTRY_SIZE,
            have: end - off,
        })?;

        if raw.installed_cpu.get() == 0 && raw.equiv_cpu.get() == 0 {
            terminated = true;
            off += EQUIV_ENTRY_SIZE;
            continue;
        }

        let entry = EquivalenceEntry {
            installed_cpu: CpuSignature(raw.installed_cpu.get()),
            fixed_errata_mask: raw.fixed_errata_mask.get(),
            fixed_errata_compare: raw.fixed_errata_compare.get(),
            equiv_id: raw.equiv_cpu.get(),
            reserved: raw.reserved.get(),
            offset: off as u64,
        };

        if let Some(prev) = entries
            .iter()
            .find(|e| e.installed_cpu == entry.installed_cpu && e.equiv_id == entry.equiv_id)
        {
            report.push(Finding::new(
                FindingCode::DuplicateEquivalenceEntry,
                off as u64,
                format!(
                    "CPUID {} maps to equiv id 0x{:04x} more than once (first at offset {})",
                    entry.installed_cpu, entry.equiv_id, prev.offset
                ),
            ));
        } else if let Some(conflict) = entries
            .iter()
            .find(|e| e.installed_cpu == entry.installed_cpu)
        {
            report.push(Finding::new(
                FindingCode::ConflictingEquivalenceEntry,
                off as u64,
                format!(
                    "CPUID {} maps to both equiv id 0x{:04x} and 0x{:04x}",
                    entry.installed_cpu, conflict.equiv_id, entry.equiv_id
                ),
            ));
        }

        entries.push(entry);
        off += EQUIV_ENTRY_SIZE;
    }

    if !terminated {
        report.push(Finding::new(
            FindingCode::EquivalenceTableUnterminated,
            start as u64,
            "equivalence table has no all-zero terminator entry; the Linux loader rejects this",
        ));
    }

    Ok(EquivalenceTable { entries })
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let slice = bytes.get(offset..offset + 4).ok_or(AmdError::Truncated {
        offset: offset as u64,
        need: 4,
        have: bytes.len().saturating_sub(offset),
    })?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(slice);
    Ok(u32::from_le_bytes(buf))
}
