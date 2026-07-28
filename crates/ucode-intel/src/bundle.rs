use sha2::{Digest, Sha256};
use ucode_core::limits::Limits;
use ucode_core::{
    HeaderKind, PatchMeta, PatchOrigin, ProcessorMatch, RuntimeUpdatePolicy, UcodeDate,
    ValidationReport, Vendor,
};
use zerocopy::FromBytes;

use crate::header::{
    EXTENDED_SIGNATURE_SIZE, EXTENDED_TABLE_HEADER_SIZE, HEADER_SIZE, IntelExtendedSignature,
    IntelHeader, MIN_UPDATE_SIZE, RawExtendedSignature, RawExtendedTableHeader,
};
use crate::validate::{IntelValidationMode, validate_entry};
use crate::{IntelError, Result};

/// One parsed microcode update inside a bundle.
#[derive(Debug, Clone)]
pub struct IntelEntry {
    pub header: IntelHeader,
    pub extended_signatures: Vec<IntelExtendedSignature>,
    /// Offset of this entry within the bundle.
    pub offset: u64,
    /// Number of bytes this entry occupies.
    pub size: u32,
    pub report: ValidationReport,
    pub sha256: [u8; 32],
}

impl IntelEntry {
    /// The entry's bytes, borrowed from the original bundle buffer.
    pub fn bytes<'b>(&self, bundle: &'b [u8]) -> Option<&'b [u8]> {
        let start = usize::try_from(self.offset).ok()?;
        let end = start.checked_add(self.size as usize)?;
        bundle.get(start..end)
    }

    /// Every `(signature, platform)` pair this entry covers, primary first.
    pub fn processor_matches(&self) -> Vec<ProcessorMatch> {
        let mut out = Vec::with_capacity(1 + self.extended_signatures.len());
        out.push(ProcessorMatch::intel(
            self.header.signature,
            self.header.platform_mask,
            true,
        ));
        for ext in &self.extended_signatures {
            let dup = out
                .iter()
                .any(|m| m.signature == ext.signature && m.platform_mask == ext.platform_mask);
            if !dup {
                out.push(ProcessorMatch::intel(
                    ext.signature,
                    ext.platform_mask,
                    false,
                ));
            }
        }
        out
    }

    pub fn to_meta(&self, source: &str) -> PatchMeta {
        let kind = if self.header.is_microcode() {
            HeaderKind::Microcode
        } else if self.header.is_ifs_image() {
            HeaderKind::IntelIfsTestImage
        } else {
            HeaderKind::Unknown(self.header.header_type)
        };

        let runtime_update = if self.header.min_required_revision != 0 {
            RuntimeUpdatePolicy::RequiresBaseRevision(self.header.min_required_revision)
        } else {
            RuntimeUpdatePolicy::Unspecified
        };

        PatchMeta {
            vendor: Vendor::Intel,
            kind,
            revision: self.header.revision,
            date: UcodeDate::from_packed_bcd(self.header.date_raw),
            total_size: self.size,
            data_size: self.header.data_size(),
            matches: self.processor_matches(),
            runtime_update,
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

/// A parsed Intel microcode bundle: a plain concatenation of updates.
#[derive(Debug, Clone)]
pub struct IntelBundle {
    pub entries: Vec<IntelEntry>,
    /// Findings that concern the bundle as a whole rather than one entry.
    pub report: ValidationReport,
    pub total_bytes: u64,
}

impl IntelBundle {
    /// Parse a bundle from a byte slice.
    ///
    /// Intel bundles have no container header: they are simply updates laid
    /// end to end. We therefore validate each entry as we go and stop at the
    /// first thing that cannot be an update.
    pub fn parse(bytes: &[u8], mode: IntelValidationMode, limits: &Limits) -> Result<Self> {
        if bytes.len() as u64 > limits.max_blob_bytes {
            return Err(IntelError::LimitExceeded("blob larger than max_blob_bytes"));
        }

        let mut entries = Vec::new();
        let mut report = ValidationReport::default();
        let mut cursor: usize = 0;

        while cursor < bytes.len() {
            let remaining = bytes.len() - cursor;
            if remaining < HEADER_SIZE {
                if remaining > 0 && !is_all_zero(bytes.get(cursor..).unwrap_or_default()) {
                    report.push(ucode_core::Finding::new(
                        ucode_core::FindingCode::TrailingGarbage,
                        cursor as u64,
                        format!("{remaining} trailing bytes after the last microcode entry"),
                    ));
                }
                break;
            }

            let slice = bytes.get(cursor..).ok_or(IntelError::Truncated {
                offset: cursor,
                need: HEADER_SIZE,
                have: 0,
            })?;

            let header = IntelHeader::parse(slice)?;
            let total = header.total_size() as usize;

            if total < HEADER_SIZE || total > remaining || total > limits.max_patch_bytes as usize {
                // Not a plausible entry. In strict mode this is fatal; in
                // recovery mode we try to resynchronise.
                if mode == IntelValidationMode::Strict {
                    return Err(IntelError::Malformed {
                        offset: cursor as u64,
                        reason: format!(
                            "declared total size {total} does not fit in {remaining} remaining bytes"
                        ),
                    });
                }
                match scan_for_microcode(bytes, cursor + 4) {
                    Some(next) => {
                        report.push(ucode_core::Finding::new(
                            ucode_core::FindingCode::TrailingGarbage,
                            cursor as u64,
                            format!("skipped {} unparseable bytes", next - cursor),
                        ));
                        cursor = next;
                        continue;
                    }
                    None => {
                        report.push(ucode_core::Finding::new(
                            ucode_core::FindingCode::TrailingGarbage,
                            cursor as u64,
                            "no further microcode entries found".to_string(),
                        ));
                        break;
                    }
                }
            }

            let entry_bytes = bytes
                .get(cursor..cursor + total)
                .ok_or(IntelError::Truncated {
                    offset: cursor,
                    need: total,
                    have: remaining,
                })?;

            let extended = parse_extended_table(entry_bytes, &header, limits)?;
            let entry_report = validate_entry(entry_bytes, &header, &extended, mode, cursor as u64);

            if mode == IntelValidationMode::Strict && entry_report.has_errors() {
                let first = entry_report
                    .findings
                    .iter()
                    .find(|f| f.severity == ucode_core::Severity::Error)
                    .map(|f| f.message.clone())
                    .unwrap_or_else(|| "structural error".to_string());
                return Err(IntelError::Malformed {
                    offset: cursor as u64,
                    reason: first,
                });
            }

            let mut hasher = Sha256::new();
            hasher.update(entry_bytes);
            let digest: [u8; 32] = hasher.finalize().into();

            entries.push(IntelEntry {
                header,
                extended_signatures: extended,
                offset: cursor as u64,
                size: total as u32,
                report: entry_report,
                sha256: digest,
            });

            if entries.len() as u64 > limits.max_patches as u64 {
                return Err(IntelError::LimitExceeded("too many microcode entries"));
            }

            cursor += total;
        }

        if entries.is_empty() {
            return Err(IntelError::NotIntelFormat);
        }

        Ok(Self {
            entries,
            report,
            total_bytes: bytes.len() as u64,
        })
    }

    /// Quick, allocation-free sniff used by format auto-detection.
    pub fn looks_like_intel(bytes: &[u8]) -> bool {
        if bytes.len() < HEADER_SIZE {
            return false;
        }
        let Ok(header) = IntelHeader::parse(bytes) else {
            return false;
        };
        let total = header.total_size() as usize;
        let hdr_ok = header.header_type == crate::header::HEADER_TYPE_MICROCODE
            || header.header_type == crate::header::HEADER_TYPE_IFS;
        hdr_ok
            && header.loader_revision == crate::header::LOADER_REVISION
            && total >= MIN_UPDATE_SIZE
            && total <= bytes.len()
            && header.data_size() as usize + HEADER_SIZE <= total
    }
}

fn parse_extended_table(
    entry: &[u8],
    header: &IntelHeader,
    limits: &Limits,
) -> Result<Vec<IntelExtendedSignature>> {
    let Some(table_off) = header.extended_table_offset() else {
        return Ok(Vec::new());
    };
    let table_off = table_off as usize;
    let Some(table) = entry.get(table_off..) else {
        return Ok(Vec::new());
    };
    let Ok((raw_hdr, _)) = RawExtendedTableHeader::read_from_prefix(table) else {
        return Ok(Vec::new());
    };
    let count = raw_hdr.count.get();
    if count == 0 {
        return Ok(Vec::new());
    }
    if count > limits.max_signatures_per_patch {
        return Err(IntelError::LimitExceeded("extended signature count"));
    }
    let needed = EXTENDED_TABLE_HEADER_SIZE
        .checked_add(
            (count as usize)
                .checked_mul(EXTENDED_SIGNATURE_SIZE)
                .unwrap_or(usize::MAX),
        )
        .unwrap_or(usize::MAX);
    if table.len() < needed {
        // Declared count does not fit. Report via validation, return nothing.
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let start = EXTENDED_TABLE_HEADER_SIZE + i * EXTENDED_SIGNATURE_SIZE;
        let Some(slice) = table.get(start..start + EXTENDED_SIGNATURE_SIZE) else {
            break;
        };
        let Ok((raw, _)) = RawExtendedSignature::read_from_prefix(slice) else {
            break;
        };
        out.push(IntelExtendedSignature::from_raw(&raw));
    }
    Ok(out)
}

fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| *b == 0)
}

/// Resynchronisation helper mirroring `intel_ucode_scan_for_microcode()`.
///
/// Scans forward on 4-byte boundaries for something that plausibly starts a
/// microcode update. Returns the offset, or `None` if nothing was found.
pub fn scan_for_microcode(bytes: &[u8], from: usize) -> Option<usize> {
    let start = from.next_multiple_of(4);
    let mut off = start;
    while off + HEADER_SIZE <= bytes.len() {
        if let Some(window) = bytes.get(off..)
            && IntelBundle::looks_like_intel(window)
        {
            return Some(off);
        }
        off += 4;
    }
    None
}
