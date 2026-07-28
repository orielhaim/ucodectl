use ucode_core::{Finding, FindingCode, Severity, UcodeDate, ValidationReport};

use crate::header::{
    EXTENDED_SIGNATURE_SIZE, EXTENDED_TABLE_HEADER_SIZE, HEADER_SIZE, HEADER_TYPE_IFS,
    HEADER_TYPE_MICROCODE, IntelExtendedSignature, IntelHeader, LOADER_REVISION, MIN_UPDATE_SIZE,
    dword_sum,
};

/// Strictness of the Intel parser.
///
/// These are deliberately two distinct modes rather than a boolean knob buried
/// in a config struct: recovery mode changes what the parser is *allowed to
/// believe*, and that must be visible at every call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntelValidationMode {
    /// Reject anything that deviates from the documented format. This is the
    /// only mode permitted when producing a boot artifact.
    Strict,
    /// Report deviations as findings and keep going. For forensics and for
    /// inspecting damaged dumps. Never use the output for loading.
    Recovery,
}

impl IntelValidationMode {
    pub fn is_strict(self) -> bool {
        matches!(self, IntelValidationMode::Strict)
    }
}

/// Full structural + semantic validation of a single microcode entry.
///
/// `entry` must be exactly `header.total_size()` bytes long; `base` is the
/// entry's offset within the enclosing blob and is used to make every finding
/// point at an absolute position.
pub fn validate_entry(
    entry: &[u8],
    header: &IntelHeader,
    extended: &[IntelExtendedSignature],
    mode: IntelValidationMode,
    base: u64,
) -> ValidationReport {
    let mut r = ValidationReport::default();

    // --- header type ------------------------------------------------------
    match header.header_type {
        HEADER_TYPE_MICROCODE => {}
        HEADER_TYPE_IFS => r.push(Finding::new(
            FindingCode::IfsTestImage,
            base,
            "header type 2: In-Field Scan test image, not loadable microcode",
        )),
        other => r.push(Finding::new(
            FindingCode::UnsupportedHeaderVersion,
            base,
            format!("unsupported header type {other}"),
        )),
    }

    if header.loader_revision != LOADER_REVISION {
        r.push(Finding::new(
            FindingCode::UnsupportedLoaderVersion,
            base + 0x14,
            format!("loader revision {} is not 1", header.loader_revision),
        ));
    }

    // --- sizes ------------------------------------------------------------
    let total = header.total_size() as usize;
    let data = header.data_size() as usize;

    if total < MIN_UPDATE_SIZE {
        r.push(Finding::new(
            FindingCode::BadTotalSize,
            base + 0x20,
            format!("total size {total} is below the {MIN_UPDATE_SIZE}-byte minimum"),
        ));
    }
    if total % 1024 != 0 {
        r.push(
            Finding::new(
                FindingCode::TotalSizeNotAligned,
                base + 0x20,
                format!("total size {total} is not a multiple of 1024"),
            )
            .escalate(if mode.is_strict() {
                Severity::Warning
            } else {
                Severity::Info
            }),
        );
    }
    if data % 4 != 0 {
        r.push(Finding::new(
            FindingCode::BadDataSize,
            base + 0x1c,
            format!("data size {data} is not a multiple of 4"),
        ));
    }
    match HEADER_SIZE.checked_add(data) {
        Some(end) if end <= total => {}
        _ => r.push(Finding::new(
            FindingCode::BadDataSize,
            base + 0x1c,
            format!("header ({HEADER_SIZE}) + data ({data}) exceeds total size ({total})"),
        )),
    }
    if entry.len() != total {
        r.push(Finding::new(
            FindingCode::Truncated,
            base,
            format!(
                "entry slice is {} bytes but header declares {total}",
                entry.len()
            ),
        ));
        return r; // everything below needs a correctly sized slice
    }
    if header.metadata_size as usize > data {
        r.push(Finding::new(
            FindingCode::UnknownMetadataSection,
            base + 0x24,
            format!(
                "metadata size {} exceeds data size {data}",
                header.metadata_size
            ),
        ));
    }
    if header.reserved != 0 {
        r.push(Finding::new(
            FindingCode::ReservedFieldNonZero,
            base + 0x2c,
            format!("reserved dword is 0x{:08x}", header.reserved),
        ));
    }

    // --- primary checksum -------------------------------------------------
    // Covers header + data only; the extended table is checksummed separately.
    let primary_end = HEADER_SIZE.saturating_add(data).min(entry.len());
    let primary_sum = dword_sum(entry.get(..primary_end).unwrap_or_default());
    if primary_sum != 0 {
        r.push(Finding::new(
            FindingCode::BadChecksum,
            base + 0x10,
            format!("header+data dword sum is 0x{primary_sum:08x}, expected 0"),
        ));
    }

    // --- extended signature table ----------------------------------------
    if let Some(table_off) = header.extended_table_offset() {
        let table_off = table_off as usize;
        let avail = entry.len().saturating_sub(table_off);
        let declared_count = extended.len();
        let table_len = EXTENDED_TABLE_HEADER_SIZE + declared_count * EXTENDED_SIGNATURE_SIZE;

        if avail < EXTENDED_TABLE_HEADER_SIZE {
            r.push(Finding::new(
                FindingCode::BadExtendedTable,
                base + table_off as u64,
                "extended signature table header does not fit inside the entry",
            ));
        } else if table_len > avail {
            r.push(Finding::new(
                FindingCode::BadExtendedTable,
                base + table_off as u64,
                format!("extended table needs {table_len} bytes but only {avail} are available"),
            ));
        } else {
            let table = entry
                .get(table_off..table_off + table_len)
                .unwrap_or_default();
            let table_sum = dword_sum(table);
            if table_sum != 0 {
                r.push(Finding::new(
                    FindingCode::BadExtendedTableChecksum,
                    base + table_off as u64 + 4,
                    format!("extended table dword sum is 0x{table_sum:08x}, expected 0"),
                ));
            }

            // Per Intel: replacing (sig, pf, cksum) in the primary header with
            // the extended triple must keep the total sum at zero. Since the
            // primary sum is already zero, the triples must sum equally.
            let primary_triple = header
                .signature
                .0
                .wrapping_add(header.platform_mask.0)
                .wrapping_add(header.checksum);
            for (i, ext) in extended.iter().enumerate() {
                let off = base
                    + table_off as u64
                    + EXTENDED_TABLE_HEADER_SIZE as u64
                    + (i * EXTENDED_SIGNATURE_SIZE) as u64;
                let triple = ext
                    .signature
                    .0
                    .wrapping_add(ext.platform_mask.0)
                    .wrapping_add(ext.checksum);
                // Account for a possibly non-zero primary sum in recovery mode.
                if triple.wrapping_add(primary_sum) != primary_triple {
                    r.push(
                        Finding::new(
                            FindingCode::BadExtendedSignatureChecksum,
                            off,
                            format!(
                                "extended signature {i} (sig {}, pf {}) has checksum 0x{:08x}, \
                                 which does not balance the update",
                                ext.signature, ext.platform_mask, ext.checksum
                            ),
                        )
                        .with_length(EXTENDED_SIGNATURE_SIZE as u32),
                    );
                }
            }

            // Duplicate detection across the primary and extended signatures.
            let mut seen: Vec<(u32, u32)> = vec![(header.signature.0, header.platform_mask.0)];
            for (i, ext) in extended.iter().enumerate() {
                let key = (ext.signature.0, ext.platform_mask.0);
                if seen.contains(&key) {
                    r.push(Finding::new(
                        FindingCode::DuplicateSignature,
                        base + table_off as u64
                            + EXTENDED_TABLE_HEADER_SIZE as u64
                            + (i * EXTENDED_SIGNATURE_SIZE) as u64,
                        format!(
                            "signature {} / platform mask {} appears more than once",
                            ext.signature, ext.platform_mask
                        ),
                    ));
                } else {
                    seen.push(key);
                }
            }
        }
    }

    // --- semantic ---------------------------------------------------------
    match UcodeDate::from_packed_bcd(header.date_raw) {
        None => r.push(Finding::new(
            FindingCode::NonBcdDate,
            base + 0x08,
            format!(
                "date field 0x{:08x} is not valid packed BCD",
                header.date_raw
            ),
        )),
        Some(d) if !d.is_plausible() => r.push(Finding::new(
            FindingCode::ImplausibleDate,
            base + 0x08,
            format!("implausible release date {d}"),
        )),
        Some(_) => {}
    }

    if header.revision == 0 {
        r.push(Finding::new(
            FindingCode::ZeroRevision,
            base + 0x04,
            "revision is zero",
        ));
    }
    if header.revision & 0x8000_0000 != 0 {
        r.push(Finding::new(
            FindingCode::HighBitRevision,
            base + 0x04,
            format!(
                "revision 0x{:08x} has bit 31 set; this usually marks a pre-production or \
                 special image. Note that iucode-tool orders such revisions as negative while \
                 the Linux loader compares them as unsigned.",
                header.revision
            ),
        ));
    }
    if header.signature.0 == 0 {
        r.push(Finding::new(
            FindingCode::EmptySignatureSet,
            base + 0x0c,
            "primary processor signature is zero",
        ));
    }

    r
}
