use ucode_core::{CpuSignature, Finding, FindingCode, UcodeDate, ValidationReport};

use crate::AmdPatchHeader;
use crate::header::PATCH_HEADER_SIZE;

/// Per-family maximum patch size, mirroring the constants in
/// `arch/x86/kernel/cpu/microcode/amd.c`. Families the kernel does not pin
/// return `None` and are only size-checked against the global limit.
pub fn max_patch_size_for_family(family: u32) -> Option<u32> {
    match family {
        0x10 | 0x11 | 0x12 | 0x13 => Some(2048),
        0x14 => Some(1824),
        0x15 => Some(4096),
        0x16 => Some(3458),
        0x17 | 0x18 => Some(3200),
        0x19 => Some(5568),
        // Zen 5 and later ship substantially larger patches (observed 14368
        // bytes on family 0x1a). No published constant, so use a generous
        // bound that still catches nonsense.
        0x1a => Some(16384),
        _ => None,
    }
}

pub fn validate_patch(
    header: &AmdPatchHeader,
    section_size: u32,
    offset: u64,
    signatures: &[CpuSignature],
) -> ValidationReport {
    let mut r = ValidationReport::default();

    if signatures.is_empty() {
        r.push(Finding::new(
            FindingCode::EquivalenceIdNotInTable,
            offset + 24,
            format!(
                "patch equivalence id 0x{:04x} is not present in the container's equivalence \
                 table; the loader will never select this patch",
                header.processor_rev_id
            ),
        ));
    }

    if let Some(sig) = signatures.first() {
        let family = sig.family();
        if let Some(max) = max_patch_size_for_family(family)
            && section_size > max
        {
            r.push(Finding::new(
                FindingCode::PatchSizeExceedsFamilyMaximum,
                offset,
                format!(
                    "patch is {section_size} bytes but family 0x{family:x} is limited to {max} \
                     bytes by the Linux loader"
                ),
            ));
        }
    }

    if (section_size as usize) < PATCH_HEADER_SIZE {
        r.push(Finding::new(
            FindingCode::BadTotalSize,
            offset,
            format!("patch section is {section_size} bytes, smaller than the 64-byte header"),
        ));
    }

    match UcodeDate::from_packed_bcd(header.date_raw) {
        None => r.push(Finding::new(
            FindingCode::NonBcdDate,
            offset,
            format!(
                "date field 0x{:08x} is not valid packed BCD",
                header.date_raw
            ),
        )),
        Some(d) if !d.is_plausible() => r.push(Finding::new(
            FindingCode::ImplausibleDate,
            offset,
            format!("implausible release date {d}"),
        )),
        Some(_) => {}
    }

    if header.patch_id == 0 {
        r.push(Finding::new(
            FindingCode::ZeroRevision,
            offset + 4,
            "patch id is zero",
        ));
    }

    if header.reserved != [0, 0, 0] {
        r.push(Finding::new(
            FindingCode::ReservedFieldNonZero,
            offset + 29,
            format!("reserved bytes are {:02x?}", header.reserved),
        ));
    }

    r
}
