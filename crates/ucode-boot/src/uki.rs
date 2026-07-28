//! UKI (Unified Kernel Image) inspection via PE/COFF sections.
//!
//! Per UAPI.5, microcode lives in a `.ucode` section. We only *read* it —
//! mutating a signed UKI would break Secure Boot signatures.

use std::path::Path;

use object::{Object, ObjectSection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ucode_archive::scan_early_cpio;
use ucode_catalog::{Catalog, IngestOptions, ingest_bytes};
use ucode_core::limits::Limits;

use crate::{BootError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UkiSectionInfo {
    pub name: String,
    pub size: u64,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UkiInspection {
    pub path: String,
    pub file_size: u64,
    pub is_pe: bool,
    pub sections: Vec<UkiSectionInfo>,
    pub has_ucode_section: bool,
    pub ucode_size: Option<u64>,
    pub ucode_sha256: Option<String>,
    /// True when the PE has a non-empty certificate table (Authenticode).
    pub has_authenticode: bool,
    pub patch_count: usize,
    #[serde(skip)]
    pub catalog: Catalog,
    pub findings: Vec<String>,
}

/// Inspect a UKI (or any PE) for a `.ucode` section.
pub fn inspect_uki(path: &Path, limits: &Limits) -> Result<UkiInspection> {
    let bytes = std::fs::read(path).map_err(|e| BootError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    inspect_uki_bytes(&bytes, path, limits)
}

pub fn inspect_uki_bytes(
    bytes: &[u8],
    display_path: &Path,
    limits: &Limits,
) -> Result<UkiInspection> {
    let mut findings = Vec::new();

    let file = object::File::parse(bytes).map_err(|e| BootError::Pe(e.to_string()))?;

    let mut sections = Vec::new();
    let mut ucode_data: Option<Vec<u8>> = None;

    for section in file.sections() {
        let name = section.name().unwrap_or("<unnamed>").to_string();
        let data = section.data().ok();
        let size = section.size();
        let sha256 = data.map(|d| {
            let mut h = Sha256::new();
            h.update(d);
            h.finalize().iter().map(|b| format!("{b:02x}")).collect()
        });
        if name == ".ucode" {
            if let Some(d) = data {
                ucode_data = Some(d.to_vec());
            }
        }
        sections.push(UkiSectionInfo { name, size, sha256 });
    }

    // Certificate directory presence (data directory index 4).
    let has_authenticode = pe_has_certificate_table(bytes);

    let mut catalog = Catalog::default();
    let mut patch_count = 0usize;

    if let Some(ucode) = &ucode_data {
        // `.ucode` content is itself an early CPIO (or raw concatenated blobs).
        match parse_ucode_payload(ucode, display_path, limits, &mut catalog) {
            Ok(n) => patch_count = n,
            Err(e) => findings.push(format!(".ucode parse: {e}")),
        }
    } else {
        findings.push("no .ucode section present".to_string());
    }

    let ucode_sha256 = ucode_data.as_ref().map(|d| {
        let mut h = Sha256::new();
        h.update(d);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    });

    Ok(UkiInspection {
        path: display_path.display().to_string(),
        file_size: bytes.len() as u64,
        is_pe: true,
        has_ucode_section: ucode_data.is_some(),
        ucode_size: ucode_data.as_ref().map(|d| d.len() as u64),
        ucode_sha256,
        has_authenticode,
        sections,
        patch_count,
        catalog,
        findings,
    })
}

fn parse_ucode_payload(
    ucode: &[u8],
    display_path: &Path,
    limits: &Limits,
    catalog: &mut Catalog,
) -> Result<usize> {
    let opts = IngestOptions {
        limits: *limits,
        keep_payloads: true,
        recursive: false,
        tolerate_failures: true,
        ..IngestOptions::default()
    };

    // Prefer early CPIO layout.
    if let Ok(Some(scan)) = scan_early_cpio(ucode, limits) {
        for entry in scan.entries {
            if let Some(data) = entry.data(ucode) {
                let vp = display_path.join(&entry.name);
                let _ = ingest_bytes(catalog, &vp, data, &opts);
            }
        }
        catalog.normalise();
        return Ok(catalog.len());
    }

    // Fall back to treating the whole section as a microcode blob.
    let vp = display_path.join(".ucode");
    ingest_bytes(catalog, &vp, ucode, &opts)?;
    catalog.normalise();
    Ok(catalog.len())
}

/// Minimal PE data-directory probe for the certificate table without depending
/// on full PE write support.
fn pe_has_certificate_table(bytes: &[u8]) -> bool {
    // DOS header e_lfanew at 0x3c.
    if bytes.len() < 0x40 {
        return false;
    }
    let e_lfanew =
        u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    // PE signature + COFF header (20) + optional header start.
    if bytes.len() < e_lfanew + 24 {
        return false;
    }
    if &bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return false;
    }
    let opt_off = e_lfanew + 24;
    if bytes.len() < opt_off + 2 {
        return false;
    }
    let magic = u16::from_le_bytes([bytes[opt_off], bytes[opt_off + 1]]);
    // Data directories start after the standard optional header fields.
    // PE32: magic 0x10b, data dirs at +96; PE32+: magic 0x20b, at +112.
    let dd_off = match magic {
        0x10b => opt_off + 96,
        0x20b => opt_off + 112,
        _ => return false,
    };
    // Certificate table is data directory index 4 → offset + 4*8 = +32.
    let cert_off = dd_off + 4 * 8;
    if bytes.len() < cert_off + 8 {
        return false;
    }
    let rva = u32::from_le_bytes([
        bytes[cert_off],
        bytes[cert_off + 1],
        bytes[cert_off + 2],
        bytes[cert_off + 3],
    ]);
    let size = u32::from_le_bytes([
        bytes[cert_off + 4],
        bytes[cert_off + 5],
        bytes[cert_off + 6],
        bytes[cert_off + 7],
    ]);
    rva != 0 && size != 0
}
