use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ucode_archive::{CpioEntry, scan_early_cpio};
use ucode_catalog::{Catalog, IngestOptions, ingest_bytes};
use ucode_core::Vendor;
use ucode_core::limits::Limits;

use crate::{BootError, Result};

/// A microcode blob found inside an early CPIO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedBlob {
    pub path: String,
    pub vendor: Option<Vendor>,
    pub size: u32,
    pub sha256: String,
    pub offset: u64,
}

/// Result of inspecting an initrd image for early microcode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitrdInspection {
    pub path: String,
    pub file_size: u64,
    pub has_early_cpio: bool,
    pub early_end_offset: Option<u64>,
    pub archive_count: u32,
    pub embedded: Vec<EmbeddedBlob>,
    /// Catalog of patches found inside the early blobs.
    #[serde(skip)]
    pub catalog: Catalog,
    pub patch_count: usize,
    pub findings: Vec<String>,
}

/// Inspect an initrd / initramfs file for early microcode.
pub fn inspect_initrd(path: &Path, limits: &Limits) -> Result<InitrdInspection> {
    let bytes = std::fs::read(path).map_err(|e| BootError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    inspect_initrd_bytes(&bytes, path, limits)
}

pub fn inspect_initrd_bytes(
    bytes: &[u8],
    display_path: &Path,
    limits: &Limits,
) -> Result<InitrdInspection> {
    let mut findings = Vec::new();
    let scan = scan_early_cpio(bytes, limits)?;

    let Some(scan) = scan else {
        return Ok(InitrdInspection {
            path: display_path.display().to_string(),
            file_size: bytes.len() as u64,
            has_early_cpio: false,
            early_end_offset: None,
            archive_count: 0,
            embedded: Vec::new(),
            catalog: Catalog::default(),
            patch_count: 0,
            findings: vec!["no leading uncompressed newc CPIO found".to_string()],
        });
    };

    let mut embedded = Vec::new();
    let mut catalog = Catalog::default();
    let opts = IngestOptions {
        limits: *limits,
        keep_payloads: true,
        recursive: false,
        tolerate_failures: true,
        ..IngestOptions::default()
    };

    for entry in &scan.entries {
        if let Some(blob) = classify_entry(entry, bytes) {
            // Ingest the payload into a catalog for further inspection.
            if let Some(data) = entry.data(bytes) {
                let virtual_path = display_path.join(&entry.name);
                match ingest_bytes(&mut catalog, &virtual_path, data, &opts) {
                    Ok(()) => {}
                    Err(e) => findings.push(format!("{}: {e}", entry.name)),
                }
            }
            embedded.push(blob);
        }
    }

    catalog.normalise();

    Ok(InitrdInspection {
        path: display_path.display().to_string(),
        file_size: bytes.len() as u64,
        has_early_cpio: true,
        early_end_offset: Some(scan.end_offset),
        archive_count: scan.archive_count,
        patch_count: catalog.len(),
        embedded,
        catalog,
        findings,
    })
}

/// Extract embedded microcode blobs as `(cpio_path, bytes)`.
pub fn extract_embedded_microcode(bytes: &[u8], limits: &Limits) -> Result<Vec<(String, Vec<u8>)>> {
    let Some(scan) = scan_early_cpio(bytes, limits)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for entry in &scan.entries {
        if is_microcode_path(&entry.name) {
            if let Some(data) = entry.data(bytes) {
                out.push((entry.name.clone(), data.to_vec()));
            }
        }
    }
    Ok(out)
}

fn classify_entry(entry: &CpioEntry, buf: &[u8]) -> Option<EmbeddedBlob> {
    if !entry.is_file() || !is_microcode_path(&entry.name) {
        return None;
    }
    let data = entry.data(buf)?;
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let sha256 = digest.iter().map(|b| format!("{b:02x}")).collect();
    let vendor = if entry.name.contains("GenuineIntel") {
        Some(Vendor::Intel)
    } else if entry.name.contains("AuthenticAMD") {
        Some(Vendor::Amd)
    } else {
        None
    };
    Some(EmbeddedBlob {
        path: entry.name.clone(),
        vendor,
        size: entry.data_len,
        sha256,
        offset: entry.data_offset,
    })
}

fn is_microcode_path(name: &str) -> bool {
    name == Vendor::Intel.early_cpio_path()
        || name == Vendor::Amd.early_cpio_path()
        || name.ends_with("/GenuineIntel.bin")
        || name.ends_with("/AuthenticAMD.bin")
}
