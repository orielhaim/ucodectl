use std::path::{Path, PathBuf};

use miette::{Result, miette};
use ucode_catalog::{AmdSidecar, Catalog, IngestOptions, ingest_path};
use ucode_core::limits::Limits;
use ucode_core::{CpuIdentity, CpuSignature, PlatformMask, Vendor};
use ucode_linux::{SystemState, discover_system, system_from_identity, with_platform_mask};

/// Load one or more paths into a catalog.
pub fn load_catalog(paths: &[PathBuf], limits: Limits, keep_payloads: bool) -> Result<Catalog> {
    if paths.is_empty() {
        return Err(miette!("at least one microcode source path is required"));
    }
    let mut catalog = Catalog::default();
    let opts = IngestOptions {
        limits,
        keep_payloads,
        recursive: true,
        tolerate_failures: true,
        ..IngestOptions::default()
    };
    for path in paths {
        ingest_path(&mut catalog, path, &opts).map_err(|e| miette!("{e}"))?;
    }
    Ok(catalog)
}

/// Optionally apply an AMD README sidecar.
pub fn apply_amd_sidecar(catalog: &mut Catalog, sidecar_path: Option<&Path>) -> Result<usize> {
    let Some(path) = sidecar_path else {
        return Ok(0);
    };
    let text = std::fs::read_to_string(path).map_err(|e| miette!("{}: {e}", path.display()))?;
    let sidecar =
        AmdSidecar::parse_linux_firmware_readme(&text).map_err(|e| miette!("sidecar: {e}"))?;
    Ok(catalog.apply_sidecar(&sidecar))
}

/// Resolve system state, optionally overridden by explicit CPU flags.
pub fn resolve_system(
    signature: Option<u32>,
    vendor: Option<VendorArg>,
    platform_id: Option<u32>,
    revision: Option<u32>,
) -> Result<SystemState> {
    if let Some(sig) = signature {
        let vendor = match vendor {
            Some(VendorArg::Intel) => Vendor::Intel,
            Some(VendorArg::Amd) => Vendor::Amd,
            None => {
                // Heuristic: high families are usually AMD display family.
                let s = CpuSignature(sig);
                if s.family() >= 0x15 {
                    Vendor::Amd
                } else {
                    Vendor::Intel
                }
            }
        };
        let mut id = CpuIdentity::new(vendor, CpuSignature(sig));
        if let Some(pid) = platform_id {
            id = id.with_platform_mask(PlatformMask::from_platform_id(pid));
        }
        if let Some(rev) = revision {
            id = id.with_revision(rev);
        }
        return Ok(system_from_identity(id));
    }

    let mut state = discover_system().map_err(|e| miette!("system discovery: {e}"))?;
    if let Some(pid) = platform_id {
        state = with_platform_mask(state, PlatformMask::from_platform_id(pid));
    }
    if let Some(rev) = revision {
        for cpu in &mut state.cpus {
            if cpu.identity.current_revision.is_none() {
                cpu.identity.current_revision = Some(rev);
            }
        }
    }
    Ok(state)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum VendorArg {
    Intel,
    Amd,
}

impl From<VendorArg> for Vendor {
    fn from(v: VendorArg) -> Self {
        match v {
            VendorArg::Intel => Vendor::Intel,
            VendorArg::Amd => Vendor::Amd,
        }
    }
}

pub fn default_limits() -> Limits {
    Limits::default()
}
