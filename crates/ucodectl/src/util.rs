use std::path::{Path, PathBuf};

use miette::{Result, miette};
use ucode_catalog::{AmdSidecar, Catalog, IngestOptions, ingest_path};
use ucode_core::limits::Limits;
use ucode_core::{CpuIdentity, CpuSignature, PlatformMask, Vendor};
use ucode_linux::{SystemState, discover_system, system_from_identity, with_platform_mask};

/// Load one or more paths into a catalog.
pub fn load_catalog(paths: &[PathBuf], limits: Limits, keep_payloads: bool) -> Result<Catalog> {
    load_catalog_named("load microcode source", paths, limits, keep_payloads, true)
}

/// Load catalog sources while making symlink policy explicit for workflows
/// that may later materialise an early-boot artifact.
pub fn load_catalog_with_options(
    paths: &[PathBuf],
    limits: Limits,
    keep_payloads: bool,
    follow_symlinks: bool,
) -> Result<Catalog> {
    load_catalog_named(
        "load microcode source",
        paths,
        limits,
        keep_payloads,
        follow_symlinks,
    )
}

pub fn load_catalog_named(
    command: &str,
    paths: &[PathBuf],
    limits: Limits,
    keep_payloads: bool,
    follow_symlinks: bool,
) -> Result<Catalog> {
    if paths.is_empty() {
        return Err(miette!("at least one microcode source path is required"));
    }
    let mut catalog = Catalog::default();
    let opts = IngestOptions {
        limits,
        keep_payloads,
        recursive: true,
        tolerate_failures: true,
        follow_symlinks,
        ..IngestOptions::default()
    };
    for path in paths {
        ingest_path(&mut catalog, path, &opts)
            .map_err(|error| crate::error::catalog(command, &error))?;
    }
    if catalog.sources.is_empty() {
        return Err(crate::error::report(
            "empty_source",
            format!("{command}: source contained no supported microcode files"),
            "pass a release directory or a supported Intel/AMD microcode file",
        ));
    }
    Ok(catalog)
}

/// Optionally apply an AMD README sidecar.
pub fn apply_amd_sidecar(catalog: &mut Catalog, sidecar_path: Option<&Path>) -> Result<usize> {
    let Some(path) = sidecar_path else {
        return Ok(0);
    };
    let text = std::fs::read_to_string(path)
        .map_err(|e| crate::error::input_io("AMD metadata", path, &e))?;
    let sidecar = AmdSidecar::parse_linux_firmware_readme(&text).map_err(|e| {
        crate::error::report(
            "malformed_microcode",
            format!("AMD metadata: {e}"),
            "provide valid release metadata",
        )
    })?;
    Ok(catalog.apply_sidecar(&sidecar))
}

/// Resolve AMD release metadata without exposing the current README layout as
/// the primary command-line API. An explicit path always wins; otherwise a
/// directory named `amd-ucode` gets its sibling README when present.
pub fn resolve_amd_metadata(paths: &[PathBuf], explicit: Option<&Path>) -> Result<Option<PathBuf>> {
    if let Some(path) = explicit {
        return Ok(Some(path.to_path_buf()));
    }

    for path in paths {
        if path.is_dir() && path.file_name().and_then(|name| name.to_str()) == Some("amd-ucode") {
            let candidate = path.join("README");
            if candidate.is_file() {
                return Ok(Some(candidate));
            }
        }
    }
    Ok(None)
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
            if vendor != Vendor::Intel {
                return Err(miette!(
                    "--intel-platform-id is only valid for Intel CPU identities"
                ));
            }
            id = id.with_platform_mask(PlatformMask::from_platform_id(pid));
        }
        if let Some(rev) = revision {
            id = id.with_revision(rev);
        }
        return Ok(system_from_identity(id));
    }

    let mut state = discover_system().map_err(|e| miette!("system discovery: {e}"))?;
    if let Some(pid) = platform_id {
        if state
            .cpus
            .iter()
            .any(|cpu| cpu.identity.vendor != Vendor::Intel)
        {
            return Err(miette!(
                "--intel-platform-id is only valid when the detected CPU vendor is Intel"
            ));
        }
        state = with_platform_mask(state, PlatformMask::from_platform_id(pid));
    }
    if let Some(rev) = revision {
        for cpu in &mut state.cpus {
            cpu.identity.current_revision = Some(rev);
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
