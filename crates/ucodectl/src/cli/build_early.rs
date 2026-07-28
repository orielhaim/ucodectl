use miette::Result;
use serde::Serialize;
use ucode_boot::{EarlyBuildInput, build_early_cpio};

use super::{BuildEarlyArgs, OutputFormat};
use crate::output::emit;
use crate::util::{apply_amd_sidecar, default_limits, load_catalog, resolve_system};

#[derive(Serialize)]
struct BuildJson {
    output: String,
    size: u64,
    sha256: String,
    intel_patches: usize,
    amd_patches: usize,
    paths: Vec<String>,
}

pub fn run(args: BuildEarlyArgs, format: OutputFormat) -> Result<i32> {
    let mut catalog = load_catalog(&args.paths, default_limits(), true)?;
    let _ = apply_amd_sidecar(&mut catalog, args.amd_readme.as_deref())?;

    let filter_cpus = if args.match_host || args.signature.is_some() {
        let system = resolve_system(args.signature, args.vendor, args.platform_id, None)?;
        Some(system.unique_identities.clone())
    } else {
        None
    };

    let result = build_early_cpio(EarlyBuildInput {
        catalog: &catalog,
        filter_cpus: filter_cpus.as_deref(),
        emit_parent_dirs: true,
        best_only: !args.all_revisions,
    })
    .map_err(|e| miette::miette!("{e}"))?;

    std::fs::write(&args.output, &result.bytes)
        .map_err(|e| miette::miette!("write {}: {e}", args.output.display()))?;

    let json = BuildJson {
        output: args.output.display().to_string(),
        size: result.size,
        sha256: result.sha256,
        intel_patches: result.intel_patches,
        amd_patches: result.amd_patches,
        paths: result.paths,
    };

    emit(format, &json, || {
        format!(
            "wrote {} ({} bytes, sha256={})\n  intel patches: {}\n  amd patches: {}\n  members: {}\n",
            json.output,
            json.size,
            json.sha256,
            json.intel_patches,
            json.amd_patches,
            json.paths.join(", "),
        )
    });

    Ok(0)
}
