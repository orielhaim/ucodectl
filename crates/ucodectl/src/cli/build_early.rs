use miette::Result;
use serde::Serialize;
use ucode_boot::{EarlyBuildInput, build_early_cpio};

use super::{BuildEarlyArgs, OutputFormat};
use crate::output::emit;
use crate::util::{apply_amd_sidecar, default_limits, load_catalog_named, resolve_system};

#[derive(Serialize)]
struct BuildJson {
    schema_version: u32,
    command: &'static str,
    output: String,
    size: u64,
    sha256: String,
    intel_patches: usize,
    amd_patches: usize,
    paths: Vec<String>,
    warnings: Vec<String>,
}

pub fn run(args: BuildEarlyArgs, format: OutputFormat) -> Result<i32> {
    if args.intel_platform_id.is_some() && args.vendor != Some(crate::util::VendorArg::Intel) {
        return Err(miette::miette!(
            "--intel-platform-id requires --vendor intel"
        ));
    }
    if args.match_host && args.signature.is_some() {
        return Err(miette::miette!("--match-host conflicts with --signature"));
    }

    let mut catalog = load_catalog_named(
        "build-early: failed to load microcode source",
        &args.paths,
        default_limits(),
        true,
        args.follow_symlinks,
    )?;
    let amd_metadata =
        crate::util::resolve_amd_metadata(&args.paths, args.amd_metadata.as_deref())?;
    let _ = apply_amd_sidecar(&mut catalog, amd_metadata.as_deref())?;
    let warnings: Vec<String> = catalog
        .failures
        .iter()
        .filter(|(_, reason)| reason.contains("refusing to follow symlink"))
        .map(|(path, reason)| format!("{}: {reason}", path.display()))
        .collect();

    let filter_cpus = if args.match_host || args.signature.is_some() {
        let system = resolve_system(args.signature, args.vendor, args.intel_platform_id, None)?;
        if args.match_host
            && matches!(
                system.virtualization,
                ucode_linux::VirtualizationKind::VirtualMachineGuest
            )
            && !args.allow_virtual_cpu_target
        {
            return Err(miette::miette!(
                "host matching is disabled for VM/WSL guests whose microcode is host-managed; pass --allow-virtual-cpu-target to target the virtual CPU explicitly"
            ));
        }
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
        .map_err(|e| crate::error::output_io("build-early", &args.output, &e))?;

    let json = BuildJson {
        schema_version: 1,
        command: "build-early",
        output: args.output.display().to_string(),
        size: result.size,
        sha256: result.sha256,
        intel_patches: result.intel_patches,
        amd_patches: result.amd_patches,
        paths: result.paths,
        warnings,
    };

    emit(format, &json, || {
        let warning = if args.all_revisions {
            "  warning: --all-revisions requested; this is not the usual minimal deterministic release selection\n"
        } else {
            ""
        };
        let skipped = json
            .warnings
            .iter()
            .map(|warning| format!("  warning: {warning}\n"))
            .collect::<String>();
        format!(
            "wrote {} ({} bytes, sha256={})\n  intel patches: {}\n  amd patches: {}\n  members: {}\n",
            json.output,
            json.size,
            json.sha256,
            json.intel_patches,
            json.amd_patches,
            json.paths.join(", "),
        ) + warning
            + &skipped
    });

    Ok(0)
}
