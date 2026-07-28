use miette::Result;
use ucode_boot::inspect_initrd;
use ucode_core::limits::Limits;
use ucode_policy::{PlanInput, evaluate};
use ucode_transaction::{ApplyOptions, apply_plan};

use super::{ApplyArgs, OutputFormat};
use crate::output::emit;
use crate::util::{default_limits, load_catalog, resolve_system};

pub fn run(args: ApplyArgs, format: OutputFormat) -> Result<i32> {
    if !args.dry_run && !args.yes {
        return Err(miette::miette!(
            "refusing to apply without --yes (or pass --dry-run)"
        ));
    }

    let system = resolve_system(None, None, args.platform_id, None)?;
    let catalog = load_catalog(&args.paths, default_limits(), true)?;
    let limits = Limits::default();
    let embedded_insp = if let Some(boot) = &args.boot {
        Some(inspect_initrd(boot, &limits).map_err(|e| miette::miette!("{e}"))?)
    } else {
        None
    };

    let plan = evaluate(&PlanInput {
        system: &system,
        available: &catalog,
        embedded: embedded_insp.as_ref().map(|i| &i.catalog),
        allow_downgrade: args.allow_downgrade,
        want_early_image: true,
        early_output: Some(args.early_output.display().to_string()),
    });

    let report = apply_plan(
        &plan,
        &ApplyOptions {
            dry_run: args.dry_run,
            backup_dir: args.backup_dir.clone(),
            journal_path: args.journal.clone(),
            confinement_root: None,
            catalog,
            filter_cpus: system.unique_identities.clone(),
        },
    )
    .map_err(|e| miette::miette!("{e}"))?;

    emit(format, &report, || {
        let mut out = String::new();
        out.push_str(&format!(
            "apply: dry_run={} committed={}\n",
            report.dry_run, report.committed
        ));
        for r in &report.results {
            out.push_str(&format!(
                "  wrote {} ({} bytes, sha256={})\n",
                r.path, r.bytes, r.sha256
            ));
            if let Some(b) = &r.backup {
                out.push_str(&format!("    backup: {b}\n"));
            }
        }
        for m in &report.messages {
            out.push_str(&format!("  note: {m}\n"));
        }
        out.push_str(&format!("  journal: {}\n", report.journal_path));
        out
    });

    Ok(0)
}
