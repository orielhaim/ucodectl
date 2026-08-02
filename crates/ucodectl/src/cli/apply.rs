use std::io::{self, Write};
use std::path::PathBuf;

use miette::Result;
use ucode_transaction::{ApplyOptions, apply_plan};

use super::{ApplyArgs, OutputFormat};
use crate::cli::plan_artifact::PlanArtifact;
use crate::output::emit;
use crate::util::{default_limits, load_catalog_with_options, resolve_system};

pub fn run(args: ApplyArgs, format: OutputFormat) -> Result<i32> {
    let artifact = PlanArtifact::read_from(&args.plan)?;
    artifact.verify_inputs()?;

    let system = resolve_system(None, None, None, None)?;
    let identities_match = artifact.target.identities.len() == system.unique_identities.len()
        && artifact
            .target
            .identities
            .iter()
            .all(|identity| system.unique_identities.contains(identity));
    if !identities_match {
        return Err(miette::miette!(
            "system CPU identities no longer match plan {}",
            artifact.plan_id
        ));
    }

    if !args.dry_run && !cfg!(target_os = "linux") {
        return Err(miette::miette!(
            "apply is supported on Linux only; use --dry-run to validate a plan on this host"
        ));
    }

    if !args.dry_run {
        confirm(&args, &artifact.plan_id)?;
    }

    let follow_symlinks = artifact
        .inputs
        .first()
        .map(|input| input.follow_symlinks)
        .unwrap_or(false);
    let source_paths: Vec<PathBuf> = artifact
        .inputs
        .iter()
        .map(|input| PathBuf::from(&input.path))
        .collect();
    let catalog =
        load_catalog_with_options(&source_paths, default_limits(), true, follow_symlinks)?;

    let (backup_dir, journal_path, receipt_path) =
        transaction_paths(&artifact.plan_id, args.backup_dir, args.journal);
    let report = apply_plan(
        &artifact.plan,
        &ApplyOptions {
            dry_run: args.dry_run,
            backup_dir,
            journal_path,
            confinement_root: None,
            catalog,
            filter_cpus: system.unique_identities,
            plan_id: artifact.plan_id.clone(),
            receipt_path: if args.dry_run {
                None
            } else {
                Some(receipt_path)
            },
        },
    )
    .map_err(|e| miette::miette!("apply transaction: {e}"))?;

    emit(format, &report, || {
        let mut out = String::new();
        out.push_str(&format!(
            "apply: plan={} transaction={} dry_run={} committed={}\n",
            report.plan_id, report.transaction_id, report.dry_run, report.committed
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
        if let Some(receipt) = &report.receipt_path {
            out.push_str(&format!("  receipt: {receipt}\n"));
        }
        out
    });

    Ok(0)
}

fn confirm(args: &ApplyArgs, plan_id: &str) -> Result<()> {
    if let Some(token) = &args.confirm {
        if token != plan_id {
            return Err(miette::miette!(
                "--confirm must equal the plan ID ({plan_id})"
            ));
        }
        return Ok(());
    }
    if args.yes {
        return Ok(());
    }

    print!("Type APPLY to continue applying plan {plan_id}: ");
    io::stdout()
        .flush()
        .map_err(|e| miette::miette!("confirmation prompt: {e}"))?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|e| miette::miette!("confirmation prompt: {e}"))?;
    if answer.trim() != "APPLY" {
        return Err(miette::miette!(
            "apply cancelled; confirmation was not APPLY"
        ));
    }
    Ok(())
}

fn transaction_paths(
    plan_id: &str,
    backup: Option<PathBuf>,
    journal: Option<PathBuf>,
) -> (PathBuf, PathBuf, PathBuf) {
    let backup_dir = backup.unwrap_or_else(|| {
        if cfg!(target_os = "linux") {
            PathBuf::from(format!("/var/lib/ucodectl/backups/{plan_id}"))
        } else {
            PathBuf::from(format!(".ucodectl-backup/{plan_id}"))
        }
    });
    let journal_path = journal.unwrap_or_else(|| {
        if cfg!(target_os = "linux") {
            PathBuf::from(format!("/var/lib/ucodectl/transactions/{plan_id}.json"))
        } else {
            PathBuf::from(format!(".ucodectl-transactions/{plan_id}.json"))
        }
    });
    let receipt_path = journal_path.with_extension("receipt.json");
    (backup_dir, journal_path, receipt_path)
}
