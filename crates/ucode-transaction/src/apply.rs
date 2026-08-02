use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use ucode_boot::{EarlyBuildInput, build_early_cpio};
use ucode_catalog::Catalog;
use ucode_core::CpuIdentity;
use ucode_policy::{Plan, PlannedWrite};

use crate::journal::{Journal, JournalEntry, atomic_write, backup_existing, sha256_hex};
use crate::preflight::{preflight, require_ok};
use crate::{Result, TransactionError};

#[derive(Debug, Clone)]
pub struct ApplyOptions {
    pub dry_run: bool,
    pub backup_dir: PathBuf,
    pub journal_path: PathBuf,
    pub confinement_root: Option<PathBuf>,
    pub catalog: Catalog,
    pub filter_cpus: Vec<CpuIdentity>,
    pub plan_id: String,
    pub receipt_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyResult {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub backup: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyReport {
    pub schema_version: u32,
    pub command: String,
    pub transaction_id: String,
    pub plan_id: String,
    pub dry_run: bool,
    pub committed: bool,
    pub results: Vec<ApplyResult>,
    pub messages: Vec<String>,
    pub journal_path: String,
    pub receipt_path: Option<String>,
}

/// Execute a plan. When `dry_run` is set, only preflight + describe.
pub fn apply_plan(plan: &Plan, opts: &ApplyOptions) -> Result<ApplyReport> {
    let pf = preflight(plan, opts.confinement_root.as_deref())?;
    require_ok(&pf)?;

    let id = format!(
        "tx-{}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    );

    let mut journal = Journal::default();
    journal.push(JournalEntry::Begin {
        id: id.clone(),
        plan_id: opts.plan_id.clone(),
        started_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    });

    let mut results = Vec::new();
    let mut messages = plan.messages.clone();

    if opts.dry_run {
        for w in &plan.writes {
            messages.push(format!("dry-run: would apply {w:?}"));
        }
        return Ok(ApplyReport {
            schema_version: 1,
            command: "apply".to_string(),
            transaction_id: id,
            plan_id: opts.plan_id.clone(),
            dry_run: true,
            committed: false,
            results,
            messages: messages.clone(),
            journal_path: opts.journal_path.display().to_string(),
            receipt_path: None,
        });
    }

    if plan.writes.is_empty() {
        messages.push("nothing to apply".to_string());
        return Ok(ApplyReport {
            schema_version: 1,
            command: "apply".to_string(),
            transaction_id: id.clone(),
            plan_id: opts.plan_id.clone(),
            dry_run: false,
            committed: true,
            results,
            messages: messages.clone(),
            journal_path: opts.journal_path.display().to_string(),
            receipt_path: write_receipt(
                opts.receipt_path.as_deref(),
                &ApplyReport {
                    schema_version: 1,
                    command: "apply".to_string(),
                    transaction_id: id,
                    plan_id: opts.plan_id.clone(),
                    dry_run: false,
                    committed: true,
                    results: Vec::new(),
                    messages: messages.clone(),
                    journal_path: opts.journal_path.display().to_string(),
                    receipt_path: None,
                },
            )?,
        });
    }

    for w in &plan.writes {
        match w {
            PlannedWrite::EarlyCpio { path, .. } => {
                let filter = if opts.filter_cpus.is_empty() {
                    None
                } else {
                    Some(opts.filter_cpus.as_slice())
                };
                let built = build_early_cpio(EarlyBuildInput {
                    catalog: &opts.catalog,
                    filter_cpus: filter,
                    emit_parent_dirs: true,
                    best_only: true,
                })?;

                let dest = Path::new(path);
                let backup = backup_existing(dest, &opts.backup_dir)?;
                atomic_write(dest, &built.bytes)?;

                let sha = sha256_hex(&built.bytes);
                info!(path = %path, bytes = built.bytes.len(), "wrote early CPIO");
                journal.push(JournalEntry::Wrote {
                    path: path.clone(),
                    sha256: sha.clone(),
                    bytes: built.bytes.len() as u64,
                    backup: backup.as_ref().map(|p| p.display().to_string()),
                });
                results.push(ApplyResult {
                    path: path.clone(),
                    bytes: built.bytes.len() as u64,
                    sha256: sha,
                    backup: backup.map(|p| p.display().to_string()),
                });
            }
            PlannedWrite::IntelFirmwareDir { dir, .. }
            | PlannedWrite::AmdFirmwareDir { dir, .. } => {
                warn!(dir = %dir, "firmware-dir writes are reserved for future releases");
                messages.push(format!(
                    "skipped firmware directory write to {dir} (not implemented in v0.1)"
                ));
            }
        }
    }

    journal.push(JournalEntry::Commit { id: id.clone() });
    if let Err(e) = journal.write_to(&opts.journal_path) {
        warn!(error = %e, "failed to persist journal");
        messages.push(format!("warning: journal not written: {e}"));
    }

    // Post-write validation: re-read and compare hashes.
    for r in &results {
        match std::fs::read(&r.path) {
            Ok(bytes) => {
                let got = sha256_hex(&bytes);
                if got != r.sha256 {
                    return Err(TransactionError::Other(format!(
                        "post-write hash mismatch for {}: expected {}, got {got}",
                        r.path, r.sha256
                    )));
                }
            }
            Err(e) => {
                return Err(TransactionError::Io {
                    path: PathBuf::from(&r.path),
                    source: e,
                });
            }
        }
    }

    let report = ApplyReport {
        schema_version: 1,
        command: "apply".to_string(),
        transaction_id: id,
        plan_id: opts.plan_id.clone(),
        dry_run: false,
        committed: true,
        results,
        messages,
        journal_path: opts.journal_path.display().to_string(),
        receipt_path: opts.receipt_path.as_ref().map(|p| p.display().to_string()),
    };
    if let Some(path) = &opts.receipt_path {
        write_receipt(Some(path), &report)?;
    }
    Ok(report)
}

fn write_receipt(path: Option<&Path>, report: &ApplyReport) -> Result<Option<String>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = serde_json::to_vec_pretty(report)
        .map_err(|e| TransactionError::Other(format!("receipt serialize: {e}")))?;
    atomic_write(path, &bytes)?;
    Ok(Some(path.display().to_string()))
}
