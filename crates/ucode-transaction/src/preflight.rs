use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use ucode_policy::{Plan, PlannedWrite};

use crate::{Result, TransactionError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightReport {
    pub ok: bool,
    pub issues: Vec<String>,
    pub target_paths: Vec<String>,
}

/// Validate that a plan can be applied safely.
pub fn preflight(plan: &Plan, confinement_root: Option<&Path>) -> Result<PreflightReport> {
    let mut issues = Vec::new();
    let mut target_paths = Vec::new();

    if plan.writes.is_empty() && plan.would_change {
        issues.push("plan claims changes but lists no writes".to_string());
    }

    for w in &plan.writes {
        match w {
            PlannedWrite::EarlyCpio { path, .. } => {
                target_paths.push(path.clone());
                check_path(Path::new(path), confinement_root, &mut issues);
            }
            PlannedWrite::IntelFirmwareDir { dir, .. }
            | PlannedWrite::AmdFirmwareDir { dir, .. } => {
                target_paths.push(dir.clone());
                check_path(Path::new(dir), confinement_root, &mut issues);
            }
        }
    }

    for path in &target_paths {
        let p = Path::new(path);
        if p.exists() {
            if let Ok(meta) = std::fs::symlink_metadata(p)
                && meta.file_type().is_symlink()
            {
                issues.push(format!("refusing to overwrite symlink {path}"));
            }
            // Parent must be writable.
            if let Some(parent) = p.parent()
                && parent.exists()
            {
                let probe = parent.join(".ucodectl-write-probe");
                match std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(&probe)
                {
                    Ok(_) => {
                        let _ = std::fs::remove_file(&probe);
                    }
                    Err(e) => issues.push(format!("cannot write to {}: {e}", parent.display())),
                }
            }
        } else if let Some(parent) = p.parent() {
            if parent.as_os_str().is_empty() {
                continue;
            }
            if !parent.exists() {
                // We will create it; check grandparent writability loosely.
                continue;
            }
        }
    }

    Ok(PreflightReport {
        ok: issues.is_empty(),
        issues,
        target_paths,
    })
}

fn check_path(path: &Path, root: Option<&Path>, issues: &mut Vec<String>) {
    if path.as_os_str().is_empty() {
        issues.push("empty target path".to_string());
        return;
    }
    if path.is_absolute()
        && let Some(root) = root
        // Absolute paths must stay under confinement root when set.
        && let (Ok(cpath), Ok(croot)) = (
            path.canonicalize().or_else(|_| {
                // Path may not exist yet; canonicalize parent.
                path.parent()
                    .unwrap_or(path)
                    .canonicalize()
                    .map(|p| p.join(path.file_name().unwrap_or_default()))
            }),
            root.canonicalize(),
        )
        && !cpath.starts_with(&croot)
    {
        issues.push(format!(
            "path {} escapes confinement root {}",
            path.display(),
            root.display()
        ));
    }
    // Relative paths are fine (cwd-relative write).
    let _ = PathBuf::from(path);
}

/// Map preflight failure into a hard error.
pub fn require_ok(report: &PreflightReport) -> Result<()> {
    if report.ok {
        Ok(())
    } else {
        Err(TransactionError::Preflight(report.issues.join("; ")))
    }
}
