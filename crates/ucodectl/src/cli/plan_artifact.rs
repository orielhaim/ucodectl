use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use miette::{Result, miette};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ucode_core::CpuIdentity;
use ucode_policy::Plan;
use ucode_transaction::journal::sha256_hex;

pub const PLAN_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanArtifact {
    pub schema_version: u32,
    pub command: String,
    pub plan_id: String,
    pub created_unix: u64,
    pub inputs: Vec<PlanInput>,
    pub target: PlanTarget,
    pub actions: Vec<String>,
    pub preconditions: Vec<String>,
    pub plan: Plan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanInput {
    pub path: String,
    pub sha256: String,
    pub follow_symlinks: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanTarget {
    pub identities: Vec<CpuIdentity>,
    pub os: String,
    pub virtualization: String,
}

impl PlanArtifact {
    pub fn create(
        plan: Plan,
        paths: &[PathBuf],
        identities: Vec<CpuIdentity>,
        os: String,
        virtualization: String,
        follow_symlinks: bool,
    ) -> Result<Self> {
        let inputs = digest_inputs(paths, follow_symlinks)?;
        let mut artifact = Self {
            schema_version: PLAN_SCHEMA_VERSION,
            command: "plan".to_string(),
            plan_id: String::new(),
            created_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            inputs,
            target: PlanTarget {
                identities,
                os,
                virtualization,
            },
            actions: plan.writes.iter().map(|w| format!("{w:?}")).collect(),
            preconditions: vec![
                "input source hashes must match before apply".to_string(),
                "current CPU identities must match the planned target".to_string(),
            ],
            plan,
        };
        artifact.plan_id = artifact.compute_id()?;
        Ok(artifact)
    }

    pub fn compute_id(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.plan_id.clear();
        let bytes = serde_json::to_vec(&unsigned)
            .map_err(|e| miette!("serialize plan for hashing: {e}"))?;
        Ok(sha256_hex(&bytes))
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != PLAN_SCHEMA_VERSION {
            return Err(miette!(
                "unsupported plan schema_version {}; expected {}",
                self.schema_version,
                PLAN_SCHEMA_VERSION
            ));
        }
        if self.command != "plan" {
            return Err(miette!("not a plan artifact (command={})", self.command));
        }
        if self.plan_id.is_empty() || self.compute_id()? != self.plan_id {
            return Err(miette!("plan_id does not match the plan artifact contents"));
        }
        Ok(())
    }

    pub fn write_to(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| miette!("serialize plan: {e}"))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette!("create {}: {e}", parent.display()))?;
        }
        std::fs::write(path, bytes).map_err(|e| miette!("write {}: {e}", path.display()))?;
        Ok(())
    }

    pub fn read_from(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|e| miette!("{}: {e}", path.display()))?;
        let artifact: Self = serde_json::from_slice(&bytes)
            .map_err(|e| miette!("parse plan {}: {e}", path.display()))?;
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn verify_inputs(&self) -> Result<()> {
        for input in &self.inputs {
            let path = PathBuf::from(&input.path);
            let got = digest_path(&path, input.follow_symlinks)?;
            if got != input.sha256 {
                return Err(miette!(
                    "plan input hash mismatch for {}: expected {}, got {}",
                    path.display(),
                    input.sha256,
                    got
                ));
            }
        }
        Ok(())
    }
}

pub fn digest_inputs(paths: &[PathBuf], follow_symlinks: bool) -> Result<Vec<PlanInput>> {
    paths
        .iter()
        .map(|path| {
            let stored_path = absolute_path(path)?;
            Ok(PlanInput {
                path: stored_path.display().to_string(),
                sha256: digest_path(path, follow_symlinks)?,
                follow_symlinks,
            })
        })
        .collect()
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|e| miette!("resolve {}: {e}", path.display()))
    }
}

fn digest_path(path: &Path, follow_symlinks: bool) -> Result<String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| miette!("{}: {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        if !follow_symlinks {
            return Err(miette!("{}: refusing to follow symlink", path.display()));
        }
        return digest_path(
            &std::fs::canonicalize(path).map_err(|e| miette!("{}: {e}", path.display()))?,
            true,
        );
    }
    if meta.is_file() {
        let bytes = std::fs::read(path).map_err(|e| miette!("{}: {e}", path.display()))?;
        return Ok(sha256_hex(&bytes));
    }
    if !meta.is_dir() {
        return Err(miette!("{}: unsupported input type", path.display()));
    }

    let mut files = Vec::new();
    collect_files(path, path, follow_symlinks, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    for (relative, bytes) in files {
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn collect_files(
    root: &Path,
    path: &Path,
    follow_symlinks: bool,
    out: &mut Vec<(String, Vec<u8>)>,
) -> Result<()> {
    let mut children: Vec<PathBuf> = std::fs::read_dir(path)
        .map_err(|e| miette!("{}: {e}", path.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();
    children.sort();
    for child in children {
        let meta =
            std::fs::symlink_metadata(&child).map_err(|e| miette!("{}: {e}", child.display()))?;
        if meta.file_type().is_symlink() {
            if !follow_symlinks {
                return Err(miette!("{}: refusing to follow symlink", child.display()));
            }
            let target =
                std::fs::canonicalize(&child).map_err(|e| miette!("{}: {e}", child.display()))?;
            collect_files(root, &target, true, out)?;
        } else if meta.is_dir() {
            collect_files(root, &child, follow_symlinks, out)?;
        } else if meta.is_file() {
            let bytes = std::fs::read(&child).map_err(|e| miette!("{}: {e}", child.display()))?;
            let relative = child
                .strip_prefix(root)
                .unwrap_or(&child)
                .display()
                .to_string();
            out.push((relative, bytes));
        }
    }
    Ok(())
}
