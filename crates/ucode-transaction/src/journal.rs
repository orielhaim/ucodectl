use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Result, TransactionError};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum JournalEntry {
    Begin {
        id: String,
        plan_id: String,
        started_unix: u64,
    },
    Wrote {
        path: String,
        sha256: String,
        bytes: u64,
        backup: Option<String>,
    },
    Commit {
        id: String,
    },
    Rollback {
        id: String,
        reason: String,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Journal {
    pub entries: Vec<JournalEntry>,
}

impl Journal {
    pub fn push(&mut self, entry: JournalEntry) {
        self.entries.push(entry);
    }

    pub fn write_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| TransactionError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| TransactionError::Other(format!("journal serialize: {e}")))?;
        atomic_write(path, &json)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).map_err(|e| TransactionError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        serde_json::from_slice(&bytes)
            .map_err(|e| TransactionError::Other(format!("journal parse: {e}")))
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Stage to a temporary file in the same directory, fsync, then rename.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| TransactionError::Io {
        path: parent.to_path_buf(),
        source: e,
    })?;

    // Reject writing through an existing symlink destination path.
    if path.exists() {
        let meta = fs::symlink_metadata(path).map_err(|e| TransactionError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        if meta.file_type().is_symlink() {
            return Err(TransactionError::Symlink {
                path: path.to_path_buf(),
            });
        }
    }

    let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(|e| TransactionError::Io {
        path: parent.to_path_buf(),
        source: e,
    })?;
    tmp.write_all(data).map_err(|e| TransactionError::Io {
        path: tmp.path().to_path_buf(),
        source: e,
    })?;
    tmp.as_file().sync_all().map_err(|e| TransactionError::Io {
        path: tmp.path().to_path_buf(),
        source: e,
    })?;
    tmp.persist(path).map_err(|e| TransactionError::Io {
        path: path.to_path_buf(),
        source: e.error,
    })?;

    // Best-effort directory fsync for durability.
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

pub fn backup_existing(path: &Path, backup_dir: &Path) -> Result<Option<PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }
    fs::create_dir_all(backup_dir).map_err(|e| TransactionError::Io {
        path: backup_dir.to_path_buf(),
        source: e,
    })?;
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    let dest = backup_dir.join(format!("{name}.bak"));
    fs::copy(path, &dest).map_err(|e| TransactionError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(Some(dest))
}
