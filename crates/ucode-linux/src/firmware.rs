use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::paths::default_firmware_paths;

/// Which firmware trees exist on the host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FirmwareTree {
    pub intel_dirs: Vec<PathBuf>,
    pub amd_dirs: Vec<PathBuf>,
    pub intel_files: usize,
    pub amd_files: usize,
}

/// Probe the default firmware paths and report which ones are present.
pub fn probe_firmware_tree() -> FirmwareTree {
    probe_paths(&default_firmware_paths())
}

pub fn probe_paths(paths: &[PathBuf]) -> FirmwareTree {
    let mut tree = FirmwareTree::default();
    for path in paths {
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let count = count_files(path);
        debug!(path = %path.display(), count, "firmware directory");
        if name.contains("intel") {
            tree.intel_dirs.push(path.clone());
            tree.intel_files += count;
        } else if name.contains("amd") {
            tree.amd_dirs.push(path.clone());
            tree.amd_files += count;
        } else {
            // Generic tree: count both naming conventions.
            tree.intel_dirs.push(path.clone());
            tree.intel_files += count;
        }
    }
    tree
}

fn count_files(dir: &Path) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .count()
}
