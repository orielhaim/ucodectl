use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{LinuxError, Result};

/// Online / offline state of one logical CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuOnlineState {
    Online,
    Offline,
    Unknown,
}

/// Read the currently loaded microcode revision from sysfs.
///
/// Path: `/sys/devices/system/cpu/cpuN/microcode/version`
pub fn read_microcode_version(cpu: u32) -> Result<Option<u32>> {
    let path = PathBuf::from(format!(
        "/sys/devices/system/cpu/cpu{cpu}/microcode/version"
    ));
    read_version_file(&path)
}

pub fn read_version_file(path: &Path) -> Result<Option<u32>> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let s = text.trim();
            let rev = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u32::from_str_radix(hex, 16)
            } else {
                s.parse()
            }
            .map_err(|e| LinuxError::Parse {
                what: "microcode version",
                reason: e.to_string(),
            })?;
            Ok(Some(rev))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => {
            debug!(path = %path.display(), error = %e, "microcode version unreadable");
            Ok(None)
        }
    }
}

/// Whether a logical CPU is online.
pub fn cpu_online_state(cpu: u32) -> CpuOnlineState {
    let path = PathBuf::from(format!("/sys/devices/system/cpu/cpu{cpu}/online"));
    match std::fs::read_to_string(path) {
        Ok(s) => match s.trim() {
            "1" => CpuOnlineState::Online,
            "0" => CpuOnlineState::Offline,
            _ => CpuOnlineState::Unknown,
        },
        // cpu0 often has no `online` file and is always online.
        Err(_) if cpu == 0 => CpuOnlineState::Online,
        Err(_) => CpuOnlineState::Unknown,
    }
}

/// Best-effort Intel platform-id bit from MSR exposure, if the distro ships it.
///
/// Most systems do not expose this without privileged tools; we never invent a
/// value. Returns `None` when unavailable.
pub fn read_platform_id_hint(_cpu: u32) -> Option<u32> {
    // Deliberately not probing MSRs: that requires CAP_SYS_RAWIO and is outside
    // the read-only, unprivileged scope of this crate. Callers that know the
    // platform mask can inject it via CLI flags.
    None
}
