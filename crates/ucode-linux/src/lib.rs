#![forbid(unsafe_code)]

//! Read-only discovery of the host's microcode-relevant state.
//!
//! This crate never mutates the system. On non-Linux hosts every probe returns
//! a structured "unavailable" result so the rest of the stack can still be
//! exercised for inspection and artifact building.

pub mod cpuinfo;
pub mod discover;
pub mod firmware;
pub mod paths;
pub mod sysfs;
pub mod virt;

pub use cpuinfo::{CpuInfoCpu, parse_cpuinfo};
pub use discover::{
    HostCpu, SystemState, discover_system, system_from_cpuinfo_text, system_from_identity,
    with_platform_mask,
};
pub use firmware::{FirmwareTree, probe_firmware_tree};
pub use paths::{default_firmware_paths, default_initrd_candidates};
pub use sysfs::{CpuOnlineState, read_microcode_version};
pub use virt::{
    VirtualizationInfo, VirtualizationKind, detect_virtualization, detect_virtualization_info,
};

use std::path::PathBuf;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, LinuxError>;

#[derive(Debug, Error)]
pub enum LinuxError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("not running on Linux; {0}")]
    NotLinux(&'static str),

    #[error("failed to parse {what}: {reason}")]
    Parse { what: &'static str, reason: String },

    #[error("no CPU information available")]
    NoCpus,
}
