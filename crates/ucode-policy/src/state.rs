use serde::{Deserialize, Serialize};
use ucode_core::{CpuIdentity, PatchMeta};
use ucode_linux::SystemState;

/// High-level status returned by `ucodectl status` / `plan`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemStatus {
    /// Running revision equals best available; boot artifact matches (or no boot check).
    UpToDate,
    /// A newer patch is installed in firmware but will not be active until reboot
    /// with an updated early image.
    InstalledButNotBootable,
    /// The early CPIO / UKI embeds older microcode than firmware provides.
    BootArtifactOutdated,
    /// Firmware has a newer revision than what is currently running.
    RebootRequired,
    /// No patch in the catalog applies to this CPU.
    NoCompatiblePatch,
    /// Multiple conflicting patches share the best revision.
    AmbiguousMatch,
    /// Selected patch would lower the running revision.
    UnsafeDowngrade,
    /// CPUs in the system have different signatures or revisions.
    MixedCpuConfiguration,
    /// Available firmware is older than the BIOS-loaded revision.
    FirmwareOlderThanBios,
    /// Guest VM; microcode is expected to be host-managed.
    VirtualMachineHostManaged,
    /// Structural validity is fine but provenance was not verified.
    SignatureUnverified,
    /// Patch is not eligible for runtime (late) update given current revision.
    RuntimeUpdateUnsupported,
    /// Platform ID unknown; selection cannot proceed safely for Intel.
    PlatformIdUnknown,
    /// Not enough information to decide.
    Unknown,
}

impl SystemStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UpToDate => "up_to_date",
            Self::InstalledButNotBootable => "installed_but_not_bootable",
            Self::BootArtifactOutdated => "boot_artifact_outdated",
            Self::RebootRequired => "reboot_required",
            Self::NoCompatiblePatch => "no_compatible_patch",
            Self::AmbiguousMatch => "ambiguous_match",
            Self::UnsafeDowngrade => "unsafe_downgrade",
            Self::MixedCpuConfiguration => "mixed_cpu_configuration",
            Self::FirmwareOlderThanBios => "firmware_older_than_bios",
            Self::VirtualMachineHostManaged => "virtual_machine_host_managed",
            Self::SignatureUnverified => "signature_unverified",
            Self::RuntimeUpdateUnsupported => "runtime_update_unsupported",
            Self::PlatformIdUnknown => "platform_id_unknown",
            Self::Unknown => "unknown",
        }
    }
}

/// Per-CPU evaluation snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuEvaluation {
    pub processor: u32,
    pub identity: CpuIdentity,
    pub status: SystemStatus,
    pub running_revision: Option<u32>,
    pub best_available_revision: Option<u32>,
    pub embedded_revision: Option<u32>,
    pub best_patch: Option<PatchMeta>,
    pub reasons: Vec<String>,
}

/// Summarise system-level concerns from host state alone.
///
/// Virtualization is **not** pushed here as a status concern that overrides
/// patch evaluation — it is reported separately via messages / overall logic.
pub fn host_concerns(system: &SystemState) -> Vec<SystemStatus> {
    let mut out = Vec::new();
    if system.mixed_signature || system.mixed_revision {
        out.push(SystemStatus::MixedCpuConfiguration);
    }
    out
}
