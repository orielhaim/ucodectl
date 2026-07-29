use serde::{Deserialize, Serialize};
use ucode_catalog::Catalog;
use ucode_core::{CpuIdentity, Vendor};
use ucode_linux::{SystemState, VirtualizationKind};

use crate::state::{CpuEvaluation, SystemStatus, host_concerns};

/// Inputs to the decision engine.
#[derive(Debug, Clone)]
pub struct PlanInput<'a> {
    pub system: &'a SystemState,
    /// Firmware / release catalog of available patches.
    pub available: &'a Catalog,
    /// Patches currently embedded in the boot artifact (initrd/UKI), if known.
    pub embedded: Option<&'a Catalog>,
    /// Allow selecting a revision lower than currently running.
    pub allow_downgrade: bool,
    /// When true, emit write actions for early CPIO generation.
    pub want_early_image: bool,
    /// Destination path for a generated early CPIO (advisory; transaction uses it).
    pub early_output: Option<String>,
}

/// A single concrete write the transaction layer may perform.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PlannedWrite {
    /// Write a complete early-load CPIO to `path`.
    EarlyCpio {
        path: String,
        intel_patches: usize,
        amd_patches: usize,
    },
    /// Write individual Intel firmware files under a directory.
    IntelFirmwareDir { dir: String, file_count: usize },
    /// Write an AMD container under a directory.
    AmdFirmwareDir { dir: String, file_count: usize },
}

/// High-level recommended action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    None,
    RebuildEarlyImage,
    InstallFirmwareAndRebuildEarly,
    Reboot,
    InvestigateAmbiguity,
    NoOpVirtualMachine,
}

/// Full explained plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub plan_version: u32,
    pub overall_status: SystemStatus,
    pub action: Action,
    pub cpus: Vec<CpuEvaluation>,
    pub writes: Vec<PlannedWrite>,
    pub messages: Vec<String>,
    /// True when apply would change the system.
    pub would_change: bool,
}

/// Evaluate the current situation and produce a plan. Pure function.
pub fn evaluate(input: &PlanInput<'_>) -> Plan {
    let mut messages = Vec::new();
    let mut cpus = Vec::new();
    let concerns = host_concerns(input.system);

    for host_cpu in &input.system.cpus {
        cpus.push(evaluate_cpu(
            host_cpu.processor,
            &host_cpu.identity,
            input.available,
            input.embedded,
            input.allow_downgrade,
        ));
    }

    // If no CPUs discovered, still try primary unique identities.
    if cpus.is_empty() {
        for (i, id) in input.system.unique_identities.iter().enumerate() {
            cpus.push(evaluate_cpu(
                i as u32,
                id,
                input.available,
                input.embedded,
                input.allow_downgrade,
            ));
        }
    }

    let overall = overall_status(&cpus, &concerns, input.system);
    let mut writes = Vec::new();
    let mut action = Action::None;
    let mut would_change = false;

    // Virtualization is an advisory signal, never a hard override of patch status.
    if input.system.virtualization == VirtualizationKind::VirtualMachineGuest {
        messages.push(format!(
            "guest virtualization detected ({}); microcode is often managed by the hypervisor host",
            input.system.virtualization_info.reason
        ));
        if overall == SystemStatus::VirtualMachineHostManaged {
            action = Action::NoOpVirtualMachine;
        }
    } else if input.system.virtualization == VirtualizationKind::HypervisorRoot {
        messages.push(format!(
            "Hyper-V root partition detected ({}); this is a normal Windows host configuration",
            input.system.virtualization_info.reason
        ));
    }

    if input.system.os != "linux" {
        messages.push(format!(
            "running on {}; microcode early-load paths and sysfs revisions are Linux-specific — \
CPU identity comes from CPUID; pass firmware with --source / path arguments to evaluate patches",
            input.system.os
        ));
    }

    if overall == SystemStatus::AmbiguousMatch {
        action = Action::InvestigateAmbiguity;
        messages.push(
            "conflicting patches share the best revision; refuse to choose automatically"
                .to_string(),
        );
    } else if overall == SystemStatus::Unknown && input.available.is_empty() {
        messages.push(
            "no microcode catalog loaded (no firmware sources found); \
pass a release tree or use --source"
                .to_string(),
        );
    } else if overall == SystemStatus::NoCompatiblePatch {
        messages.push("no compatible microcode patch found in the available catalog".to_string());
    } else if overall == SystemStatus::PlatformIdUnknown {
        messages.push(
            "Intel platform ID is unknown; pass --platform-id or load from a context that provides it"
                .to_string(),
        );
    } else {
        let needs_newer_firmware = cpus.iter().any(|c| {
            matches!(
                c.status,
                SystemStatus::RebootRequired
                    | SystemStatus::InstalledButNotBootable
                    | SystemStatus::BootArtifactOutdated
                    | SystemStatus::FirmwareOlderThanBios
            )
        });
        let boot_stale = cpus.iter().any(|c| {
            matches!(
                c.status,
                SystemStatus::BootArtifactOutdated | SystemStatus::InstalledButNotBootable
            )
        }) || input.embedded.is_none() && input.want_early_image;

        if input.want_early_image || boot_stale {
            let path = input
                .early_output
                .clone()
                .unwrap_or_else(|| "ucode-early.cpio".to_string());
            let intel = count_selected(input.available, &cpus, Vendor::Intel);
            let amd = count_selected(input.available, &cpus, Vendor::Amd);
            if intel + amd > 0 {
                writes.push(PlannedWrite::EarlyCpio {
                    path,
                    intel_patches: intel,
                    amd_patches: amd,
                });
                would_change = true;
                action = if needs_newer_firmware {
                    Action::InstallFirmwareAndRebuildEarly
                } else {
                    Action::RebuildEarlyImage
                };
                messages.push(
                    "rebuild the early microcode CPIO and integrate it into the initrd/UKI via distro tooling"
                        .to_string(),
                );
            }
        }

        if matches!(
            overall,
            SystemStatus::RebootRequired | SystemStatus::InstalledButNotBootable
        ) && action == Action::None
        {
            action = Action::Reboot;
            messages.push(
                "a reboot with an updated early image is required for the new microcode to load"
                    .to_string(),
            );
        }

        if overall == SystemStatus::UpToDate {
            messages.push("running microcode matches the best available patch".to_string());
        }
    }

    for c in &concerns {
        if *c == SystemStatus::MixedCpuConfiguration {
            messages.push(
                "mixed CPU signature or microcode revision detected across logical CPUs"
                    .to_string(),
            );
        }
    }

    Plan {
        plan_version: 1,
        overall_status: overall,
        action,
        cpus,
        writes,
        messages,
        would_change,
    }
}

fn evaluate_cpu(
    processor: u32,
    identity: &CpuIdentity,
    available: &Catalog,
    embedded: Option<&Catalog>,
    allow_downgrade: bool,
) -> CpuEvaluation {
    let mut reasons = Vec::new();
    let selection = available.select(identity);

    if identity.vendor == Vendor::Intel && identity.platform_mask.is_none() {
        // Retry with a synthetic "unknown platform" explanation.
        let any_sig = available.patches.iter().any(|p| {
            p.vendor == Vendor::Intel
                && p.is_loadable()
                && p.matches.iter().any(|m| m.signature == identity.signature)
        });
        if any_sig {
            reasons
                .push("Intel platform ID unknown; cannot safely match platform flags".to_string());
            return CpuEvaluation {
                processor,
                identity: identity.clone(),
                status: SystemStatus::PlatformIdUnknown,
                running_revision: identity.current_revision,
                best_available_revision: None,
                embedded_revision: embedded_rev(embedded, identity),
                best_patch: None,
                reasons,
            };
        }
    }

    if selection.is_ambiguous() {
        reasons.push("multiple distinct patches share the highest revision".to_string());
        return CpuEvaluation {
            processor,
            identity: identity.clone(),
            status: SystemStatus::AmbiguousMatch,
            running_revision: identity.current_revision,
            best_available_revision: selection.best.map(|p| p.revision),
            embedded_revision: embedded_rev(embedded, identity),
            best_patch: selection.best.cloned(),
            reasons,
        };
    }

    let best = selection.best;
    let best_rev = best.map(|p| p.revision);
    let emb_rev = embedded_rev(embedded, identity);
    let running = identity.current_revision;

    let status = match (running, best_rev, emb_rev) {
        (_, None, _) if available.is_empty() => {
            reasons.push("no firmware catalog loaded".to_string());
            SystemStatus::Unknown
        }
        (_, None, _) => {
            reasons.push("no applicable patch in available catalog".to_string());
            SystemStatus::NoCompatiblePatch
        }
        (Some(run), Some(best_r), _) if best_r < run && !allow_downgrade => {
            reasons.push(format!(
                "best available 0x{best_r:08x} is older than running 0x{run:08x}"
            ));
            SystemStatus::FirmwareOlderThanBios
        }
        (Some(run), Some(best_r), _) if best_r < run && allow_downgrade => {
            reasons.push("downgrade explicitly allowed".to_string());
            SystemStatus::UnsafeDowngrade
        }
        (Some(run), Some(best_r), emb) if best_r > run => {
            reasons.push(format!(
                "running 0x{run:08x}, best available 0x{best_r:08x}"
            ));
            match emb {
                Some(e) if e < best_r => {
                    reasons.push(format!("boot artifact embeds 0x{e:08x}, which is outdated"));
                    SystemStatus::BootArtifactOutdated
                }
                Some(e) if e >= best_r => {
                    reasons.push(
                        "boot artifact already has the newer image; reboot required".to_string(),
                    );
                    SystemStatus::RebootRequired
                }
                None => {
                    reasons.push("boot artifact not inspected".to_string());
                    SystemStatus::InstalledButNotBootable
                }
                _ => SystemStatus::RebootRequired,
            }
        }
        (Some(run), Some(best_r), emb) if best_r == run => match emb {
            Some(e) if e < best_r => {
                reasons.push(format!(
                    "running is current but boot artifact embeds older 0x{e:08x}"
                ));
                SystemStatus::BootArtifactOutdated
            }
            _ => {
                reasons.push("running revision matches best available".to_string());
                SystemStatus::UpToDate
            }
        },
        (None, Some(best_r), emb) => {
            reasons.push(format!(
                "running revision unknown; best available 0x{best_r:08x}"
            ));
            match emb {
                Some(e) if e < best_r => SystemStatus::BootArtifactOutdated,
                Some(_) => SystemStatus::Unknown,
                None => SystemStatus::Unknown,
            }
        }
        _ => SystemStatus::Unknown,
    };

    // Runtime-update gate annotation (informational; we do not late-load).
    if let (Some(run), Some(patch)) = (running, best) {
        if let Some(false) = patch.runtime_update_allowed_from(run) {
            reasons.push(format!(
                "runtime update to 0x{:08x} requires base revision ≥ 0x{:08x}",
                patch.revision,
                match patch.runtime_update {
                    ucode_core::RuntimeUpdatePolicy::RequiresBaseRevision(v) => v,
                    _ => 0,
                }
            ));
        }
        if let Some(false) = patch.base_revision_satisfied(run) {
            reasons.push(format!(
                "AMD minimum base revision 0x{:08x} not satisfied by running 0x{run:08x}",
                patch.min_base_revision.unwrap_or(0)
            ));
        }
    }

    CpuEvaluation {
        processor,
        identity: identity.clone(),
        status,
        running_revision: running,
        best_available_revision: best_rev,
        embedded_revision: emb_rev,
        best_patch: best.cloned(),
        reasons,
    }
}

fn embedded_rev(embedded: Option<&Catalog>, identity: &CpuIdentity) -> Option<u32> {
    let cat = embedded?;
    cat.select(identity).best.map(|p| p.revision)
}

fn overall_status(
    cpus: &[CpuEvaluation],
    concerns: &[SystemStatus],
    system: &SystemState,
) -> SystemStatus {
    // CPU/patch status always wins over virtualization. A false VM positive used
    // to hide real results; even true guests still report per-CPU match state.
    let mut statuses: Vec<SystemStatus> = cpus.iter().map(|c| c.status).collect();
    if concerns.contains(&SystemStatus::MixedCpuConfiguration) {
        statuses.push(SystemStatus::MixedCpuConfiguration);
    }
    // Only surface VirtualMachineHostManaged when we are a confident guest *and*
    // there is no stronger patch-related status (e.g. no catalog loaded).
    let base = priority_status(statuses.into_iter());
    if system.virtualization == VirtualizationKind::VirtualMachineGuest
        && matches!(
            base,
            SystemStatus::Unknown | SystemStatus::NoCompatiblePatch | SystemStatus::UpToDate
        )
        && cpus.iter().all(|c| c.best_available_revision.is_none())
    {
        return SystemStatus::VirtualMachineHostManaged;
    }
    let _ = system;
    base
}

fn priority_status(statuses: impl Iterator<Item = SystemStatus>) -> SystemStatus {
    // Highest priority first.
    const ORDER: &[SystemStatus] = &[
        SystemStatus::AmbiguousMatch,
        SystemStatus::PlatformIdUnknown,
        SystemStatus::NoCompatiblePatch,
        SystemStatus::UnsafeDowngrade,
        SystemStatus::MixedCpuConfiguration,
        SystemStatus::BootArtifactOutdated,
        SystemStatus::InstalledButNotBootable,
        SystemStatus::RebootRequired,
        SystemStatus::FirmwareOlderThanBios,
        SystemStatus::RuntimeUpdateUnsupported,
        SystemStatus::SignatureUnverified,
        SystemStatus::VirtualMachineHostManaged,
        SystemStatus::Unknown,
        SystemStatus::UpToDate,
    ];
    let set: Vec<SystemStatus> = statuses.collect();
    if set.is_empty() {
        return SystemStatus::Unknown;
    }
    for &candidate in ORDER {
        if set.contains(&candidate) {
            return candidate;
        }
    }
    SystemStatus::Unknown
}

fn count_selected(available: &Catalog, cpus: &[CpuEvaluation], vendor: Vendor) -> usize {
    let mut n = 0;
    for c in cpus {
        if c.identity.vendor != vendor {
            continue;
        }
        if c.best_patch.is_some() {
            n += 1;
        }
    }
    // Fall back to counting applicable patches when evaluations lack best_patch.
    if n == 0 {
        n = available
            .patches
            .iter()
            .filter(|p| p.vendor == vendor && p.is_loadable())
            .count()
            .min(1);
        if vendor == Vendor::Intel {
            n = available
                .patches
                .iter()
                .filter(|p| p.vendor == Vendor::Intel && p.is_loadable())
                .count();
        }
    }
    n
}
