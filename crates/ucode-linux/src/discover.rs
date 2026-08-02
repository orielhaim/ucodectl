use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use ucode_core::{
    CpuIdentity, CpuSignature, PlatformMask, RevisionObservation, RevisionSource, Vendor,
};

use crate::cpuinfo::{CpuInfoCpu, parse_cpuinfo, read_cpuinfo};
use crate::firmware::{FirmwareTree, probe_firmware_tree};
use crate::sysfs::{CpuOnlineState, cpu_online_state, read_microcode_version};
use crate::virt::{VirtualizationInfo, VirtualizationKind, detect_virtualization_info};
use crate::{LinuxError, Result};

/// One logical CPU with microcode-relevant fields filled in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCpu {
    pub processor: u32,
    pub identity: CpuIdentity,
    pub online: CpuOnlineState,
    pub physical_id: Option<u32>,
    pub core_id: Option<u32>,
    pub brand: Option<String>,
    /// Active microcode observation with source and availability semantics.
    pub revision: RevisionObservation,
}

/// Windows registry metadata whose scope is the system rather than one CPU.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsMicrocodeMetadata {
    pub current_revision: Option<RevisionObservation>,
    pub previous_revision: Option<RevisionObservation>,
    /// Number of processor registry keys that exposed `Previous Update Revision`.
    pub registry_keys_observed: usize,
    pub logical_processor_count: usize,
}

/// Aggregate system view used by status / plan / match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemState {
    pub cpus: Vec<HostCpu>,
    pub windows_microcode: Option<WindowsMicrocodeMetadata>,
    /// Distinct CPU identities across the system (signature + platform).
    pub unique_identities: Vec<CpuIdentity>,
    pub mixed_signature: bool,
    pub mixed_revision: bool,
    pub virtualization: VirtualizationKind,
    pub virtualization_info: VirtualizationInfo,
    pub firmware: FirmwareTree,
    /// Kernel release string when available.
    pub kernel_release: Option<String>,
    /// Whether any CPU is offline.
    pub has_offline_cpus: bool,
    /// Source of the discovery (`proc`, `cpuid`, `manual`, …).
    pub source: String,
    pub os: String,
}

impl SystemState {
    /// Representative identity for selection (first online CPU, else first).
    pub fn primary_cpu(&self) -> Option<&HostCpu> {
        self.cpus
            .iter()
            .find(|c| c.online == CpuOnlineState::Online)
            .or_else(|| self.cpus.first())
    }

    pub fn primary_identity(&self) -> Option<&CpuIdentity> {
        self.primary_cpu().map(|c| &c.identity)
    }

    pub fn vendors(&self) -> Vec<Vendor> {
        let mut v: Vec<Vendor> = self.cpus.iter().map(|c| c.identity.vendor).collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

/// Discover the local system. Falls back gracefully off Linux.
pub fn discover_system() -> Result<SystemState> {
    if cfg!(target_os = "linux") {
        match discover_from_proc() {
            Ok(s) => return Ok(s),
            Err(e) => {
                warn!(error = %e, "proc discovery failed; trying CPUID");
            }
        }
    }

    discover_from_cpuid().map_err(|e| {
        debug!(error = %e, "cpuid discovery unavailable");
        if cfg!(target_os = "linux") {
            e
        } else {
            LinuxError::NotLinux("CPU discovery requires /proc/cpuinfo or x86 CPUID")
        }
    })
}

/// Build a system state from an explicit identity (for offline workflows).
pub fn system_from_identity(identity: CpuIdentity) -> SystemState {
    SystemState {
        cpus: vec![HostCpu {
            processor: 0,
            identity: identity.clone(),
            online: CpuOnlineState::Online,
            physical_id: Some(0),
            core_id: Some(0),
            brand: None,
            revision: RevisionObservation::unavailable(
                RevisionSource::Manual,
                "manual identity does not include an active microcode revision",
            ),
        }],
        windows_microcode: None,
        unique_identities: vec![identity],
        mixed_signature: false,
        mixed_revision: false,
        virtualization: VirtualizationKind::Unknown,
        virtualization_info: VirtualizationInfo {
            kind: VirtualizationKind::Unknown,
            authority: crate::MicrocodeAuthority::Unknown,
            reason: "manual identity; virtualization not probed".to_string(),
            hypervisor_vendor: None,
            hypervisor_bit: false,
            hyperv_root: false,
        },
        firmware: FirmwareTree::default(),
        kernel_release: None,
        has_offline_cpus: false,
        source: "manual".to_string(),
        os: std::env::consts::OS.to_string(),
    }
}

fn discover_from_proc() -> Result<SystemState> {
    let infos = read_cpuinfo(Path::new("/proc/cpuinfo"))?;
    let mut cpus = Vec::with_capacity(infos.len());

    for info in &infos {
        let mut identity = info.to_identity();
        let mut revision = revision_from_proc(info.microcode);
        // Prefer sysfs revision when present (more authoritative).
        if let Ok(Some(rev)) = read_microcode_version(info.processor) {
            identity.current_revision = Some(rev);
            revision = RevisionObservation::known(rev, RevisionSource::LinuxSysfs);
        } else if let Some(rev) = revision.known_revision() {
            identity.current_revision = Some(rev);
        }
        let online = cpu_online_state(info.processor);
        cpus.push(HostCpu {
            processor: info.processor,
            identity,
            online,
            physical_id: info.physical_id,
            core_id: info.core_id,
            brand: None,
            revision,
        });
    }

    let brand = cpuid_brand_string();
    if let Some(ref b) = brand {
        for c in &mut cpus {
            c.brand = Some(b.clone());
        }
    }

    Ok(finalise(cpus, "proc".to_string(), None))
}

fn discover_from_cpuid() -> Result<SystemState> {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        use raw_cpuid::CpuId;
        let cpuid = CpuId::new();
        let vendor_str = cpuid
            .get_vendor_info()
            .map(|v| v.as_str().to_string())
            .unwrap_or_default();
        let vendor = Vendor::from_cpuid_string(&vendor_str).ok_or(LinuxError::NoCpus)?;
        let fi = cpuid.get_feature_info().ok_or(LinuxError::NoCpus)?;
        // raw-cpuid returns display family/model already folded.
        let family = fi.family_id() as u32;
        let model = fi.model_id() as u32;
        let stepping = fi.stepping_id() as u32;
        let signature = CpuSignature::from_fms(vendor, family, model, stepping);

        // Prefer the raw CPUID.1:EAX signature when it round-trips; raw leaf is
        // the authoritative processor signature used by microcode matching.
        let raw_eax = {
            use raw_cpuid::cpuid;
            cpuid!(1u32).eax
        };
        let signature = if CpuSignature(raw_eax).family() == family
            && CpuSignature(raw_eax).model_for(vendor) == model
            && CpuSignature(raw_eax).stepping() == stepping
        {
            CpuSignature(raw_eax)
        } else {
            signature
        };

        let identity = CpuIdentity::new(vendor, signature);
        let brand = cpuid
            .get_processor_brand_string()
            .map(|b| b.as_str().trim().to_string())
            .filter(|s| !s.is_empty());
        #[cfg(windows)]
        let count = ucode_windows::logical_processor_count().max(1);
        #[cfg(not(windows))]
        let count = 1;
        let mut cpus = Vec::with_capacity(count);
        #[cfg(windows)]
        let system_revision = ucode_windows::update_revision(0).with_scope_confidence(
            ucode_core::ObservationScope::System,
            ucode_core::ObservationConfidence::Reported,
        );
        #[cfg(windows)]
        let system_previous_revision = ucode_windows::previous_update_revision(0).map(|value| {
            value.with_scope_confidence(
                ucode_core::ObservationScope::System,
                ucode_core::ObservationConfidence::Reported,
            )
        });
        for processor in 0..count as u32 {
            #[cfg(windows)]
            let revision = system_revision.clone();
            #[cfg(not(windows))]
            let revision = RevisionObservation::unavailable(
                RevisionSource::Unavailable,
                "no active microcode revision source is available off Linux/Windows",
            );
            let mut cpu_identity = identity.clone();
            cpu_identity.current_revision = revision.known_revision();
            cpus.push(HostCpu {
                processor,
                identity: cpu_identity,
                online: CpuOnlineState::Online,
                physical_id: None,
                core_id: None,
                brand: brand.clone(),
                revision,
            });
        }
        #[cfg(windows)]
        let windows_microcode = Some(WindowsMicrocodeMetadata {
            current_revision: Some(system_revision),
            previous_revision: system_previous_revision,
            registry_keys_observed: 1,
            logical_processor_count: count,
        });
        #[cfg(not(windows))]
        let windows_microcode = None;
        Ok(finalise(cpus, "cpuid".to_string(), windows_microcode))
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        Err(LinuxError::NoCpus)
    }
}

fn cpuid_brand_string() -> Option<String> {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        use raw_cpuid::CpuId;
        CpuId::new()
            .get_processor_brand_string()
            .map(|b| b.as_str().trim().to_string())
            .filter(|s| !s.is_empty())
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        None
    }
}

fn finalise(
    cpus: Vec<HostCpu>,
    source: String,
    windows_microcode: Option<WindowsMicrocodeMetadata>,
) -> SystemState {
    let mut sigs: BTreeSet<(Vendor, u32)> = BTreeSet::new();
    let mut revs: BTreeSet<u32> = BTreeSet::new();
    let mut unique: Vec<CpuIdentity> = Vec::new();

    for c in &cpus {
        sigs.insert((c.identity.vendor, c.identity.signature.raw()));
        if let Some(revision) = c.revision.known_revision() {
            revs.insert(revision);
        }
        if !unique.iter().any(|u| {
            u.vendor == c.identity.vendor
                && u.signature == c.identity.signature
                && u.platform_mask == c.identity.platform_mask
        }) {
            unique.push(c.identity.clone());
        }
    }

    let has_offline = cpus.iter().any(|c| c.online == CpuOnlineState::Offline);
    let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string());

    let virt = detect_virtualization_info();

    SystemState {
        mixed_signature: sigs.len() > 1,
        mixed_revision: revs.len() > 1,
        unique_identities: unique,
        virtualization: virt.kind,
        virtualization_info: virt,
        firmware: if cfg!(target_os = "linux") {
            probe_firmware_tree()
        } else {
            FirmwareTree::default()
        },
        kernel_release,
        has_offline_cpus: has_offline,
        source,
        os: std::env::consts::OS.to_string(),
        windows_microcode,
        cpus,
    }
}

fn revision_from_proc(value: Option<u32>) -> RevisionObservation {
    match value {
        Some(u32::MAX) => RevisionObservation::unavailable(
            RevisionSource::ProcCpuinfo,
            "kernel reported sentinel 0xffffffff; the active revision is hidden or virtualized by the host",
        ),
        Some(revision) => RevisionObservation::known(revision, RevisionSource::ProcCpuinfo),
        None => RevisionObservation::unavailable(
            RevisionSource::ProcCpuinfo,
            "/proc/cpuinfo does not report a microcode revision",
        ),
    }
}

/// Parse cpuinfo text into a system state (tests / offline analysis).
pub fn system_from_cpuinfo_text(text: &str) -> Result<SystemState> {
    let infos: Vec<CpuInfoCpu> = parse_cpuinfo(text)?;
    let cpus = infos
        .into_iter()
        .map(|info| HostCpu {
            processor: info.processor,
            identity: {
                let mut identity = info.to_identity();
                identity.current_revision = revision_from_proc(info.microcode).known_revision();
                identity
            },
            online: CpuOnlineState::Online,
            physical_id: info.physical_id,
            core_id: info.core_id,
            brand: None,
            revision: revision_from_proc(info.microcode),
        })
        .collect();
    Ok(finalise(cpus, "cpuinfo-text".to_string(), None))
}

/// Attach a platform mask to every Intel CPU that lacks one.
pub fn with_platform_mask(mut state: SystemState, mask: PlatformMask) -> SystemState {
    for cpu in &mut state.cpus {
        if cpu.identity.vendor == Vendor::Intel && cpu.identity.platform_mask.is_none() {
            cpu.identity.platform_mask = Some(mask);
        }
    }
    for id in &mut state.unique_identities {
        if id.vendor == Vendor::Intel && id.platform_mask.is_none() {
            id.platform_mask = Some(mask);
        }
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_sentinel_is_not_a_revision() {
        let observation = revision_from_proc(Some(u32::MAX));
        assert_eq!(observation.known_revision(), None);
        assert!(matches!(
            observation,
            RevisionObservation::Unavailable { .. }
        ));
    }
}
