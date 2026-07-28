use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use ucode_core::{CpuIdentity, CpuSignature, PlatformMask, Vendor};

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
}

/// Aggregate system view used by status / plan / match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemState {
    pub cpus: Vec<HostCpu>,
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

    discover_from_cpuid().or_else(|e| {
        debug!(error = %e, "cpuid discovery unavailable");
        Err(if cfg!(target_os = "linux") {
            e
        } else {
            LinuxError::NotLinux("CPU discovery requires /proc/cpuinfo or x86 CPUID")
        })
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
        }],
        unique_identities: vec![identity],
        mixed_signature: false,
        mixed_revision: false,
        virtualization: VirtualizationKind::Unknown,
        virtualization_info: VirtualizationInfo {
            kind: VirtualizationKind::Unknown,
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
        // Prefer sysfs revision when present (more authoritative).
        if let Ok(Some(rev)) = read_microcode_version(info.processor) {
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
        });
    }

    let brand = cpuid_brand_string();
    if let Some(ref b) = brand {
        for c in &mut cpus {
            c.brand = Some(b.clone());
        }
    }

    Ok(finalise(cpus, "proc".to_string()))
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
        let cpus = vec![HostCpu {
            processor: 0,
            identity,
            online: CpuOnlineState::Online,
            physical_id: Some(0),
            core_id: Some(0),
            brand,
        }];
        return Ok(finalise(cpus, "cpuid".to_string()));
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
        return CpuId::new()
            .get_processor_brand_string()
            .map(|b| b.as_str().trim().to_string())
            .filter(|s| !s.is_empty());
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        None
    }
}

fn finalise(cpus: Vec<HostCpu>, source: String) -> SystemState {
    let mut sigs: BTreeSet<(Vendor, u32)> = BTreeSet::new();
    let mut revs: BTreeSet<Option<u32>> = BTreeSet::new();
    let mut unique: Vec<CpuIdentity> = Vec::new();

    for c in &cpus {
        sigs.insert((c.identity.vendor, c.identity.signature.raw()));
        revs.insert(c.identity.current_revision);
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
        cpus,
    }
}

/// Parse cpuinfo text into a system state (tests / offline analysis).
pub fn system_from_cpuinfo_text(text: &str) -> Result<SystemState> {
    let infos: Vec<CpuInfoCpu> = parse_cpuinfo(text)?;
    let cpus = infos
        .into_iter()
        .map(|info| HostCpu {
            processor: info.processor,
            identity: info.to_identity(),
            online: CpuOnlineState::Online,
            physical_id: info.physical_id,
            core_id: info.core_id,
            brand: None,
        })
        .collect();
    Ok(finalise(cpus, "cpuinfo-text".to_string()))
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
