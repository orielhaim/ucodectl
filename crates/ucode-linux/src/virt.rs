//! Virtualization detection that distinguishes real *guests* from bare metal
//! and from type-1 hypervisor *hosts* (notably Hyper-V root on Windows).
//!
//! ## Why a naive "hypervisor CPUID bit" check is wrong
//!
//! `CPUID.1:ECX[31]` ("hypervisor present") is set on many **physical**
//! machines that run a type-1 hypervisor under the OS:
//!
//! - Windows with Hyper-V / WSL2 / VBS / Core Isolation / Credential Guard
//! - Xen dom0 / similar hosts
//!
//! Treating that bit alone as "this is a VM" misclassifies ordinary laptops
//! (including AMD Ryzen systems under Windows) as guests whose microcode is
//! "host-managed".
//!
//! We therefore:
//! 1. Prefer explicit guest DMI product names when available (Linux sysfs).
//! 2. When a hypervisor is present, identify the vendor (leaf `0x40000000`)
//!    and, for Hyper-V, the CreatePartitions privilege (root vs guest).
//! 3. Never treat the bare hypervisor bit as sufficient proof of a guest.

use serde::{Deserialize, Serialize};

/// Detected virtualization / container environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionEnvironment {
    /// Native operating system with no detected hypervisor layer.
    Native,
    /// Windows / Hyper-V parent partition, with physical-device access.
    HypervisorRoot,
    /// Confident guest under a hypervisor; microcode is typically host-managed.
    VirtualMachineGuest,
    Container,
    Unknown,
}

/// Compatibility name used by the existing policy API.
pub type VirtualizationKind = ExecutionEnvironment;

/// The layer that is expected to control active microcode for this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MicrocodeAuthority {
    OperatingSystem,
    FirmwareAndOperatingSystem,
    HypervisorHost,
    FirmwareOnly,
    Unknown,
}

/// Detailed result of virtualization probing (for diagnostics / JSON status).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualizationInfo {
    pub kind: VirtualizationKind,
    pub authority: MicrocodeAuthority,
    /// Short human-readable reason for the decision.
    pub reason: String,
    /// Hypervisor identity (e.g. `HyperV`, `KVM`, `VMware`), if present.
    pub hypervisor_vendor: Option<String>,
    /// True when CPUID.1:ECX\[31\] is set.
    pub hypervisor_bit: bool,
    /// True when we believe this process runs in a Hyper-V *root* partition.
    pub hyperv_root: bool,
}

impl Default for VirtualizationInfo {
    fn default() -> Self {
        Self {
            kind: VirtualizationKind::Unknown,
            authority: MicrocodeAuthority::Unknown,
            reason: "not probed".to_string(),
            hypervisor_vendor: None,
            hypervisor_bit: false,
            hyperv_root: false,
        }
    }
}

/// Best-effort virtualization detection. Never fails hard.
pub fn detect_virtualization() -> VirtualizationKind {
    detect_virtualization_info().kind
}

/// Full diagnostic probe used by discovery and status.
pub fn detect_virtualization_info() -> VirtualizationInfo {
    if is_container() {
        return VirtualizationInfo {
            kind: VirtualizationKind::Container,
            authority: MicrocodeAuthority::Unknown,
            reason: "container markers present (/.dockerenv, cgroup, or $container)".to_string(),
            hypervisor_vendor: None,
            hypervisor_bit: false,
            hyperv_root: false,
        };
    }

    let hv = hypervisor_probe();

    // WSL2 deliberately exposes the physical CPU's Hyper-V CPUID signature,
    // but normally exposes neither the Hyper-V guest DMI product name nor the
    // root-partition CreatePartitions privilege.  It is therefore a known
    // false negative for a DMI + CPUID-only probe.  The Microsoft kernel
    // marker is an explicit guest signal, so handle it before the generic
    // hypervisor logic.
    if let Some(reason) = wsl_guest_signal() {
        return VirtualizationInfo {
            kind: VirtualizationKind::VirtualMachineGuest,
            authority: MicrocodeAuthority::HypervisorHost,
            reason,
            hypervisor_vendor: hv.vendor_label,
            hypervisor_bit: hv.bit,
            hyperv_root: false,
        };
    }

    let dmi_guest = dmi_guest_signal();

    // Strong DMI guest product name always wins.
    if let Some(reason) = dmi_guest {
        return VirtualizationInfo {
            kind: VirtualizationKind::VirtualMachineGuest,
            authority: MicrocodeAuthority::HypervisorHost,
            reason,
            hypervisor_vendor: hv.vendor_label.clone(),
            hypervisor_bit: hv.bit,
            hyperv_root: hv.hyperv_root,
        };
    }

    if !hv.bit {
        return VirtualizationInfo {
            kind: VirtualizationKind::Native,
            authority: MicrocodeAuthority::FirmwareAndOperatingSystem,
            reason: "no guest DMI markers and no hypervisor present bit".to_string(),
            hypervisor_vendor: None,
            hypervisor_bit: false,
            hyperv_root: false,
        };
    }

    // Hypervisor present - classify carefully.
    if hv.hyperv_root {
        return VirtualizationInfo {
            kind: VirtualizationKind::HypervisorRoot,
            authority: MicrocodeAuthority::FirmwareAndOperatingSystem,
            reason: "Hyper-V root partition (type-1 host on physical hardware; \
                     common with Windows VBS/WSL2/Hyper-V enabled)"
                .to_string(),
            hypervisor_vendor: hv.vendor_label,
            hypervisor_bit: true,
            hyperv_root: true,
        };
    }

    if hv.is_guest_vendor {
        return VirtualizationInfo {
            kind: VirtualizationKind::VirtualMachineGuest,
            authority: MicrocodeAuthority::HypervisorHost,
            reason: format!(
                "guest hypervisor identity {:?}",
                hv.vendor_label.as_deref().unwrap_or("unknown")
            ),
            hypervisor_vendor: hv.vendor_label,
            hypervisor_bit: true,
            hyperv_root: false,
        };
    }

    // A hypervisor is definitely present but this process is neither a known
    // guest nor a root partition. Do not relabel that uncertainty as native.
    VirtualizationInfo {
        kind: VirtualizationKind::Unknown,
        authority: MicrocodeAuthority::Unknown,
        reason: format!(
            "hypervisor present ({:?}) but partition role is not known",
            hv.vendor_label.as_deref().unwrap_or("no vendor id")
        ),
        hypervisor_vendor: hv.vendor_label,
        hypervisor_bit: true,
        hyperv_root: false,
    }
}

fn is_container() -> bool {
    if std::path::Path::new("/.dockerenv").exists() {
        return true;
    }
    if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
        let c = cgroup.to_ascii_lowercase();
        if c.contains("docker")
            || c.contains("/lxc/")
            || c.contains("kubepods")
            || c.contains("containerd")
        {
            return true;
        }
    }
    if let Ok(env) = std::env::var("container")
        && !env.is_empty()
    {
        return true;
    }
    false
}

/// Detect WSL from Linux-kernel markers, which are authoritative inside a WSL
/// distribution and do not depend on DMI being virtualized correctly.
fn wsl_guest_signal() -> Option<String> {
    if !cfg!(target_os = "linux") {
        return None;
    }

    let osrelease = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let version = std::fs::read_to_string("/proc/version")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let env_marker =
        std::env::var_os("WSL_INTEROP").is_some() || std::env::var_os("WSL_DISTRO_NAME").is_some();

    wsl_guest_reason(&osrelease, &version, env_marker)
}

fn wsl_guest_reason(osrelease: &str, version: &str, env_marker: bool) -> Option<String> {
    let release = osrelease.to_ascii_lowercase();
    let kernel_version = version.to_ascii_lowercase();
    if release.contains("microsoft-standard-wsl") {
        return Some(
            "WSL2 guest detected from the Microsoft WSL kernel; microcode is managed by the Windows/Hyper-V host"
                .to_string(),
        );
    }
    if release.contains("microsoft") || kernel_version.contains("microsoft") {
        return Some(
            "WSL guest detected from the Microsoft Linux kernel; microcode is managed by the Windows host"
                .to_string(),
        );
    }
    if env_marker {
        return Some(
            "WSL guest detected from WSL environment markers; microcode is managed by the Windows host"
                .to_string(),
        );
    }
    None
}

/// Returns `Some(reason)` only for *strong* guest DMI signals.
///
/// Deliberately does **not** treat `sys_vendor == "Microsoft Corporation"` alone
/// as a VM - that string appears on physical Surface devices and is useless
/// under Hyper-V root.
fn dmi_guest_signal() -> Option<String> {
    let product = read_dmi("product_name").unwrap_or_default();
    let vendor = read_dmi("sys_vendor").unwrap_or_default();
    let board = read_dmi("board_name").unwrap_or_default();
    let p = product.to_ascii_lowercase();
    let v = vendor.to_ascii_lowercase();
    let b = board.to_ascii_lowercase();

    let product_markers = [
        "virtual machine", // Hyper-V *guest* product_name
        "virtualbox",
        "vbox",
        "vmware",
        "kvm",
        "bochs",
        "openstack",
        "google compute engine",
        "amazon ec2",
        "standard pc (i440fx",
        "standard pc (q35",
        "q35 +",
        "parallels virtual platform",
        "hvm domu",
    ];

    for m in product_markers {
        if p.contains(m) || b.contains(m) {
            return Some(format!(
                "DMI product/board indicates guest ({product:?} / {board:?})"
            ));
        }
    }

    let vendor_markers = [
        ("qemu", "QEMU"),
        ("innotek", "VirtualBox (innotek)"),
        ("vmware", "VMware"),
        ("xen", "Xen"),
        ("parallels", "Parallels"),
        ("bochs", "Bochs"),
        ("nutanix", "Nutanix"),
    ];
    for (needle, label) in vendor_markers {
        if v.contains(needle) {
            return Some(format!("DMI sys_vendor indicates {label} ({vendor:?})"));
        }
    }

    None
}

struct HvProbe {
    bit: bool,
    vendor_label: Option<String>,
    hyperv_root: bool,
    is_guest_vendor: bool,
}

fn hypervisor_probe() -> HvProbe {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        use raw_cpuid::{CpuId, Hypervisor};

        let cpuid = CpuId::new();
        let bit = cpuid
            .get_feature_info()
            .map(|fi| fi.has_hypervisor())
            .unwrap_or(false);

        if !bit {
            return HvProbe {
                bit: false,
                vendor_label: None,
                hyperv_root: false,
                is_guest_vendor: false,
            };
        }

        let identity = cpuid.get_hypervisor_info().map(|h| h.identify());
        let vendor_label = identity.as_ref().map(|id| format!("{id:?}"));

        let (hyperv_root, is_guest_vendor) = match identity {
            Some(Hypervisor::HyperV) => {
                let root = hyperv_create_partitions();
                // Root → host. Guest → guest. If we cannot read the feature
                // leaf, on Windows assume root (VBS/Hyper-V host is the common
                // case for physical laptops); on Linux assume guest only when
                // DMI already said so (handled earlier).
                if root {
                    (true, false)
                } else if cfg!(windows) {
                    // No CreatePartitions bit: could be a real Hyper-V guest
                    // on Windows, OR an incomplete leaf. Prefer bare metal on
                    // Windows without DMI guest product - false VM is worse.
                    // Real Hyper-V guests almost always have product_name
                    // "Virtual Machine" which we already checked.
                    (false, false)
                } else {
                    // Linux with Microsoft Hv and no DMI guest mark is rare
                    // (WSL1-like / nested). Don't claim guest without DMI.
                    (false, false)
                }
            }
            Some(
                Hypervisor::KVM
                | Hypervisor::VMware
                | Hypervisor::Xen
                | Hypervisor::QEMU
                | Hypervisor::Bhyve
                | Hypervisor::QNX
                | Hypervisor::ACRN,
            ) => (false, true),
            Some(Hypervisor::Unknown(_, _, _)) => (false, false),
            None => (false, false),
        };

        HvProbe {
            bit: true,
            vendor_label,
            hyperv_root,
            is_guest_vendor,
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        HvProbe {
            bit: false,
            vendor_label: None,
            hyperv_root: false,
            is_guest_vendor: false,
        }
    }
}

/// Hyper-V feature leaf `0x40000003`: EBX bit 0 = CreatePartitions (root only).
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn hyperv_create_partitions() -> bool {
    use raw_cpuid::cpuid;
    let max = cpuid!(0x4000_0000u32).eax;
    if max < 0x4000_0003 {
        // Incomplete hypervisor leaves. On Windows this still almost always
        // means root/VBS; treat as root so we don't false-positive as guest.
        return cfg!(windows);
    }
    let feat = cpuid!(0x4000_0003u32);
    (feat.ebx & 1) != 0
}

fn read_dmi(name: &str) -> Option<String> {
    let path = format!("/sys/class/dmi/id/{name}");
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "None")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_does_not_panic() {
        let info = detect_virtualization_info();
        // Must classify as something concrete on x86.
        assert!(matches!(
            info.kind,
            VirtualizationKind::Native
                | VirtualizationKind::HypervisorRoot
                | VirtualizationKind::VirtualMachineGuest
                | VirtualizationKind::Container
                | VirtualizationKind::Unknown
        ));
        assert!(!info.reason.is_empty());
    }

    #[test]
    fn recognizes_wsl2_kernel_without_dmi() {
        let reason = wsl_guest_reason(
            "6.18.33.2-microsoft-standard-WSL2",
            "Linux version 6.18.33.2-microsoft-standard-WSL2",
            false,
        );
        assert!(reason.is_some_and(|r| r.contains("WSL2 guest")));
    }

    #[test]
    fn recognizes_wsl_environment_marker() {
        let reason = wsl_guest_reason("6.12.0-generic", "Linux version 6.12.0", true);
        assert!(reason.is_some_and(|r| r.contains("WSL guest")));
    }

    #[test]
    fn does_not_mistake_regular_linux_for_wsl() {
        assert!(wsl_guest_reason("6.12.0-generic", "Linux version 6.12.0", false).is_none());
    }
}
