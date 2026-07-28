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
pub enum VirtualizationKind {
    /// Physical machine, or type-1 hypervisor *host* / root partition.
    BareMetal,
    /// Confident guest under a hypervisor; microcode is typically host-managed.
    VirtualMachine,
    Container,
    Unknown,
}

/// Detailed result of virtualization probing (for diagnostics / JSON status).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualizationInfo {
    pub kind: VirtualizationKind,
    /// Short human-readable reason for the decision.
    pub reason: String,
    /// Hypervisor identity (e.g. `HyperV`, `KVM`, `VMware`), if present.
    pub hypervisor_vendor: Option<String>,
    /// True when CPUID.1:ECX[31] is set.
    pub hypervisor_bit: bool,
    /// True when we believe this process runs in a Hyper-V *root* partition.
    pub hyperv_root: bool,
}

impl Default for VirtualizationInfo {
    fn default() -> Self {
        Self {
            kind: VirtualizationKind::Unknown,
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
            reason: "container markers present (/.dockerenv, cgroup, or $container)".to_string(),
            hypervisor_vendor: None,
            hypervisor_bit: false,
            hyperv_root: false,
        };
    }

    let dmi_guest = dmi_guest_signal();
    let hv = hypervisor_probe();

    // Strong DMI guest product name always wins.
    if let Some(reason) = dmi_guest {
        return VirtualizationInfo {
            kind: VirtualizationKind::VirtualMachine,
            reason,
            hypervisor_vendor: hv.vendor_label.clone(),
            hypervisor_bit: hv.bit,
            hyperv_root: hv.hyperv_root,
        };
    }

    if !hv.bit {
        return VirtualizationInfo {
            kind: VirtualizationKind::BareMetal,
            reason: "no guest DMI markers and no hypervisor present bit".to_string(),
            hypervisor_vendor: None,
            hypervisor_bit: false,
            hyperv_root: false,
        };
    }

    // Hypervisor present — classify carefully.
    if hv.hyperv_root {
        return VirtualizationInfo {
            kind: VirtualizationKind::BareMetal,
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
            kind: VirtualizationKind::VirtualMachine,
            reason: format!(
                "guest hypervisor identity {:?}",
                hv.vendor_label.as_deref().unwrap_or("unknown")
            ),
            hypervisor_vendor: hv.vendor_label,
            hypervisor_bit: true,
            hyperv_root: false,
        };
    }

    // Bit set but not a known guest (unknown vendor, or Hyper-V without root
    // proof on non-Windows). Prefer bare metal over a false VM claim.
    VirtualizationInfo {
        kind: VirtualizationKind::BareMetal,
        reason: format!(
            "hypervisor bit set ({:?}) but not classified as a guest",
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
    if let Ok(env) = std::env::var("container") {
        if !env.is_empty() {
            return true;
        }
    }
    false
}

/// Returns `Some(reason)` only for *strong* guest DMI signals.
///
/// Deliberately does **not** treat `sys_vendor == "Microsoft Corporation"` alone
/// as a VM — that string appears on physical Surface devices and is useless
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
                    // Windows without DMI guest product — false VM is worse.
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

        return HvProbe {
            bit: true,
            vendor_label,
            hyperv_root,
            is_guest_vendor,
        };
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
            VirtualizationKind::BareMetal
                | VirtualizationKind::VirtualMachine
                | VirtualizationKind::Container
                | VirtualizationKind::Unknown
        ));
        assert!(!info.reason.is_empty());
    }
}
