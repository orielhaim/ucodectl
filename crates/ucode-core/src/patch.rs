use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};

use crate::cpu::{CpuIdentity, CpuSignature, PlatformMask, Vendor};
use crate::date::UcodeDate;

/// What kind of payload a header describes.
///
/// Intel reuses the microcode header for In-Field Scan test images
/// (`hdrver == MC_HEADER_TYPE_IFS`). These must never be handed to the
/// microcode loader, so the distinction is part of the domain model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderKind {
    Microcode,
    IntelIfsTestImage,
    Unknown(u32),
}

impl fmt::Display for HeaderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderKind::Microcode => f.write_str("microcode"),
            HeaderKind::IntelIfsTestImage => f.write_str("IFS test image"),
            HeaderKind::Unknown(v) => write!(f, "unknown header type {v}"),
        }
    }
}

/// One (signature, platform) pair a patch applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProcessorMatch {
    pub signature: CpuSignature,
    /// Intel platform mask. Always `PlatformMask::ANY` for AMD.
    pub platform_mask: PlatformMask,
    /// AMD equivalence id (`processor_rev_id`). `None` for Intel.
    pub equivalence_id: Option<u16>,
    /// `true` for the signature carried in the primary header, `false` for
    /// entries that came from an Intel extended signature table.
    pub primary: bool,
}

impl ProcessorMatch {
    pub fn intel(signature: CpuSignature, platform_mask: PlatformMask, primary: bool) -> Self {
        Self {
            signature,
            platform_mask,
            equivalence_id: None,
            primary,
        }
    }

    pub fn amd(signature: CpuSignature, equivalence_id: u16) -> Self {
        Self {
            signature,
            platform_mask: PlatformMask::ANY,
            equivalence_id: Some(equivalence_id),
            primary: true,
        }
    }

    /// `intel_ucode_sigmatch()` generalised over vendors.
    pub fn applies_to(&self, cpu: &CpuIdentity) -> bool {
        if self.signature != cpu.signature {
            return false;
        }
        match cpu.vendor {
            Vendor::Amd => true,
            Vendor::Intel => match cpu.platform_mask {
                Some(cpu_mask) => self.platform_mask.matches(cpu_mask),
                // Unknown platform ID: we refuse to claim a match. The policy
                // layer turns this into an explicit "ambiguous" state instead
                // of quietly loading a possibly wrong image.
                None => false,
            },
        }
    }
}

/// Whether a patch may be applied while the system is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeUpdatePolicy {
    /// Intel published a non-zero Minimum Runtime Update Revision.
    RequiresBaseRevision(u32),
    /// The vendor gave no runtime-update indication.
    Unspecified,
}

/// Where a patch physically came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchOrigin {
    /// Display path of the containing blob.
    pub source: String,
    /// Byte offset of the patch inside that blob.
    pub offset: u64,
    /// Byte length of the patch as stored.
    pub length: u32,
}

/// A stable identity for a patch: two patches with the same `PatchRef` are
/// interchangeable from the loader's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PatchRef {
    pub vendor: Vendor,
    pub signature: CpuSignature,
    pub platform_mask: PlatformMask,
    pub revision: u32,
}

/// Vendor-neutral metadata for one microcode patch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchMeta {
    pub vendor: Vendor,
    pub kind: HeaderKind,
    /// Intel: header `rev`. AMD: `patch_id`.
    pub revision: u32,
    pub date: Option<UcodeDate>,
    /// Total on-disk size of the patch as it must be serialised.
    pub total_size: u32,
    /// Payload size excluding headers/tables, when meaningful.
    pub data_size: u32,
    pub matches: Vec<ProcessorMatch>,
    pub runtime_update: RuntimeUpdatePolicy,
    /// AMD only, and always sourced from out-of-band metadata (the
    /// linux-firmware README), never from the container itself.
    pub min_base_revision: Option<u32>,
    pub origin: PatchOrigin,
    /// SHA-256 over the exact serialised bytes of this patch.
    pub sha256: Option<[u8; 32]>,
}

impl PatchMeta {
    /// True if this patch is safe to hand to the kernel loader at all.
    pub fn is_loadable(&self) -> bool {
        matches!(self.kind, HeaderKind::Microcode)
    }

    pub fn applies_to(&self, cpu: &CpuIdentity) -> bool {
        self.vendor == cpu.vendor && self.matches.iter().any(|m| m.applies_to(cpu))
    }

    pub fn primary_match(&self) -> Option<&ProcessorMatch> {
        self.matches
            .iter()
            .find(|m| m.primary)
            .or_else(|| self.matches.first())
    }

    pub fn patch_ref(&self) -> Option<PatchRef> {
        let m = self.primary_match()?;
        Some(PatchRef {
            vendor: self.vendor,
            signature: m.signature,
            platform_mask: m.platform_mask,
            revision: self.revision,
        })
    }

    /// Revision ordering.
    ///
    /// We compare **unsigned**, matching the Linux loader
    /// (`struct microcode_header_intel.rev` is `unsigned int` and the loader
    /// does an unsigned comparison). iucode-tool historically used a signed
    /// comparison; the difference only shows up for revisions with bit 31 set,
    /// which are flagged separately as a validation finding.
    pub fn is_newer_than(&self, other_revision: u32) -> bool {
        self.revision > other_revision
    }

    /// Whether a *runtime* (late) update to this patch is permitted given the
    /// currently loaded revision.
    pub fn runtime_update_allowed_from(&self, current: u32) -> Option<bool> {
        match self.runtime_update {
            RuntimeUpdatePolicy::RequiresBaseRevision(min) if min != 0 => Some(current >= min),
            _ => None,
        }
    }

    /// AMD: whether the loader will accept this patch given the running base.
    pub fn base_revision_satisfied(&self, current: u32) -> Option<bool> {
        self.min_base_revision.map(|min| current >= min)
    }
}
