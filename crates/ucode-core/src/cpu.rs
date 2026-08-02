use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};

/// CPU vendor as relevant to microcode loading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Vendor {
    Intel,
    Amd,
}

impl Vendor {
    /// CPUID vendor string as reported by `CPUID.0:EBX,EDX,ECX`.
    pub const fn cpuid_string(self) -> &'static str {
        match self {
            Vendor::Intel => "GenuineIntel",
            Vendor::Amd => "AuthenticAMD",
        }
    }

    /// Canonical file name used by the Linux early loader inside the CPIO.
    pub const fn early_blob_name(self) -> &'static str {
        match self {
            Vendor::Intel => "GenuineIntel.bin",
            Vendor::Amd => "AuthenticAMD.bin",
        }
    }

    /// Canonical CPIO path expected by `arch/x86/kernel/cpu/microcode`.
    pub const fn early_cpio_path(self) -> &'static str {
        match self {
            Vendor::Intel => "kernel/x86/microcode/GenuineIntel.bin",
            Vendor::Amd => "kernel/x86/microcode/AuthenticAMD.bin",
        }
    }

    pub fn from_cpuid_string(s: &str) -> Option<Self> {
        match s {
            "GenuineIntel" => Some(Vendor::Intel),
            "AuthenticAMD" | "HygonGenuine" => Some(Vendor::Amd),
            _ => None,
        }
    }
}

impl fmt::Display for Vendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Vendor::Intel => "Intel",
            Vendor::Amd => "AMD",
        })
    }
}

/// Raw `CPUID.1:EAX` value ("processor signature").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CpuSignature(pub u32);

impl CpuSignature {
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Base family field, `EAX[11:8]`.
    pub const fn base_family(self) -> u32 {
        (self.0 >> 8) & 0xf
    }

    /// Extended family field, `EAX[27:20]`.
    pub const fn extended_family(self) -> u32 {
        (self.0 >> 20) & 0xff
    }

    /// Effective (display) family, per both Intel SDM and AMD APM.
    pub const fn family(self) -> u32 {
        let base = self.base_family();
        if base == 0xf {
            base + self.extended_family()
        } else {
            base
        }
    }

    /// Effective (display) model.
    ///
    /// Note that Intel and AMD differ: Intel only folds in the extended model
    /// for families 0x6 and 0xf, while AMD always does. We follow the
    /// vendor-specific rule because it changes the printed model number.
    pub const fn model_for(self, vendor: Vendor) -> u32 {
        let base_model = (self.0 >> 4) & 0xf;
        let ext_model = (self.0 >> 16) & 0xf;
        match vendor {
            Vendor::Intel => {
                let base_family = self.base_family();
                if base_family == 0x6 || base_family == 0xf {
                    (ext_model << 4) | base_model
                } else {
                    base_model
                }
            }
            Vendor::Amd => (ext_model << 4) | base_model,
        }
    }

    pub const fn stepping(self) -> u32 {
        self.0 & 0xf
    }

    /// Processor type field, `EAX[13:12]`.
    pub const fn processor_type(self) -> u32 {
        (self.0 >> 12) & 0x3
    }

    /// Rebuild a signature from family/model/stepping. Used when the only
    /// source of truth is `/proc/cpuinfo` (which reports decoded values).
    pub const fn from_fms(vendor: Vendor, family: u32, model: u32, stepping: u32) -> Self {
        let (base_family, ext_family) = if family >= 0xf {
            (0xf_u32, family - 0xf)
        } else {
            (family, 0)
        };
        let base_model = model & 0xf;
        let ext_model = match vendor {
            Vendor::Intel if base_family != 0x6 && base_family != 0xf => 0,
            _ => (model >> 4) & 0xf,
        };
        Self(
            ((ext_family & 0xff) << 20)
                | ((ext_model & 0xf) << 16)
                | ((base_family & 0xf) << 8)
                | (base_model << 4)
                | (stepping & 0xf),
        )
    }

    /// `06-8c-01`-style file name used by `/lib/firmware/intel-ucode`.
    pub fn intel_firmware_name(self) -> alloc::string::String {
        alloc::format!(
            "{:02x}-{:02x}-{:02x}",
            self.family(),
            self.model_for(Vendor::Intel),
            self.stepping()
        )
    }
}

impl fmt::Display for CpuSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

/// Intel platform-flags bitmask (`pf`). One bit per platform ID.
///
/// For a CPU this is `1 << IA32_PLATFORM_ID[52:50]`; for a microcode entry it
/// is a mask of every platform the entry applies to.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct PlatformMask(pub u32);

impl PlatformMask {
    pub const ANY: PlatformMask = PlatformMask(0);

    pub const fn raw(self) -> u32 {
        self.0
    }

    pub const fn from_platform_id(id: u32) -> Self {
        PlatformMask(1u32 << (id & 0x7))
    }

    /// Exactly the semantics of `intel_ucode_sigmatch()`'s platform half:
    /// intersecting bits, or the "unrestricted" 0/0 case.
    pub const fn matches(self, cpu: PlatformMask) -> bool {
        (self.0 & cpu.0) != 0 || (self.0 == 0 && cpu.0 == 0)
    }

    /// Lowest set platform ID, if any. Useful for display.
    pub const fn first_platform_id(self) -> Option<u32> {
        if self.0 == 0 {
            None
        } else {
            Some(self.0.trailing_zeros())
        }
    }
}

impl fmt::Display for PlatformMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:02x}", self.0)
    }
}

/// Where an active microcode revision observation came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionSource {
    ProcCpuinfo,
    LinuxSysfs,
    WindowsRegistry,
    Manual,
    Unavailable,
}

/// Scope of a hardware or operating-system observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationScope {
    System,
    ProcessorPackage,
    Core,
    LogicalProcessor,
    VirtualCpu,
    Unknown,
}

/// Confidence and authority level of an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationConfidence {
    Authoritative,
    Reported,
    Inferred,
    Virtualized,
    Unverified,
}

/// Self-describing raw bytes retained alongside a decoded observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawObservation {
    pub encoding: String,
    pub hex: String,
    pub bytes: Vec<u8>,
}

impl RawObservation {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let encoding = match bytes.len() {
            4 => "little_endian_u32",
            8 => "little_endian_u32_at_offset_4",
            _ => "raw_bytes",
        };
        let mut hex = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in &bytes {
            hex.push_str(&alloc::format!("{byte:02x}"));
        }
        Self {
            encoding: encoding.into(),
            hex,
            bytes,
        }
    }
}

/// A normalized active-microcode observation.  Unlike an `Option<u32>`, this
/// preserves why a revision cannot be used for update policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RevisionObservation {
    Known {
        revision: u32,
        source: RevisionSource,
        scope: ObservationScope,
        confidence: ObservationConfidence,
        #[serde(skip_serializing_if = "Option::is_none")]
        raw: Option<RawObservation>,
    },
    Unavailable {
        source: RevisionSource,
        scope: ObservationScope,
        confidence: ObservationConfidence,
        reason: String,
    },
    Unsupported {
        source: RevisionSource,
        scope: ObservationScope,
        confidence: ObservationConfidence,
        reason: String,
    },
    Invalid {
        source: RevisionSource,
        scope: ObservationScope,
        confidence: ObservationConfidence,
        raw: RawObservation,
        reason: String,
    },
}

impl RevisionObservation {
    fn defaults(source: RevisionSource) -> (ObservationScope, ObservationConfidence) {
        match source {
            RevisionSource::LinuxSysfs => (
                ObservationScope::LogicalProcessor,
                ObservationConfidence::Authoritative,
            ),
            RevisionSource::ProcCpuinfo | RevisionSource::WindowsRegistry => (
                ObservationScope::LogicalProcessor,
                ObservationConfidence::Reported,
            ),
            RevisionSource::Manual => {
                (ObservationScope::Unknown, ObservationConfidence::Unverified)
            }
            RevisionSource::Unavailable => {
                (ObservationScope::Unknown, ObservationConfidence::Unverified)
            }
        }
    }

    pub fn known(revision: u32, source: RevisionSource) -> Self {
        let (scope, confidence) = Self::defaults(source);
        Self::Known {
            revision,
            source,
            scope,
            confidence,
            raw: None,
        }
    }

    pub fn known_raw(revision: u32, source: RevisionSource, raw_value: Vec<u8>) -> Self {
        let (scope, confidence) = Self::defaults(source);
        Self::Known {
            revision,
            source,
            scope,
            confidence,
            raw: Some(RawObservation::from_bytes(raw_value)),
        }
    }

    pub fn unavailable(source: RevisionSource, reason: impl Into<alloc::string::String>) -> Self {
        let (scope, confidence) = Self::defaults(source);
        Self::Unavailable {
            source,
            scope,
            confidence,
            reason: reason.into(),
        }
    }

    pub fn unsupported(source: RevisionSource, reason: impl Into<alloc::string::String>) -> Self {
        let (scope, confidence) = Self::defaults(source);
        Self::Unsupported {
            source,
            scope,
            confidence,
            reason: reason.into(),
        }
    }

    pub fn invalid(
        source: RevisionSource,
        raw_value: Vec<u8>,
        reason: impl Into<alloc::string::String>,
    ) -> Self {
        let (scope, confidence) = Self::defaults(source);
        Self::Invalid {
            source,
            scope,
            confidence,
            raw: RawObservation::from_bytes(raw_value),
            reason: reason.into(),
        }
    }

    pub fn with_scope_confidence(
        mut self,
        scope: ObservationScope,
        confidence: ObservationConfidence,
    ) -> Self {
        match &mut self {
            Self::Known {
                scope: current_scope,
                confidence: current_confidence,
                ..
            }
            | Self::Unavailable {
                scope: current_scope,
                confidence: current_confidence,
                ..
            }
            | Self::Unsupported {
                scope: current_scope,
                confidence: current_confidence,
                ..
            }
            | Self::Invalid {
                scope: current_scope,
                confidence: current_confidence,
                ..
            } => {
                *current_scope = scope;
                *current_confidence = confidence;
            }
        }
        self
    }

    pub fn known_revision(&self) -> Option<u32> {
        match self {
            Self::Known { revision, .. } => Some(*revision),
            Self::Unavailable { .. } | Self::Unsupported { .. } | Self::Invalid { .. } => None,
        }
    }

    pub fn source(&self) -> RevisionSource {
        match self {
            Self::Known { source, .. }
            | Self::Unavailable { source, .. }
            | Self::Unsupported { source, .. }
            | Self::Invalid { source, .. } => *source,
        }
    }

    pub fn scope(&self) -> ObservationScope {
        match self {
            Self::Known { scope, .. }
            | Self::Unavailable { scope, .. }
            | Self::Unsupported { scope, .. }
            | Self::Invalid { scope, .. } => *scope,
        }
    }

    pub fn confidence(&self) -> ObservationConfidence {
        match self {
            Self::Known { confidence, .. }
            | Self::Unavailable { confidence, .. }
            | Self::Unsupported { confidence, .. }
            | Self::Invalid { confidence, .. } => *confidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn raw_revision_observation_is_self_describing() {
        let observation = RevisionObservation::known_raw(
            0x1234,
            RevisionSource::WindowsRegistry,
            vec![0x34, 0x12, 0, 0],
        );
        assert!(matches!(
            &observation,
            RevisionObservation::Known { raw: Some(_), .. }
        ));
        if let RevisionObservation::Known {
            scope,
            confidence,
            raw: Some(raw),
            ..
        } = observation
        {
            assert_eq!(scope, ObservationScope::LogicalProcessor);
            assert_eq!(confidence, ObservationConfidence::Reported);
            assert_eq!(raw.encoding, "little_endian_u32");
            assert_eq!(raw.hex, "34120000");
            assert_eq!(raw.bytes, vec![0x34, 0x12, 0, 0]);
        }
    }
}

/// Everything we know about one logical CPU, from the microcode point of view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuIdentity {
    pub vendor: Vendor,
    pub signature: CpuSignature,
    /// Intel only. `None` means "could not be determined".
    pub platform_mask: Option<PlatformMask>,
    /// Currently running microcode revision, if readable.
    pub current_revision: Option<u32>,
}

impl CpuIdentity {
    pub fn new(vendor: Vendor, signature: CpuSignature) -> Self {
        Self {
            vendor,
            signature,
            platform_mask: None,
            current_revision: None,
        }
    }

    pub fn with_platform_mask(mut self, mask: PlatformMask) -> Self {
        self.platform_mask = Some(mask);
        self
    }

    pub fn with_revision(mut self, rev: u32) -> Self {
        self.current_revision = Some(rev);
        self
    }

    pub fn family(&self) -> u32 {
        self.signature.family()
    }

    pub fn model(&self) -> u32 {
        self.signature.model_for(self.vendor)
    }

    pub fn stepping(&self) -> u32 {
        self.signature.stepping()
    }

    /// Effective platform mask for matching. When the platform ID is unknown
    /// we deliberately do *not* guess: callers get `None` and must decide
    /// whether to widen the match or report an ambiguity.
    pub fn effective_platform_mask(&self) -> Option<PlatformMask> {
        match self.vendor {
            Vendor::Intel => self.platform_mask,
            Vendor::Amd => Some(PlatformMask::ANY),
        }
    }
}
