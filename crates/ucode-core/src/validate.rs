use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational: worth reporting, never blocks anything.
    Info,
    /// The image is usable but deviates from the documented format.
    Warning,
    /// The image is structurally broken; it must never be loaded.
    Error,
}

/// Stable machine-readable finding codes. These are part of the JSON contract,
/// so variants are only ever added, never renamed or removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCode {
    // --- structural -------------------------------------------------------
    Truncated,
    BadMagic,
    UnsupportedHeaderVersion,
    UnsupportedLoaderVersion,
    BadTotalSize,
    BadDataSize,
    TotalSizeNotAligned,
    BadChecksum,
    BadExtendedTable,
    BadExtendedTableChecksum,
    BadExtendedSignatureChecksum,
    TrailingGarbage,
    OverlappingRegions,
    // --- semantic ---------------------------------------------------------
    ImplausibleDate,
    NonBcdDate,
    ZeroRevision,
    HighBitRevision,
    DuplicateSignature,
    EmptySignatureSet,
    IfsTestImage,
    ReservedFieldNonZero,
    UnknownMetadataSection,
    // --- AMD --------------------------------------------------------------
    EquivalenceIdNotInTable,
    EquivalenceTableUnterminated,
    DuplicateEquivalenceEntry,
    ConflictingEquivalenceEntry,
    PatchSizeExceedsFamilyMaximum,
    UnknownSectionType,
    // --- limits -----------------------------------------------------------
    LimitExceeded,
}

impl FindingCode {
    /// Default severity. Individual parsers may escalate but never de-escalate
    /// an `Error` into something softer.
    pub const fn default_severity(self) -> Severity {
        use FindingCode::*;
        match self {
            Truncated
            | BadMagic
            | UnsupportedHeaderVersion
            | BadTotalSize
            | BadDataSize
            | BadChecksum
            | BadExtendedTable
            | BadExtendedTableChecksum
            | BadExtendedSignatureChecksum
            | OverlappingRegions
            | LimitExceeded
            | EquivalenceTableUnterminated => Severity::Error,

            UnsupportedLoaderVersion
            | TotalSizeNotAligned
            | TrailingGarbage
            | NonBcdDate
            | ImplausibleDate
            | DuplicateSignature
            | EmptySignatureSet
            | ZeroRevision
            | HighBitRevision
            | EquivalenceIdNotInTable
            | DuplicateEquivalenceEntry
            | ConflictingEquivalenceEntry
            | PatchSizeExceedsFamilyMaximum
            | UnknownSectionType => Severity::Warning,

            IfsTestImage | ReservedFieldNonZero | UnknownMetadataSection => Severity::Info,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub code: FindingCode,
    pub severity: Severity,
    /// Byte offset the finding refers to, relative to the start of the blob.
    pub offset: u64,
    /// Length of the offending region, when known.
    pub length: Option<u32>,
    pub message: String,
}

impl Finding {
    pub fn new(code: FindingCode, offset: u64, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: code.default_severity(),
            offset,
            length: None,
            message: message.into(),
        }
    }

    pub fn with_length(mut self, length: u32) -> Self {
        self.length = Some(length);
        self
    }

    pub fn escalate(mut self, severity: Severity) -> Self {
        if severity > self.severity {
            self.severity = severity;
        }
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    pub findings: Vec<Finding>,
}

impl ValidationReport {
    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn extend(&mut self, other: ValidationReport) {
        self.findings.extend(other.findings);
    }

    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    pub fn has_errors(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Error)
    }

    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }
}
