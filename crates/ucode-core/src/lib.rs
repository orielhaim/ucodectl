#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

//! Vendor-neutral domain model for x86 CPU microcode.
//!
//! This crate deliberately contains **no** filesystem access, no CPUID
//! execution, no Linux paths, no CLI concerns and no vendor-specific binary
//! structures. Vendor crates parse bytes and then project their result into
//! the types defined here.

extern crate alloc;

pub mod cpu;
pub mod date;
pub mod error;
pub mod limits;
pub mod patch;
pub mod select;
pub mod validate;

pub use cpu::{
    CpuIdentity, CpuSignature, ObservationConfidence, ObservationScope, PlatformMask,
    RawObservation, RevisionObservation, RevisionSource, Vendor,
};
pub use date::UcodeDate;
pub use error::{CoreError, CoreResult};
pub use patch::{
    HeaderKind, PatchMeta, PatchOrigin, PatchRef, ProcessorMatch, RuntimeUpdatePolicy,
};
pub use select::{Candidate, Rejection, SelectionOutcome, select_for_cpu};
pub use validate::{Finding, FindingCode, Severity, ValidationReport};

/// Version of the semantic model. Bumped when the meaning of any exported
/// enum variant changes in a way that consumers must react to.
pub const MODEL_VERSION: u32 = 2;
