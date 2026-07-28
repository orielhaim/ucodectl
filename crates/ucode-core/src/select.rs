use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::cpu::CpuIdentity;
use crate::patch::PatchMeta;

/// Why a structurally valid patch was not selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rejection {
    WrongVendor,
    SignatureMismatch,
    PlatformMaskMismatch,
    PlatformIdUnknown,
    NotAMicrocodeImage,
    OlderThanRunning,
    SameAsRunning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Candidate<'a> {
    pub patch: &'a PatchMeta,
    pub rejection: Option<Rejection>,
}

/// Result of choosing the best patch for one CPU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionOutcome<'a> {
    /// Highest-revision applicable patch, regardless of what is running.
    pub best: Option<&'a PatchMeta>,
    /// Every patch that applies to this CPU, newest first.
    pub applicable: Vec<&'a PatchMeta>,
    /// Applicable patches that tie with `best` on revision but differ in
    /// content. A non-empty value means the input set is self-contradictory.
    pub ambiguous_with: Vec<&'a PatchMeta>,
    /// All inputs annotated with why they were or were not applicable.
    pub considered: Vec<Candidate<'a>>,
}

impl<'a> SelectionOutcome<'a> {
    pub fn is_ambiguous(&self) -> bool {
        !self.ambiguous_with.is_empty()
    }
}

/// Pure selection: no I/O, no side effects, fully deterministic.
///
/// Ordering rule, in priority order:
///   1. higher revision wins;
///   2. newer date wins (ties on revision should not happen, but do in the
///      wild when vendors re-release);
///   3. narrower platform mask wins (a targeted image beats a catch-all);
///   4. lexicographic origin, purely to make the result deterministic.
pub fn select_for_cpu<'a, I>(patches: I, cpu: &CpuIdentity) -> SelectionOutcome<'a>
where
    I: IntoIterator<Item = &'a PatchMeta>,
{
    let mut considered: Vec<Candidate<'a>> = Vec::new();
    let mut applicable: Vec<&'a PatchMeta> = Vec::new();

    for patch in patches {
        let rejection = classify(patch, cpu);
        if rejection.is_none() {
            applicable.push(patch);
        }
        considered.push(Candidate { patch, rejection });
    }

    applicable.sort_by(|a, b| {
        b.revision
            .cmp(&a.revision)
            .then_with(|| {
                let ka = a.date.map(|d| d.sort_key()).unwrap_or(0);
                let kb = b.date.map(|d| d.sort_key()).unwrap_or(0);
                kb.cmp(&ka)
            })
            .then_with(|| mask_width(a).cmp(&mask_width(b)))
            .then_with(|| a.origin.source.cmp(&b.origin.source))
            .then_with(|| a.origin.offset.cmp(&b.origin.offset))
    });

    let best = applicable.first().copied();
    let mut ambiguous_with: Vec<&'a PatchMeta> = Vec::new();
    if let Some(best) = best {
        for other in applicable.iter().skip(1) {
            if other.revision != best.revision {
                break;
            }
            if other.sha256.is_some() && other.sha256 == best.sha256 {
                continue; // byte-identical duplicate, not a conflict
            }
            ambiguous_with.push(other);
        }
    }

    SelectionOutcome {
        best,
        applicable,
        ambiguous_with,
        considered,
    }
}

fn mask_width(p: &PatchMeta) -> u32 {
    p.primary_match()
        .map(|m| m.platform_mask.raw().count_ones())
        .unwrap_or(u32::MAX)
}

fn classify(patch: &PatchMeta, cpu: &CpuIdentity) -> Option<Rejection> {
    if patch.vendor != cpu.vendor {
        return Some(Rejection::WrongVendor);
    }
    if !patch.is_loadable() {
        return Some(Rejection::NotAMicrocodeImage);
    }
    let sig_hit = patch.matches.iter().any(|m| m.signature == cpu.signature);
    if !sig_hit {
        return Some(Rejection::SignatureMismatch);
    }
    if cpu.vendor == crate::cpu::Vendor::Intel && cpu.platform_mask.is_none() {
        return Some(Rejection::PlatformIdUnknown);
    }
    if !patch.applies_to(cpu) {
        return Some(Rejection::PlatformMaskMismatch);
    }
    None
}
