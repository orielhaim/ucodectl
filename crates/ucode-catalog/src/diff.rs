use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use ucode_core::{CpuSignature, PatchMeta, PlatformMask, Vendor};

use crate::Catalog;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffKind {
    Added,
    Removed,
    Upgraded,
    Downgraded,
    /// Same revision, different bytes. Always worth flagging.
    Changed,
    Unchanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub kind: DiffKind,
    pub vendor: Vendor,
    pub signature: String,
    pub platform_mask: String,
    pub old_revision: Option<String>,
    pub new_revision: Option<String>,
    pub old_date: Option<String>,
    pub new_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogDiff {
    pub entries: Vec<DiffEntry>,
    pub added: usize,
    pub removed: usize,
    pub upgraded: usize,
    pub downgraded: usize,
    pub changed: usize,
    pub unchanged: usize,
}

type Key = (Vendor, CpuSignature, PlatformMask);

fn index(catalog: &Catalog) -> BTreeMap<Key, &PatchMeta> {
    let mut map: BTreeMap<Key, &PatchMeta> = BTreeMap::new();
    for p in &catalog.patches {
        for m in &p.matches {
            let key = (p.vendor, m.signature, m.platform_mask);
            map.entry(key)
                .and_modify(|existing| {
                    if p.revision > existing.revision {
                        *existing = p;
                    }
                })
                .or_insert(p);
        }
    }
    map
}

/// Compare two catalogs on their best patch per target.
pub fn diff_catalogs(old: &Catalog, new: &Catalog, include_unchanged: bool) -> CatalogDiff {
    let old_idx = index(old);
    let new_idx = index(new);

    let mut keys: Vec<Key> = old_idx.keys().chain(new_idx.keys()).copied().collect();
    keys.sort_unstable();
    keys.dedup();

    let mut out = CatalogDiff {
        entries: Vec::new(),
        added: 0,
        removed: 0,
        upgraded: 0,
        downgraded: 0,
        changed: 0,
        unchanged: 0,
    };

    for key in keys {
        let o = old_idx.get(&key).copied();
        let n = new_idx.get(&key).copied();

        let kind = match (o, n) {
            (None, Some(_)) => DiffKind::Added,
            (Some(_), None) => DiffKind::Removed,
            (Some(a), Some(b)) if b.revision > a.revision => DiffKind::Upgraded,
            (Some(a), Some(b)) if b.revision < a.revision => DiffKind::Downgraded,
            (Some(a), Some(b)) if a.sha256 != b.sha256 => DiffKind::Changed,
            _ => DiffKind::Unchanged,
        };

        match kind {
            DiffKind::Added => out.added += 1,
            DiffKind::Removed => out.removed += 1,
            DiffKind::Upgraded => out.upgraded += 1,
            DiffKind::Downgraded => out.downgraded += 1,
            DiffKind::Changed => out.changed += 1,
            DiffKind::Unchanged => out.unchanged += 1,
        }

        if kind == DiffKind::Unchanged && !include_unchanged {
            continue;
        }

        out.entries.push(DiffEntry {
            kind,
            vendor: key.0,
            signature: key.1.to_string(),
            platform_mask: key.2.to_string(),
            old_revision: o.map(|p| format!("0x{:08x}", p.revision)),
            new_revision: n.map(|p| format!("0x{:08x}", p.revision)),
            old_date: o.and_then(|p| p.date).map(|d| d.to_string()),
            new_date: n.and_then(|p| p.date).map(|d| d.to_string()),
        });
    }

    out
}
