//! Out-of-band metadata that vendors publish outside the container.
//!
//! The only case that matters today is AMD's "Minimum base ucode version for
//! loading", which appears in `linux-firmware/amd-ucode/README` as free text
//! and is *not* encoded anywhere in the `DMA\0` container. Rather than invent
//! a header field, we parse the README and attach the value to the matching
//! patch id.

use std::collections::BTreeMap;

use crate::{CatalogError, Result};

#[derive(Debug, Clone, Default)]
pub struct AmdSidecar {
    /// patch id -> minimum currently-loaded revision required.
    minimums: BTreeMap<u32, u32>,
    /// Free-form notes keyed by patch id, preserved for display.
    notes: BTreeMap<u32, String>,
}

impl AmdSidecar {
    pub fn min_base_revision(&self, patch_id: u32) -> Option<u32> {
        self.minimums.get(&patch_id).copied()
    }

    pub fn note(&self, patch_id: u32) -> Option<&str> {
        self.notes.get(&patch_id).map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.minimums.len()
    }

    pub fn is_empty(&self) -> bool {
        self.minimums.is_empty()
    }

    /// Parse `linux-firmware/amd-ucode/README`.
    ///
    /// The relevant shape is:
    ///
    /// ```text
    ///   Family=0x19 Model=0x01 Stepping=0x01: Patch=0x0a0011d5 Length=5568 bytes
    ///     Minimum base ucode version for loading: 0x0a0011d9
    /// ```
    ///
    /// The minimum line follows the patch line it applies to, so we track the
    /// most recently seen patch id.
    pub fn parse_linux_firmware_readme(text: &str) -> Result<Self> {
        let mut out = AmdSidecar::default();
        let mut current: Option<u32> = None;

        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }

            if let Some(patch_id) = extract_hex_after(line, "Patch=") {
                current = Some(patch_id);
                continue;
            }

            if let Some(rest) = line.strip_prefix("Minimum base ucode version for loading:") {
                let value = parse_hex(rest.trim()).ok_or_else(|| {
                    CatalogError::Sidecar(format!("unparseable minimum revision in {line:?}"))
                })?;
                match current {
                    Some(id) => {
                        out.minimums.insert(id, value);
                    }
                    None => {
                        return Err(CatalogError::Sidecar(
                            "found a minimum-base line before any patch line".to_string(),
                        ));
                    }
                }
                continue;
            }

            if let Some(id) = current
                && line.starts_with("Note")
            {
                out.notes.insert(id, line.to_string());
            }
        }

        Ok(out)
    }
}

fn extract_hex_after(line: &str, key: &str) -> Option<u32> {
    let idx = line.find(key)?;
    let rest = line.get(idx + key.len()..)?;
    let token = rest.split_whitespace().next()?;
    parse_hex(token)
}

fn parse_hex(s: &str) -> Option<u32> {
    let s = s
        .trim()
        .trim_end_matches(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X');
    let digits = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    u32::from_str_radix(digits, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimum_base_revision() {
        let text = "\
Microcode patches in microcode_amd_fam19h.bin:
  Family=0x19 Model=0x01 Stepping=0x01: Patch=0x0a0011d5 Length=5568 bytes
    Minimum base ucode version for loading: 0x0a0011d9
  Family=0x19 Model=0x11 Stepping=0x01: Patch=0x0a101148 Length=5568 bytes
";
        let s = AmdSidecar::parse_linux_firmware_readme(text).unwrap();
        assert_eq!(s.min_base_revision(0x0a0011d5), Some(0x0a0011d9));
        assert_eq!(s.min_base_revision(0x0a101148), None);
        assert_eq!(s.len(), 1);
    }
}
