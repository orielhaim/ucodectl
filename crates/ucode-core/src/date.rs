use core::fmt;
use serde::{Deserialize, Serialize};

/// Release date of a microcode patch.
///
/// Both Intel and AMD store this as a packed BCD `u32` laid out as
/// `0xMMDDYYYY`, i.e. month in bits 31..24, day in 23..16 and year in 15..0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct UcodeDate {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    /// Raw packed value, preserved verbatim so we can round-trip nonsense.
    pub raw: u32,
}

fn bcd_to_u16(v: u32) -> Option<u16> {
    let mut out: u16 = 0;
    let mut shift = 0;
    while shift < 16 {
        let nibble = ((v >> shift) & 0xf) as u16;
        if nibble > 9 {
            return None;
        }
        out += nibble * 10u16.pow(shift / 4);
        shift += 4;
    }
    Some(out)
}

fn bcd_to_u8(v: u32) -> Option<u8> {
    let lo = (v & 0xf) as u8;
    let hi = ((v >> 4) & 0xf) as u8;
    if lo > 9 || hi > 9 {
        None
    } else {
        Some(hi * 10 + lo)
    }
}

impl UcodeDate {
    /// Decode a packed BCD date. Returns `None` when the nibbles are not
    /// valid BCD; the caller should surface this as a validation finding
    /// rather than silently "fixing" it.
    pub fn from_packed_bcd(raw: u32) -> Option<Self> {
        let year = bcd_to_u16(raw & 0xffff)?;
        let day = bcd_to_u8((raw >> 16) & 0xff)?;
        let month = bcd_to_u8((raw >> 24) & 0xff)?;
        Some(Self {
            year,
            month,
            day,
            raw,
        })
    }

    /// Loose plausibility check used for validation findings.
    pub fn is_plausible(&self) -> bool {
        (1990..=2100).contains(&self.year)
            && (1..=12).contains(&self.month)
            && (1..=31).contains(&self.day)
    }

    /// Sortable `YYYYMMDD` integer.
    pub fn sort_key(&self) -> u32 {
        (self.year as u32) * 10_000 + (self.month as u32) * 100 + self.day as u32
    }
}

impl fmt::Display for UcodeDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}
