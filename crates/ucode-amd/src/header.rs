use ucode_core::CpuSignature;
use zerocopy::byteorder::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{AmdError, Result};

/// `"DMA\0"` read as a little-endian u32.
pub const UCODE_MAGIC: u32 = 0x0041_4d44;
pub const UCODE_MAGIC_BYTES: [u8; 4] = *b"DMA\0";

pub const SECTION_TYPE_EQUIV_TABLE: u32 = 0;
pub const SECTION_TYPE_PATCH: u32 = 1;

pub const CONTAINER_HEADER_SIZE: usize = 12;
pub const SECTION_HEADER_SIZE: usize = 8;
pub const EQUIV_ENTRY_SIZE: usize = 16;
pub const PATCH_HEADER_SIZE: usize = 64;

/// `struct equiv_cpu_entry` from `arch/x86/kernel/cpu/microcode/amd.c`.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct RawEquivEntry {
    pub installed_cpu: U32,
    pub fixed_errata_mask: U32,
    pub fixed_errata_compare: U32,
    pub equiv_cpu: U16,
    pub reserved: U16,
}

const _: () = assert!(core::mem::size_of::<RawEquivEntry>() == EQUIV_ENTRY_SIZE);

/// `struct microcode_header_amd`.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct RawPatchHeader {
    pub data_code: U32,
    pub patch_id: U32,
    pub mc_patch_data_id: U16,
    pub mc_patch_data_len: u8,
    pub init_flag: u8,
    pub mc_patch_data_checksum: U32,
    pub nb_dev_id: U32,
    pub sb_dev_id: U32,
    pub processor_rev_id: U16,
    pub nb_rev_id: u8,
    pub sb_rev_id: u8,
    pub bios_api_rev: u8,
    pub reserved1: [u8; 3],
    pub match_reg: [U32; 8],
}

const _: () = assert!(core::mem::size_of::<RawPatchHeader>() == PATCH_HEADER_SIZE);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmdPatchHeader {
    /// Packed BCD date, same layout as Intel: `0xMMDDYYYY`.
    pub date_raw: u32,
    pub patch_id: u32,
    pub data_id: u16,
    pub data_len: u8,
    pub init_flag: u8,
    pub data_checksum: u32,
    pub nb_dev_id: u32,
    pub sb_dev_id: u32,
    /// Equivalence id; must be present in the container's equivalence table.
    pub processor_rev_id: u16,
    pub nb_rev_id: u8,
    pub sb_rev_id: u8,
    pub bios_api_rev: u8,
    pub reserved: [u8; 3],
    pub match_reg: [u32; 8],
}

impl AmdPatchHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let (raw, _) =
            RawPatchHeader::read_from_prefix(bytes).map_err(|_| AmdError::Truncated {
                offset: 0,
                need: PATCH_HEADER_SIZE,
                have: bytes.len(),
            })?;
        Ok(Self::from_raw(&raw))
    }

    pub fn from_raw(raw: &RawPatchHeader) -> Self {
        let mut match_reg = [0u32; 8];
        for (dst, src) in match_reg.iter_mut().zip(raw.match_reg.iter()) {
            *dst = src.get();
        }
        Self {
            date_raw: raw.data_code.get(),
            patch_id: raw.patch_id.get(),
            data_id: raw.mc_patch_data_id.get(),
            data_len: raw.mc_patch_data_len,
            init_flag: raw.init_flag,
            data_checksum: raw.mc_patch_data_checksum.get(),
            nb_dev_id: raw.nb_dev_id.get(),
            sb_dev_id: raw.sb_dev_id.get(),
            processor_rev_id: raw.processor_rev_id.get(),
            nb_rev_id: raw.nb_rev_id,
            sb_rev_id: raw.sb_rev_id,
            bios_api_rev: raw.bios_api_rev,
            reserved: raw.reserved1,
            match_reg,
        }
    }

    /// AMD encodes the target family in the top byte of the patch id for
    /// modern parts (`0x0aa00215` → family 0x19). This is a display aid only;
    /// authoritative matching always goes through the equivalence table.
    pub fn implied_family_nibble(&self) -> u8 {
        ((self.patch_id >> 24) & 0xff) as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EquivalenceEntryView {
    pub installed_cpu: CpuSignature,
    pub fixed_errata_mask: u32,
    pub fixed_errata_compare: u32,
    pub equiv_id: u16,
    pub reserved: u16,
}
