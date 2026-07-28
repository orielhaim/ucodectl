use ucode_core::{CpuSignature, PlatformMask};
use zerocopy::byteorder::little_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{IntelError, Result};

pub const HEADER_SIZE: usize = 48;
pub const EXTENDED_TABLE_HEADER_SIZE: usize = 20;
pub const EXTENDED_SIGNATURE_SIZE: usize = 12;
/// Smallest object that could hold a production microcode update.
pub const MIN_UPDATE_SIZE: usize = 1024;

pub const DEFAULT_DATA_SIZE: u32 = 2000;
pub const DEFAULT_TOTAL_SIZE: u32 = 2048;

pub const HEADER_TYPE_MICROCODE: u32 = 1;
pub const HEADER_TYPE_IFS: u32 = 2;
pub const LOADER_REVISION: u32 = 1;

/// Raw on-disk Intel microcode header. Never expose this type in public APIs;
/// use [`IntelHeader`] instead.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct RawHeader {
    pub hdrver: U32,
    pub rev: U32,
    pub date: U32,
    pub sig: U32,
    pub cksum: U32,
    pub ldrver: U32,
    pub pf: U32,
    pub datasize: U32,
    pub totalsize: U32,
    pub metasize: U32,
    pub min_req_ver: U32,
    pub reserved: U32,
}

const _: () = assert!(core::mem::size_of::<RawHeader>() == HEADER_SIZE);

/// Decoded, bounds-checked view of an Intel microcode header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntelHeader {
    pub header_type: u32,
    pub revision: u32,
    pub date_raw: u32,
    pub signature: CpuSignature,
    pub checksum: u32,
    pub loader_revision: u32,
    pub platform_mask: PlatformMask,
    /// Declared value, i.e. before the "0 means default" substitution.
    pub declared_data_size: u32,
    pub declared_total_size: u32,
    pub metadata_size: u32,
    /// Intel "Minimum Runtime Update Revision"; 0 means unspecified.
    pub min_required_revision: u32,
    pub reserved: u32,
}

impl IntelHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let (raw, _) = RawHeader::read_from_prefix(bytes).map_err(|_| IntelError::Truncated {
            offset: 0,
            need: HEADER_SIZE,
            have: bytes.len(),
        })?;
        Ok(Self::from_raw(&raw))
    }

    pub fn from_raw(raw: &RawHeader) -> Self {
        Self {
            header_type: raw.hdrver.get(),
            revision: raw.rev.get(),
            date_raw: raw.date.get(),
            signature: CpuSignature(raw.sig.get()),
            checksum: raw.cksum.get(),
            loader_revision: raw.ldrver.get(),
            platform_mask: PlatformMask(raw.pf.get()),
            declared_data_size: raw.datasize.get(),
            declared_total_size: raw.totalsize.get(),
            metadata_size: raw.metasize.get(),
            min_required_revision: raw.min_req_ver.get(),
            reserved: raw.reserved.get(),
        }
    }

    pub fn to_raw(self) -> RawHeader {
        RawHeader {
            hdrver: U32::new(self.header_type),
            rev: U32::new(self.revision),
            date: U32::new(self.date_raw),
            sig: U32::new(self.signature.0),
            cksum: U32::new(self.checksum),
            ldrver: U32::new(self.loader_revision),
            pf: U32::new(self.platform_mask.0),
            datasize: U32::new(self.declared_data_size),
            totalsize: U32::new(self.declared_total_size),
            metasize: U32::new(self.metadata_size),
            min_req_ver: U32::new(self.min_required_revision),
            reserved: U32::new(self.reserved),
        }
    }

    /// Effective payload size, applying the documented default.
    pub fn data_size(&self) -> u32 {
        if self.declared_data_size == 0 {
            DEFAULT_DATA_SIZE
        } else {
            self.declared_data_size
        }
    }

    /// Effective total size, applying the documented default.
    pub fn total_size(&self) -> u32 {
        if self.declared_total_size == 0 {
            DEFAULT_TOTAL_SIZE
        } else {
            self.declared_total_size
        }
    }

    /// Byte offset of the extended signature table, if the sizes leave room
    /// for one.
    pub fn extended_table_offset(&self) -> Option<u32> {
        let end_of_data = (HEADER_SIZE as u32).checked_add(self.data_size())?;
        let total = self.total_size();
        (total > end_of_data && total - end_of_data >= EXTENDED_TABLE_HEADER_SIZE as u32)
            .then_some(end_of_data)
    }

    pub fn is_microcode(&self) -> bool {
        self.header_type == HEADER_TYPE_MICROCODE
    }

    pub fn is_ifs_image(&self) -> bool {
        self.header_type == HEADER_TYPE_IFS
    }
}

/// One `(sig, pf, cksum)` triple from the extended signature table.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct RawExtendedSignature {
    pub sig: U32,
    pub pf: U32,
    pub cksum: U32,
}

const _: () = assert!(core::mem::size_of::<RawExtendedSignature>() == EXTENDED_SIGNATURE_SIZE);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntelExtendedSignature {
    pub signature: CpuSignature,
    pub platform_mask: PlatformMask,
    pub checksum: u32,
}

impl IntelExtendedSignature {
    pub fn from_raw(raw: &RawExtendedSignature) -> Self {
        Self {
            signature: CpuSignature(raw.sig.get()),
            platform_mask: PlatformMask(raw.pf.get()),
            checksum: raw.cksum.get(),
        }
    }

    pub fn to_raw(self) -> RawExtendedSignature {
        RawExtendedSignature {
            sig: U32::new(self.signature.0),
            pf: U32::new(self.platform_mask.0),
            cksum: U32::new(self.checksum),
        }
    }
}

/// Header of the extended signature table: `count`, `checksum`, 12 reserved.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct RawExtendedTableHeader {
    pub count: U32,
    pub checksum: U32,
    pub reserved: [u8; 12],
}

const _: () = assert!(core::mem::size_of::<RawExtendedTableHeader>() == EXTENDED_TABLE_HEADER_SIZE);

/// Wrapping dword sum, the primitive behind every Intel checksum.
pub fn dword_sum(bytes: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for chunk in bytes.chunks_exact(4) {
        let v = u32::from_le_bytes([
            *chunk.first().unwrap_or(&0),
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
            *chunk.get(3).unwrap_or(&0),
        ]);
        sum = sum.wrapping_add(v);
    }
    sum
}
