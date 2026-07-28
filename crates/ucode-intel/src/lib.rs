#![forbid(unsafe_code)]

//! Intel microcode container support.
//!
//! Layout of one microcode update (Intel SDM Vol. 3A, "Microcode Update
//! Facilities"), all fields little-endian `u32`:
//!
//! ```text
//! offset  field
//!   0x00  hdrver     1 = microcode, 2 = In-Field Scan test image
//!   0x04  rev        update revision
//!   0x08  date       packed BCD, 0xMMDDYYYY
//!   0x0c  sig        CPUID.1:EAX this update targets
//!   0x10  cksum      dword sum of header+data == 0
//!   0x14  ldrver     loader revision, 1
//!   0x18  pf         platform-flags bitmask
//!   0x1c  datasize   payload size, 0 means 2000
//!   0x20  totalsize  whole update size, 0 means 2048
//!   0x24  metasize   size of the metadata region inside the payload
//!   0x28  min_req_ver  Minimum Runtime Update Revision (0 = unspecified)
//!   0x2c  reserved
//! ```
//!
//! Optionally followed, at `0x30 + datasize`, by an extended signature table:
//! `count`, `checksum`, 12 reserved bytes, then `count` × `(sig, pf, cksum)`.

pub mod bundle;
#[cfg(feature = "dat")]
pub mod dat;
pub mod header;
pub mod validate;

pub use bundle::{IntelBundle, IntelEntry, scan_for_microcode};
pub use header::{
    EXTENDED_SIGNATURE_SIZE, EXTENDED_TABLE_HEADER_SIZE, HEADER_SIZE, IntelExtendedSignature,
    IntelHeader, MIN_UPDATE_SIZE,
};
pub use validate::{IntelValidationMode, validate_entry};

use thiserror::Error;

pub type Result<T> = core::result::Result<T, IntelError>;

#[derive(Debug, Error)]
pub enum IntelError {
    #[error("input too short at offset {offset}: need {need} bytes, have {have}")]
    Truncated {
        offset: usize,
        need: usize,
        have: usize,
    },

    #[error("not an Intel microcode bundle")]
    NotIntelFormat,

    #[error("malformed microcode entry at offset {offset}: {reason}")]
    Malformed { offset: u64, reason: String },

    #[error("resource limit exceeded: {0}")]
    LimitExceeded(&'static str),

    #[error(transparent)]
    Core(#[from] ucode_core::CoreError),

    #[cfg(feature = "dat")]
    #[error("malformed .dat input at line {line}: {reason}")]
    Dat { line: usize, reason: String },
}
