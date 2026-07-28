#![forbid(unsafe_code)]

//! Deterministic `newc` CPIO support.
//!
//! We implement this ourselves rather than depending on a general-purpose
//! cpio crate because the resulting artifact is a boot-critical, reproducible
//! output: we need total control over ordering, padding, timestamps, inode
//! numbers, uid/gid, mode bits and the trailer. Any incidental metadata from
//! the building machine leaking into the archive would break reproducibility.

pub mod reader;
pub mod writer;

pub use reader::{CpioEntry, CpioReader, EarlyCpioScan, find_first_archive_end, scan_early_cpio};
pub use writer::{CpioBuilder, CpioFile};

use thiserror::Error;

pub type Result<T> = core::result::Result<T, ArchiveError>;

/// `070701`, the "new ASCII" cpio magic.
pub const NEWC_MAGIC: &[u8; 6] = b"070701";
pub const NEWC_HEADER_SIZE: usize = 110;
pub const TRAILER_NAME: &str = "TRAILER!!!";
/// Everything in a newc archive is padded to a 4-byte boundary.
pub const ALIGNMENT: usize = 4;

pub const MODE_FILE: u32 = 0o100_000;
pub const MODE_DIR: u32 = 0o040_000;

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("not a newc cpio archive at offset {offset}")]
    BadMagic { offset: u64 },

    #[error("truncated cpio archive at offset {offset}: need {need} bytes, have {have}")]
    Truncated {
        offset: u64,
        need: usize,
        have: usize,
    },

    #[error("invalid cpio header field {field:?} at offset {offset}")]
    BadField { field: &'static str, offset: u64 },

    #[error("unsafe cpio member name {name:?}: {reason}")]
    UnsafeName { name: String, reason: &'static str },

    #[error("resource limit exceeded: {0}")]
    LimitExceeded(&'static str),

    #[error("archive is missing a TRAILER!!! record")]
    MissingTrailer,

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
