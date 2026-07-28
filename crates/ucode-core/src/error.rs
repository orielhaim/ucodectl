use alloc::string::String;
use thiserror::Error;

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoreError {
    #[error(
        "input truncated: needed {needed} bytes at offset {offset}, only {available} available"
    )]
    Truncated {
        offset: usize,
        needed: usize,
        available: usize,
    },

    #[error("value out of range at offset {offset}: {what}")]
    OutOfRange { offset: usize, what: String },

    #[error("resource limit exceeded: {what} ({value} > {limit})")]
    LimitExceeded {
        what: &'static str,
        value: u64,
        limit: u64,
    },

    #[error("unrecognised container format")]
    UnknownFormat,

    #[error("{0}")]
    Malformed(String),
}
