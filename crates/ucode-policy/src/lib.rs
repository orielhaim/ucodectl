#![forbid(unsafe_code)]

//! Pure, deterministic decision engine.
//!
//! The policy crate never touches the filesystem. It takes already-discovered
//! system state, catalogs and boot-artifact metadata and returns an explained
//! plan. Mutation is the exclusive responsibility of `ucode-transaction`.

pub mod plan;
pub mod state;

pub use plan::{Action, Plan, PlanInput, PlannedWrite, evaluate};
pub use state::SystemStatus;

use thiserror::Error;

pub type Result<T> = core::result::Result<T, PolicyError>;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("{0}")]
    Invalid(String),
}
