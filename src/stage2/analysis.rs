//! Recovers probes, record envelopes, and payload layouts from returned programs.
//!
//! 1. Disassemble with the session's [`Source`](crate::script::Source) and index the listing.
//! 2. Discover probes in execution order and collect their strings.
//! 3. Map session names to reference names with [`crate::stage2::vocabulary`], pinning
//!    environment-audit fields by the values they store.
//! 4. Recognize probes. Operations recognized by reference strings keep the reference build's
//!    names, and their records are renamed when they are collected.
//! 5. Recover the envelope, payload layout, and controller frame.
//!
//! The result, saved as `stage2.json`, keeps unrecognized probes without an operation.

mod analyze;
mod audit;
mod controller;
mod discovery;
mod envelope;
mod outcome;
pub(crate) mod recognize;

pub use analyze::{Analysis, Artifact, ProbeEvidence, analyze};
pub use outcome::ProgramOutcome;
