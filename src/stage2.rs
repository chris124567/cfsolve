//! Analyzes returned programs, reading their listings without executing them, and answers them
//! natively.
//!
//! [`analysis`] recovers a [`records::ProbePlan`], with [`vocabulary`] mapping randomized names
//! to the reference build. [`registry`] selects each family's answer source: [`replay`] supplies
//! stored device facts refreshed with the iframe's [`trace`], while `probes` and `benchmark`
//! compute current results. [`interaction`] recovers the checkbox program, [`call_stack`]
//! rebuilds `new Error()` stacks, and `challenge_page` handles orchestrator programs. Payloads
//! are assembled from recovered [`payload::Layout`] data.

pub mod analysis;
pub(crate) mod benchmark;
pub mod call_stack;
pub(crate) mod challenge_page;
pub mod interaction;
pub mod payload;
pub(crate) mod probes;
pub(crate) mod proof;
pub mod records;
pub(crate) mod reference;
pub mod registry;
pub mod replay;
pub mod trace;
pub mod vocabulary;
mod worker_timing;
