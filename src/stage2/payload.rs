//! Recovers and assembles payloads passed to the iframe sender.
//!
//! `recover` turns object construction into a [`Layout`] containing [`Expression`] values.
//! [`Layout::assemble`] evaluates them with [`State`] without running the program.
//!
//! Probe, widget, and checkbox payloads use the same mechanism. Each step evaluates against
//! immutable state and produces ordered writes applied afterward. Reads therefore see the state
//! before that step's changes.

mod expression;
mod layout;
mod recover;

pub use expression::{Environment, Expression, Scope, State};
pub use layout::{Document, Layout, RecordTemplate, Template};
pub(super) use recover::{RecordLiteral, Recovered, recover_unique, scan};
