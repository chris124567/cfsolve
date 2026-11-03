//! Interprets the JavaScript that implements the VM's handlers.
//!
//! Values that depend only on program bytes are computed; values that depend on unknown
//! registers stay symbolic expressions. [`explore()`] replays a handler for each feasible choice
//! of symbolic branches.
//!
//! Runs start from a [`Session`](crate::vm::session::Session) and copy mutable session objects
//! on first access, which isolates branches and candidate-string attempts. Scoping is lexical:
//! functions see their creation scopes and session bindings, never caller locals.

mod access;
mod builtin;
mod call;
mod compile;
mod copies;
mod evaluate;
mod explore;
mod frozen;
mod intrinsic;
mod plan;
mod run;
mod semantics;
mod setup;

pub(crate) use builtin::Builtin;
pub(crate) use explore::{Branching, Invocation, MAXIMUM_PATHS, Way, decode, explore};
pub(crate) use frozen::Frozen;
pub(crate) use intrinsic::{Intrinsics, intrinsics};
pub(crate) use plan::Plans;
pub(crate) use run::{Decrypted, Run, Spare};
pub(crate) use setup::setup;
