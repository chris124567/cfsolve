//! Analyzes disassembled listings without executing them: the initial iframe program
//! ([`crate::challenge::installed`]) and POST response programs ([`crate::stage2`]).
//!
//! [`Index`] caches lookups, [`fold`] resolves constants, and [`query`] traces value sources.
//! String-pool decoding works independently of randomized opcodes. Facts across control flow
//! come from [`crate::vm::dataflow`], which the disassembler shares.

pub(crate) mod fold;
mod index;
pub(crate) mod query;
mod strings;

pub(crate) use index::Index;
pub(crate) use strings::decode_string;
