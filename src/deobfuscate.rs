//! Deobfuscates challenge scripts in repeated rewrite rounds using Oxc.
//!
//! Rewrites make further rewrites possible: decoding names allows helper inlining, which reveals
//! control flow and more calls. Each round runs the [`pipeline`] steps in order, skipping a step
//! that already left the current program unchanged. Rounds stop when the passes settle, a whole
//! round makes no net change, or the round limit is reached. Final hygiene resolves naming
//! conflicts introduced by moving references. Each rewrite module describes its transformation,
//! the patterns it accepts, and the conditions that keep it safe.

mod analysis;
mod argument_arrays;
mod arrow_blocks;
mod ast;
mod bitwise;
mod blocks;
mod call_helpers;
mod control_flow;
mod copy_propagation;
mod dead_branches;
mod dead_properties;
mod dispatch;
mod encoded_strings;
mod function_lengths;
mod helper_objects;
mod hygiene;
mod int32_helpers;
mod literals;
mod loops;
mod memoized_strings;
mod merged_functions;
mod pipeline;
mod register_arrays;
mod removal;
mod simplify;
mod state_machines;
mod statements;
mod static_members;
#[cfg(test)]
mod testing;
mod unused_bindings;

pub(crate) use encoded_strings::{Encoded, encode as encode_string, inline_strings};
pub use pipeline::{Deobfuscated, Unconverged, deobfuscate};
pub(crate) use pipeline::{decode, deobfuscate_capturing};

/// Fast hashing for identifier and node maps; no rewrite depends on their iteration order.
type HashMap<K, V> = rustc_hash::FxHashMap<K, V>;
type HashSet<T> = rustc_hash::FxHashSet<T>;
