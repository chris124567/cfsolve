//! Deobfuscates Cloudflare challenge scripts in repeated rewrite rounds.
//!
//! Rewrites make further rewrites possible: decoding names allows helper inlining, which
//! reveals control flow and more calls. Each round runs the [`pipeline`] steps in order. A step
//! is skipped if it already left the current program unchanged. Rounds stop when all steps have
//! processed the current program or a whole round makes no net change. The final hygiene pass
//! resolves naming conflicts. Each rewrite module describes its transformation.

/// Fast hashing for the rewrites' identifier and node maps; no rewrite depends on their order.
type HashMap<K, V> = rustc_hash::FxHashMap<K, V>;
type HashSet<T> = rustc_hash::FxHashSet<T>;

mod analysis;
mod argument_arrays;
mod arrow_blocks;
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
mod int32_helpers;
mod literals;
mod loops;
mod memoized_strings;
mod merged_functions;
mod pipeline;
mod register_arrays;
mod removal;
mod state_machines;
mod statements;
mod static_members;
#[cfg(test)]
mod testing;
mod unused_bindings;

pub(crate) use encoded_strings::{Encoded, encode as encode_string, inline_strings};
pub use pipeline::{Deobfuscated, Unconverged, deobfuscate};
pub(crate) use pipeline::{deobfuscate_with, read_decoded};
