//! Disassembles challenge VM programs using handlers recovered from each session.
//!
//! The iframe defines a register-machine class whose `run` method decodes opcodes and calls
//! handlers; handlers, opcodes and masks vary by session. [`Machine::disassemble`] interprets
//! the handlers symbolically over program bytes to recover reachable instructions, effects and
//! successors.
//!
//! Bytes that do not decode produce [`Failure`] entries while disassembly continues. Handler
//! code the interpreter does not follow ends a path with [`Exit::Unfollowed`]. Reaching one
//! program counter under two dispatch keys stops disassembly, because a listing stores one
//! instruction per counter.

mod convert;
pub(crate) mod dataflow;
mod disassemble;
mod dispatch;
mod extract;
mod interpret;
mod machine;
mod output;
mod registers;
mod session;
mod value;

pub use disassemble::catch_frame;
pub(crate) use extract::{calls_runner, runner_name};
pub use machine::{Definition, Machine};
pub use output::{
    Cause, Constant, Effect, Exit, Failure, Hidden, Instruction, Listing, Path, Position, Term,
};

/// FxHash maps for the VM's small keys.
pub(crate) type HashMap<K, V> = rustc_hash::FxHashMap<K, V>;
