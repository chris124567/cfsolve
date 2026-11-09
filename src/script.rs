//! One parsed, deobfuscated iframe or orchestrator script shared across session extractors.

use anyhow::{Result, anyhow};
use self_cell::self_cell;

use crate::js::ast::{ParsedScript, Script};
use crate::vm::{Definition, Listing, Machine};

/// The VM a script defines, or why recovery failed. Recovery runs with the parse because the
/// definition borrows the tree; the error surfaces only when the VM is requested.
struct Recovered<'a>(Result<Definition<'a>>);

self_cell!(
    struct Cell {
        owner: ParsedScript,
        #[covariant]
        dependent: Recovered,
    }
);

/// A parsed iframe script shared by encoder extraction, parameter merging, scene recovery, and
/// VM analysis. Rejects scripts with recoverable parse errors.
pub struct Source(Cell);

// SAFETY: The definition holds only shared references into the tree the `ParsedScript` owns, and
// plain data. `ParsedScript` is `Send` and `Sync` because the tree is immutable once built; see
// its implementations.
unsafe impl Send for Source {}
// SAFETY: See `Send` above.
unsafe impl Sync for Source {}

impl Source {
    /// Parses `text` and recovers its VM. Errors from VM recovery are deferred until the VM is
    /// requested.
    pub fn try_new(text: &str) -> Result<Self> {
        let parsed = ParsedScript::parse("deobfuscated script", text)?;
        Ok(Self(Cell::new(parsed, |parsed| {
            Recovered(Definition::from_script(parsed.script()))
        })))
    }

    #[must_use]
    pub(crate) fn script(&self) -> Script<'_> {
        self.0.borrow_owner().script()
    }

    /// The VM the script defines, ready to decode one program.
    pub fn machine(&self) -> Result<Machine<'_>> {
        match &self.0.borrow_dependent().0 {
            Ok(definition) => Machine::try_new(definition),
            Err(error) => Err(anyhow!("{error:#}")),
        }
    }

    /// Disassembles `program` from its entry using [`Machine::disassemble`]. Probe analysis
    /// uses separate settings; see [`crate::stage2::analysis::analyze()`].
    pub fn disassemble(&self, program: &[u8]) -> Result<Listing> {
        self.machine()?.disassemble(program)
    }
}
