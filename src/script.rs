//! One parsed, deobfuscated iframe or orchestrator script shared across session extractors.

use std::sync::OnceLock;

use anyhow::Result;

use crate::js::ast::{self, ParsedScript};
use crate::vm::{Definition, Listing, Machine};

/// A parsed iframe script shared by encoder extraction, parameter merging, scene recovery, and
/// VM analysis. Rejects scripts with recoverable parse errors.
pub struct Source {
    parsed: ParsedScript,
    /// Lazily recovered VM, needed only when the session analyzes a program.
    definition: OnceLock<Definition>,
}

impl Source {
    /// Parses `text`. Defers VM recovery and its possible errors until the VM is requested.
    pub fn try_new(text: &str) -> Result<Self> {
        Ok(Self {
            parsed: ast::parse_iframe_javascript(text)?,
            definition: OnceLock::new(),
        })
    }

    #[must_use]
    pub(crate) fn parsed(&self) -> &ParsedScript {
        &self.parsed
    }

    /// The VM the script defines, ready to decode one program.
    pub fn machine(&self) -> Result<Machine<'_>> {
        let definition = match self.definition.get() {
            Some(definition) => definition,
            None => {
                let definition = Definition::from_script(&self.parsed.script)?;
                self.definition.get_or_init(|| definition)
            }
        };
        Machine::try_new(definition)
    }

    /// Disassembles `program` from its entry using [`Machine::disassemble`]. Probe analysis
    /// uses separate settings; see [`crate::stage2::analysis::analyze()`].
    pub fn disassemble(&self, program: &[u8]) -> Result<Listing> {
        self.machine()?.disassemble(program)
    }
}
