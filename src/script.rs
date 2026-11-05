//! One parsed, deobfuscated iframe or orchestrator script shared across session extractors.

use std::sync::OnceLock;

use anyhow::Result;

use swc_core::ecma::ast::CallExpr;
use swc_core::ecma::visit::{Visit, VisitWith};

use crate::js::ast::{self, ParsedScript};
use crate::vm::{self, Definition, Listing, Machine};

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

    /// The base64 text of the first literal program the script passes to its program runner, as
    /// in `<global>.<runner>("<base64>")`. The runner's name is random.
    #[must_use]
    pub fn embedded_program(&self) -> Option<String> {
        struct First<'name> {
            runner: &'name str,
            found: Option<String>,
        }

        impl Visit for First<'_> {
            fn visit_call_expr(&mut self, call: &CallExpr) {
                if self.found.is_none()
                    && vm::calls_runner(call, self.runner)
                    && let Some(program) = call
                        .args
                        .first()
                        .and_then(|argument| ast::static_str(&argument.expr))
                {
                    self.found = Some(program.to_owned());
                }
                call.visit_children_with(self);
            }
        }

        let runner = vm::runner_name(&self.parsed.script)?;
        let mut first = First {
            runner: &runner,
            found: None,
        };
        self.parsed.script.visit_with(&mut first);
        first.found
    }

    /// Disassembles `program` from its entry using [`Machine::disassemble`]. Probe analysis
    /// uses separate settings; see [`crate::stage2::analysis::analyze()`].
    pub fn disassemble(&self, program: &[u8]) -> Result<Listing> {
        self.machine()?.disassemble(program)
    }
}
