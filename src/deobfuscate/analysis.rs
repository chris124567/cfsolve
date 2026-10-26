//! Shared conservative analysis for deobfuscation rewrites.
//!
//! Allows a rewrite only when analysis proves it safe; unknown syntax prevents rewriting. Uses
//! resolved [`swc_core::ecma::ast::Id`] values for bindings, so results are valid only after
//! name resolution and before hygiene.

use swc_core::common::Mark;
use swc_core::ecma::ast::Program;

mod bindings;
pub(super) mod effects;
mod globals;
pub(super) mod hoisting;
pub(super) mod names;
mod properties;

pub(super) use bindings::Bindings;
pub(super) use globals::Globals;
pub(super) use properties::{Properties, constant_index, member_key, prop_key};

/// Caches analysis of the current program until a rewrite changes it. A rewrite that needs to
/// analyze its own changes must collect fresh results.
pub(crate) struct Analysis {
    /// Remains valid across rewrites.
    pub(crate) globals: Globals,
    bindings: Option<Bindings>,
    properties: Option<Properties>,
}

impl Analysis {
    #[must_use]
    pub(crate) fn new(unresolved_mark: Mark) -> Self {
        Self {
            globals: Globals::new(unresolved_mark),
            bindings: None,
            properties: None,
        }
    }

    #[must_use]
    pub(crate) fn bindings(&mut self, program: &Program) -> &Bindings {
        self.bindings
            .get_or_insert_with(|| Bindings::collect(program))
    }

    /// Returns binding and property summaries; property uses build on the bindings.
    #[must_use]
    pub(crate) fn properties(&mut self, program: &Program) -> (&Bindings, &Properties) {
        let bindings = self
            .bindings
            .get_or_insert_with(|| Bindings::collect(program));
        let properties = self
            .properties
            .get_or_insert_with(|| Properties::collect(program, bindings));
        (bindings, properties)
    }

    pub(crate) fn invalidate(&mut self) {
        self.bindings = None;
        self.properties = None;
    }
}
