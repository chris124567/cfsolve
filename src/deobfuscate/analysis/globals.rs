//! Distinguishes references to browser globals from local bindings.

use swc_core::common::{Mark, Span, SyntaxContext};
use swc_core::ecma::ast::Ident;

/// Identifies unresolved references marked by the resolver. Only these refer to globals; a
/// local `Reflect` or `undefined` shadows the browser global.
#[derive(Clone, Copy)]
pub(crate) struct Globals {
    pub(crate) mark: Mark,
    /// The syntax context of every unresolved reference.
    pub(crate) unresolved: SyntaxContext,
}

impl Globals {
    #[must_use]
    pub(crate) fn new(unresolved_mark: Mark) -> Self {
        Self {
            mark: unresolved_mark,
            unresolved: SyntaxContext::empty().apply_mark(unresolved_mark),
        }
    }

    #[must_use]
    pub(crate) fn is(&self, identifier: &Ident, name: &str) -> bool {
        identifier.ctxt == self.unresolved && identifier.sym == name
    }

    #[must_use]
    pub(crate) fn reference(&self, name: &str, span: Span) -> Ident {
        Ident::new(name.into(), span, self.unresolved)
    }
}
