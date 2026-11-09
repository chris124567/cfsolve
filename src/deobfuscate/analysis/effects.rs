//! Tracks the bindings an expression reads and writes.

use oxc::ast::ast::{ArrowFunctionExpression, Expression, Function, IdentifierReference};
use oxc::ast_visit::{Visit, walk};
use oxc::syntax::scope::ScopeFlags;

use super::{Analysis, Id};
use crate::deobfuscate::HashSet;

/// Binding reads and writes outside function bodies, since creating a closure does not run its
/// body. Calls, construction, tagged templates, `await`, and `yield` are opaque: they may change
/// a binding through code that this local scan cannot analyze.
#[derive(Default)]
pub(in crate::deobfuscate) struct Effects {
    pub reads: HashSet<Id>,
    pub writes: HashSet<Id>,
    pub opaque: bool,
}

impl Effects {
    /// Uses reference flags, so writes include destructuring targets.
    pub(crate) fn expression(expression: &Expression<'_>, analysis: &Analysis<'_>) -> Self {
        let mut uses = Uses {
            analysis,
            effects: Self::default(),
        };
        uses.visit_expression(expression);
        uses.effects
    }
}

struct Uses<'b, 'a> {
    analysis: &'b Analysis<'a>,
    effects: Effects,
}

impl<'a> Visit<'a> for Uses<'_, 'a> {
    fn visit_identifier_reference(&mut self, reference: &IdentifierReference<'a>) {
        if let Some(id) = self.analysis.id(reference) {
            let reference_id = reference.reference_id.get().expect("resolved reference");
            let flags = self.analysis.scoping.get_reference(reference_id).flags();
            if flags.is_read() {
                self.effects.reads.insert(id);
            }
            if flags.is_write() {
                self.effects.writes.insert(id);
            }
        }
    }

    fn visit_expression(&mut self, expression: &Expression<'a>) {
        self.effects.opaque |= matches!(
            expression,
            Expression::CallExpression(_)
                | Expression::NewExpression(_)
                | Expression::TaggedTemplateExpression(_)
                | Expression::AwaitExpression(_)
                | Expression::YieldExpression(_)
        );
        walk::walk_expression(self, expression)
    }

    fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}

    fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {}
}
