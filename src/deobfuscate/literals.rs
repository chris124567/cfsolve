//! Restores plain expressions from minifier forms:
//!
//! ```js
//! !0; void 0; (0, f)(x); (0, Date).now();  // becomes true; undefined; f(x); Date.now()
//! var z = 0; (z, f)(x); (z, o).p;           // becomes f(x); o.p
//! ```
//!
//! Folds `!` and `void` only for effect-free literal operands. Unwraps inert callee sequences only
//! when the final value is an identifier other than `eval`, preserving call behavior. Also
//! simplifies inert sequences used for property access. A sequence is inert when its leading
//! operands are literals or reads of `var` and parameter bindings outside `with` statements: such
//! a read is initialized on entry, so it cannot throw, and no object can intercept it. New
//! `undefined` references resolve to the global binding.

use std::mem;

use oxc::allocator::{CloneIn, GetAllocator};
use oxc::ast::ast::{CallExpression, Expression, MemberExpression, Program, WithStatement};
use oxc::ast_visit::{VisitMut, walk_mut};
use oxc::syntax::operator::UnaryOperator;
use oxc::syntax::symbol::SymbolFlags;

use super::analysis::Analysis;
use super::ast;

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let mut restore = Restore {
        analysis,
        within_with: false,
        changed: false,
    };
    restore.visit_program(program);
    restore.changed
}

struct Restore<'b, 'a> {
    analysis: &'b Analysis<'a>,
    /// Whether the visited code is inside a `with` statement's body, where an object may
    /// intercept reads of any name.
    within_with: bool,
    changed: bool,
}

impl<'a> Restore<'_, 'a> {
    /// Splits an inert sequence (see the module documentation) into its value and leading
    /// operands.
    fn inert_sequence<'b>(
        &self,
        expression: &'b Expression<'a>,
    ) -> Option<(&'b Expression<'a>, &'b [Expression<'a>])> {
        let Expression::SequenceExpression(sequence) = expression.get_inner_expression() else {
            return None;
        };
        let (last, prefix) = sequence.expressions.split_last()?;
        prefix
            .iter()
            .all(|operand| self.is_inert(operand))
            .then_some((last, prefix))
    }

    fn is_inert(&self, operand: &Expression<'_>) -> bool {
        if operand.is_literal() {
            return true;
        }
        let Expression::Identifier(reference) = operand.get_inner_expression() else {
            return false;
        };
        !self.within_with
            && self
                .analysis
                .id(reference)
                .and_then(|id| id.local())
                .is_some_and(|symbol| {
                    self.analysis
                        .scoping
                        .symbol_flags(symbol)
                        .contains(SymbolFlags::FunctionScopedVariable)
                })
    }
}

impl<'a> VisitMut<'a> for Restore<'_, 'a> {
    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        walk_mut::walk_expression(self, expression);
        if let Expression::UnaryExpression(unary) = expression
            && let Some(value) = ast::truthiness(&unary.argument)
        {
            let builder = &self.analysis.ast;
            *expression = match unary.operator {
                UnaryOperator::LogicalNot => {
                    Expression::new_boolean_literal(unary.span, !value, builder)
                }
                UnaryOperator::Void => Expression::new_identifier(unary.span, "undefined", builder),
                _ => return,
            };
            self.changed = true;
        }
    }

    fn visit_call_expression(&mut self, call: &mut CallExpression<'a>) {
        walk_mut::walk_call_expression(self, call);
        if let Some((callee, _)) = self.inert_sequence(&call.callee)
            && let Expression::Identifier(identifier) = callee
            && identifier.name != "eval"
        {
            call.callee = callee.clone_in_with_semantic_ids(self.analysis.allocator());
            self.changed = true;
        }
    }

    fn visit_member_expression(&mut self, member: &mut MemberExpression<'a>) {
        walk_mut::walk_member_expression(self, member);
        if let Some((object, [_, ..])) = self.inert_sequence(member.object()) {
            *member.object_mut() = object.clone_in_with_semantic_ids(self.analysis.allocator());
            self.changed = true;
        }
    }

    fn visit_with_statement(&mut self, statement: &mut WithStatement<'a>) {
        self.visit_expression(&mut statement.object);
        let within_with = mem::replace(&mut self.within_with, true);
        self.visit_statement(&mut statement.body);
        self.within_with = within_with;
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn restores_literals_and_direct_calls() {
        let transform = |source: &str| testing::rewrite(source, super::run);
        let output =
            transform("function f() { return [!0, !1, !2, !'', !'a', !null, !![], !{}]; }");
        testing::assert_contains(
            &output,
            &["true, false, false, true, false, true, true, false"],
        );
        assert!(!output.contains('!'), "{output}");
        assert_eq!(transform(&output), output);
        let output = transform("function f(x) { x = void 0; return x === void 0 ? void 1 : x; }");
        let expected = ["x = undefined;", "x === undefined ? undefined : x"];
        testing::assert_contains(&output, &expected);
        assert!(!output.contains("void"), "{output}");
        // Operands that may have effects stay.
        let output = transform("function f(x) { return [!x, !f(), !x.y, void f(), void x]; }");
        testing::assert_contains(&output, &["!x", "!f()", "!x.y", "void f()", "void x"]);
        assert!(!output.contains("undefined"), "{output}");
        // Indirect calls of names other than `eval` become direct.
        let output = transform("function f(g, o) { (0, g)(this, 1); (0, o.m)(); (0, eval)('x'); }");
        testing::assert_contains(&output, &["g(this, 1);", "(0, o.m)();", "(0, eval)("]);
        // A property access uses the final value of the sequence as its object.
        let output = transform(
            "function f(o) { return [(0, Date).now(), (1, o).p, (0, o.a).push(1), (g(), o).q]; }",
        );
        testing::assert_contains(&output, &["Date.now(), o.p, o.a.push(1), (g(), o).q"]);
    }

    #[test]
    fn drops_reads_of_var_and_parameter_bindings_from_sequences() {
        let output = testing::rewrite(
            "function f(z, o, g) {
                var y = 0;
                let l = 0;
                const c = 0;
                use((z, g)(1), (y, o).p, (y, z, o).q, (l, g)(2), (c, o).r, (u, g)(3),
                    (y, o.m)(4), (y, eval)('x'));
                with (o) { use((y, g)(5), (y, o).s); }
            }",
            super::run,
        );
        testing::assert_contains(
            &output,
            &[
                "g(1), o.p, o.q, (l, g)(2), (c, o).r, (u, g)(3), (y, o.m)(4), (y, eval)(\"x\")",
                "use((y, g)(5), (y, o).s);",
            ],
        );
    }
}
