//! Folds constant expressions with Oxc's ECMAScript evaluator:
//!
//! ```js
//! use("3" - 1, "a" + 2, "a" === "a");  // becomes use(2, "a2", true)
//! ```
//!
//! A known result does not erase observable evaluation, such as the call in `void effect()`.
//! Constant conditionals and logical expressions keep only the chosen value when testing the
//! discarded operand is effect-free. String results keep lone surrogates. `void` spelling is
//! handled by [`super::literals`].

use oxc::allocator::{CloneIn, GetAllocator};
use oxc::ast::ast::{Expression, Program};
use oxc::ast_visit::{VisitMut, walk_mut};
use oxc::span::GetSpan;
use oxc::syntax::operator::{LogicalOperator, UnaryOperator};
use oxc_ecmascript::ConstantValue;
use oxc_ecmascript::constant_evaluation::ConstantEvaluation;
use oxc_ecmascript::side_effects::MayHaveSideEffects;

use super::analysis::Analysis;
use super::ast;

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let mut fold = Fold {
        analysis,
        changed: false,
    };
    fold.visit_program(program);
    fold.changed
}

struct Fold<'b, 'a> {
    analysis: &'b Analysis<'a>,
    changed: bool,
}

impl<'a> Fold<'_, 'a> {
    fn fold(&self, expression: &Expression<'a>) -> Option<Expression<'a>> {
        let analysis = self.analysis;
        let kept = match expression {
            Expression::SequenceExpression(sequence) if sequence.expressions.len() == 1 => {
                Some(&sequence.expressions[0])
            }
            Expression::ConditionalExpression(conditional) => {
                let test = conditional.test.get_side_free_boolean_value(analysis);
                test.map(|test| {
                    if test {
                        &conditional.consequent
                    } else {
                        &conditional.alternate
                    }
                })
            }
            Expression::LogicalExpression(logical) => {
                let test = logical.left.get_side_free_boolean_value(analysis);
                match (logical.operator, test) {
                    (LogicalOperator::And, Some(true)) | (LogicalOperator::Or, Some(false)) => {
                        Some(&logical.right)
                    }
                    (LogicalOperator::And, Some(false)) | (LogicalOperator::Or, Some(true)) => {
                        Some(&logical.left)
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        if let Some(kept) = kept {
            return Some(kept.clone_in_with_semantic_ids(analysis.allocator()));
        }
        match expression {
            Expression::BinaryExpression(_) => {}
            Expression::UnaryExpression(unary) if unary.operator != UnaryOperator::Void => {}
            _ => return None,
        }
        if expression.may_have_side_effects(analysis) {
            return None;
        }
        let span = expression.span();
        match expression.evaluate_value(analysis)? {
            ConstantValue::Number(number) if number.is_finite() => {
                Some(ast::number_literal(span, number, &analysis.ast))
            }
            ConstantValue::Boolean(value) => {
                Some(Expression::new_boolean_literal(span, value, analysis))
            }
            ConstantValue::String(value) => {
                Some(Expression::new_string_literal(span, value, None, analysis))
            }
            ConstantValue::Null => Some(Expression::new_null_literal(span, analysis)),
            _ => None,
        }
    }
}

impl<'a> VisitMut<'a> for Fold<'_, 'a> {
    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        walk_mut::walk_expression(self, expression);
        if let Some(replacement) = self.fold(expression) {
            *expression = replacement;
            self.changed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use oxc::allocator::Allocator;
    use oxc::ast::ast::{Expression, Statement};

    use crate::deobfuscate::{ast, pipeline, testing};

    #[test]
    fn folds_nested_parenthesized_arithmetic_before_callee_cleanup() {
        let output = testing::rewrite(
            "use(27253 ^ (36202 ^ 59167), (27253 ^ (36202 ^ 59167), f)(x));",
            super::run,
        );
        testing::assert_contains(&output, &["use(0, (0, f)(x));"]);
    }

    #[test]
    fn uses_ecmascript_coercions_and_preserves_lone_surrogates() {
        let output = testing::rewrite(
            r#"use("3" - 1, "a" + 2, "a" === "a", "\uD800" + "\uDC00");"#,
            super::run,
        );
        testing::assert_contains(&output, &["use(2, \"a2\", true,"]);
        let allocator = Allocator::default();
        let (program, _) = pipeline::parse(&allocator, &output).unwrap();
        let Statement::ExpressionStatement(statement) = &program.body[0] else {
            panic!("expected call")
        };
        let Expression::CallExpression(call) = &statement.expression else {
            panic!("expected call")
        };
        let string = ast::static_string(call.arguments[3].as_expression().unwrap()).unwrap();
        assert_eq!(string.encode_utf16().collect::<Vec<_>>(), [0xd800, 0xdc00]);
    }

    #[test]
    fn preserves_effects_in_constant_valued_conditions() {
        let output = testing::rewrite("use((void effect()) ? a : b);", super::run);
        assert!(output.contains("effect()"), "{output}");
    }
}
