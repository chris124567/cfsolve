//! Removes fractional parts from bitwise operands:
//!
//! ```js
//! x & 255.51;  // becomes x & 255
//! ```
//!
//! Applies only to operators whose `ToInt32` or `ToUint32` conversion discards the fractional
//! part before evaluation. Integer operands are also wrapped to their signed 32-bit
//! representation; shifts retain the same low bits and shift count after the corresponding
//! JavaScript conversions.

use oxc::ast::ast::{AssignmentExpression, BinaryExpression, Expression, Program, UnaryExpression};
use oxc::ast_visit::{VisitMut, walk_mut};
use oxc::span::GetSpan;

use super::analysis::Analysis;
use super::ast;
use crate::js;

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let mut truncate = Truncate {
        analysis,
        changed: false,
    };
    truncate.visit_program(program);
    truncate.changed
}

struct Truncate<'b, 'a> {
    analysis: &'b Analysis<'a>,
    changed: bool,
}

impl<'a> Truncate<'_, 'a> {
    fn truncate(&mut self, operand: &mut Expression<'a>) {
        if let Some(number) = ast::number(operand) {
            let truncated = js::int32(number) as f64;
            if number != truncated {
                *operand = ast::number_literal(operand.span(), truncated, &self.analysis.ast);
                self.changed = true;
            }
        }
    }
}

impl<'a> VisitMut<'a> for Truncate<'_, 'a> {
    fn visit_binary_expression(&mut self, binary: &mut BinaryExpression<'a>) {
        walk_mut::walk_binary_expression(self, binary);
        if binary.operator.is_bitwise() {
            self.truncate(&mut binary.left);
            self.truncate(&mut binary.right);
        }
    }

    fn visit_assignment_expression(&mut self, assignment: &mut AssignmentExpression<'a>) {
        walk_mut::walk_assignment_expression(self, assignment);
        if assignment.operator.is_bitwise() {
            self.truncate(&mut assignment.right);
        }
    }

    fn visit_unary_expression(&mut self, unary: &mut UnaryExpression<'a>) {
        walk_mut::walk_unary_expression(self, unary);
        if unary.operator.is_bitwise() {
            self.truncate(&mut unary.argument)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn truncates_only_bitwise_operands() {
        let transform = |source: &str| testing::rewrite(source, super::run);
        let output = transform(
            "function f(x) { return (x & 255.51) ^ (x | 8.27) ^ (x ^ 60.71) ^ (x << 16.7) ^ (x >> 12.15) ^ (x >>> 10.46); }",
        );
        let expected = [
            "x & 255", "x | 8", "x ^ 60", "x << 16", "x >> 12", "x >>> 10",
        ];
        testing::assert_contains(&output, &expected);
        assert!(!output.contains('.'), "{output}");
        assert_eq!(transform(&output), output);
        // Compound assignments, negated operands, and complements.
        let output =
            transform("function f(x) { x &= 63.01; x >>>= 3.94; y = x & -3.7; z = ~9.5; }");
        testing::assert_contains(&output, &["x &= 63", "x >>>= 3", "x & -3", "~9"]);
        let output =
            transform("function f(x) { return [x & 255, x + 255.51, x * 1.5, 0.5, x(23.5)]; }");
        let kept = ["x & 255", "x + 255.51", "x * 1.5", ".5", "x(23.5)"];
        testing::assert_contains(&output, &kept);
    }
}
