//! Removes fractional parts from bitwise operands:
//!
//! ```js
//! x & 255.51;  // becomes x & 255
//! ```
//!
//! Applies only to operators whose `ToInt32` or `ToUint32` conversion discards the fractional
//! part before evaluation.

use swc_core::ecma::ast::{AssignExpr, BinExpr, BinaryOp, Expr, Lit, Program, UnaryExpr, UnaryOp};
use swc_core::ecma::visit::{VisitMut, VisitMutWith};

use super::analysis::Analysis;

pub(super) fn run(program: &mut Program, _: &mut Analysis) -> bool {
    let mut truncate = TruncateOperands { changed: false };
    program.visit_mut_with(&mut truncate);
    truncate.changed
}

struct TruncateOperands {
    changed: bool,
}

impl VisitMut for TruncateOperands {
    fn visit_mut_bin_expr(&mut self, binary: &mut BinExpr) {
        binary.visit_mut_children_with(self);

        if is_bitwise(binary.op) {
            self.changed |= truncate_operand(&mut binary.left);
            self.changed |= truncate_operand(&mut binary.right);
        }
    }

    fn visit_mut_assign_expr(&mut self, assignment: &mut AssignExpr) {
        assignment.visit_mut_children_with(self);

        if assignment.op.to_update().is_some_and(is_bitwise) {
            self.changed |= truncate_operand(&mut assignment.right);
        }
    }

    fn visit_mut_unary_expr(&mut self, unary: &mut UnaryExpr) {
        unary.visit_mut_children_with(self);

        if unary.op == UnaryOp::Tilde {
            self.changed |= truncate_operand(&mut unary.arg);
        }
    }
}

pub(super) fn is_bitwise(operator: BinaryOp) -> bool {
    matches!(
        operator,
        BinaryOp::BitAnd
            | BinaryOp::BitOr
            | BinaryOp::BitXor
            | BinaryOp::LShift
            | BinaryOp::RShift
            | BinaryOp::ZeroFillRShift
    )
}

/// Returns whether a fractional part was removed.
fn truncate_operand(operand: &mut Expr) -> bool {
    match operand {
        Expr::Lit(Lit::Num(number)) if number.value.is_finite() && number.value.fract() != 0.0 => {
            number.value = number.value.trunc();
            number.raw = None;
            true
        }
        Expr::Paren(paren) => truncate_operand(&mut paren.expr),
        Expr::Unary(unary) if matches!(unary.op, UnaryOp::Plus | UnaryOp::Minus) => {
            truncate_operand(&mut unary.arg)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn truncates_only_bitwise_operands() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
        let output = transform(
            "function f(x) { return (x & 255.51) ^ (x | 8.27) ^ (x ^ 60.71) ^ (x << 16.7) ^ (x >> 12.15) ^ (x >>> 10.46); }",
        );
        let expected = [
            "x & 255", "x | 8", "x ^ 60", "x << 16", "x >> 12", "x >>> 10",
        ];
        testing::assert_contains(&output, &expected, &[]);
        assert!(!output.contains('.'), "{output}");
        assert_eq!(transform(&output), output);
        // Compound assignments, negated operands, and complements.
        let output =
            transform("function f(x) { x &= 63.01; x >>>= 3.94; y = x & -3.7; z = ~9.5; }");
        testing::assert_contains(&output, &["x &= 63", "x >>>= 3", "x & -3", "~9"], &[]);
        let output =
            transform("function f(x) { return [x & 255, x + 255.51, x * 1.5, 0.5, x(23.5)]; }");
        let kept = ["x & 255", "x + 255.51", "x * 1.5", "0.5", "x(23.5)"];
        testing::assert_contains(&output, &kept, &[]);
    }
}
