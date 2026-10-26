//! Replaces a function literal's `length` with its parameter count, exposing constants hidden
//! by the obfuscator:
//!
//! ```js
//! ((a) => a).length + 2;  // becomes 1 + 2
//! ```
//!
//! Counts parameters before the first default or rest parameter, as `length` does.

use swc_core::ecma::ast::{Expr, Lit, Number, Pat, Program};
use swc_core::ecma::visit::{VisitMut, VisitMutWith};

use super::analysis::Analysis;
use crate::js::ast;

pub(super) fn run(program: &mut Program, _: &mut Analysis) -> bool {
    let mut lengths = FoldLengths { changed: false };
    program.visit_mut_with(&mut lengths);
    lengths.changed
}

struct FoldLengths {
    changed: bool,
}

impl VisitMut for FoldLengths {
    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        expression.visit_mut_children_with(self);
        if let Expr::Member(member) = expression
            && ast::member_str(&member.prop) == Some("length")
            && let Some(length) = literal_length(&member.obj)
        {
            *expression = Expr::Lit(Lit::Num(Number {
                span: member.span,
                value: length as f64,
                raw: None,
            }));
            self.changed = true;
        }
    }
}

/// The `length` of a function or arrow literal, possibly parenthesized.
fn literal_length(expression: &Expr) -> Option<usize> {
    let counted = |pattern: &&Pat| !matches!(pattern, Pat::Assign(_) | Pat::Rest(_));
    let length = match expression.unwrap_parens() {
        Expr::Arrow(arrow) => arrow.params.iter().take_while(counted).count(),
        Expr::Fn(function) => function
            .function
            .params
            .iter()
            .map(|parameter| &parameter.pat)
            .take_while(counted)
            .count(),
        _ => return None,
    };
    Some(length)
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn counts_parameters_before_defaults_and_rest() {
        let output = testing::rewrite(
            "f((a => a).length, (function(a, b) {}).length, ((a, b = 1, c) => a).length,
                ((...a) => a).length, g.length);",
            super::run,
            /* fix= */ true,
        );
        testing::assert_contains(&output, &[], &["f(1, 2, 1, 0, g.length)"]);
    }
}
