//! Replaces a function literal's `length` with its parameter count, exposing constants hidden
//! by the obfuscator:
//!
//! ```js
//! ((a) => a).length + 2;  // becomes 1 + 2
//! ```
//!
//! Counts parameters before the first default or rest parameter, as `length` does.

use oxc::ast::ast::{Expression, Program};
use oxc::ast_visit::{VisitMut, walk_mut};
use oxc::span::GetSpan;

use super::analysis::Analysis;
use super::ast;

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let mut lengths = Lengths {
        analysis,
        changed: false,
    };
    lengths.visit_program(program);
    lengths.changed
}

struct Lengths<'b, 'a> {
    analysis: &'b Analysis<'a>,
    changed: bool,
}

impl<'a> VisitMut<'a> for Lengths<'_, 'a> {
    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        walk_mut::walk_expression(self, expression);
        let Some(member) = expression.as_member_expression() else {
            return;
        };
        if member
            .static_property_name()
            .is_none_or(|key| key != "length")
        {
            return;
        }
        let parameters = match member.object().get_inner_expression() {
            Expression::FunctionExpression(function) => &function.params,
            Expression::ArrowFunctionExpression(function) => &function.params,
            _ => return,
        };
        let items = parameters.items.iter();
        let length = items.take_while(|item| item.initializer.is_none()).count() as f64;
        *expression = ast::number_literal(expression.span(), length, &self.analysis.ast);
        self.changed = true;
    }
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
        );
        testing::assert_contains(&output, &["f(1, 2, 1, 0, g.length)"]);
    }
}
