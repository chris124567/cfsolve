//! Replaces calls to helpers that reconstruct their argument's low bits by counting:
//!
//! ```js
//! function convert(x) {
//!     var low = x & 7, count = 0;
//!     for (; low; low--) { count++; }
//!     return x & -8 | count;
//! }
//! convert(a & 255);  // becomes a & 255
//! convert(a);        // becomes a | 0
//! ```
//!
//! The helper is `ToInt32` when its two masks complement each other, so an argument that is
//! already a 32-bit integer is returned unchanged. Requires a helper declared once. Removes the
//! helper once no reads remain.

use std::slice;

use oxc::allocator::{CloneIn, GetAllocator};
use oxc::ast::ast::{Expression, Function, Program, SimpleAssignmentTarget, Statement};
use oxc::ast_visit::{VisitMut, walk_mut};
use oxc::syntax::operator::{BinaryOperator, UpdateOperator};

use super::analysis::{Analysis, Id};
use super::{HashMap, HashSet, ast, removal};
use crate::js;

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let accept = |function: &Function<'_>| is_helper(function, analysis).unwrap_or(false);
    let helpers: HashSet<Id> = ast::functions(program, analysis, &accept)
        .into_keys()
        .collect();
    let mut inline = Inline {
        analysis,
        helpers: &helpers,
        replaced: HashMap::default(),
    };
    inline.visit_program(program);
    let unread = removal::unread(&inline.replaced, analysis);
    removal::remove_function_declarations(program, &unread);
    !inline.replaced.is_empty()
}

/// Matches `argument & mask` when the mask is an exactly representable signed 32-bit integer.
fn masked(expression: &Expression<'_>, argument: Id, analysis: &Analysis<'_>) -> Option<i32> {
    let Expression::BinaryExpression(binary) = expression.get_inner_expression() else {
        return None;
    };
    if binary.operator != BinaryOperator::BitwiseAnd
        || analysis.expression_id(&binary.left) != Some(argument)
    {
        return None;
    }
    let mask = ast::number(&binary.right)?;
    let exact = mask.fract() == 0.0 && (i32::MIN as f64..=i32::MAX as f64).contains(&mask);
    exact.then_some(mask as i32)
}

fn updated(
    expression: &Expression<'_>,
    operator: UpdateOperator,
    analysis: &Analysis<'_>,
) -> Option<Id> {
    let Expression::UpdateExpression(update) = expression.get_inner_expression() else {
        return None;
    };
    let SimpleAssignmentTarget::AssignmentTargetIdentifier(target) = &update.argument else {
        return None;
    };
    if update.operator != operator {
        return None;
    }
    analysis.id(target)
}

/// Recognizes a single-parameter function that counts the low masked bits, then combines the
/// count with the complementary high-bit mask. Requires the expected decrement and increment
/// loop, and no other declarations or statements that could affect the result.
fn is_helper(function: &Function<'_>, analysis: &Analysis<'_>) -> Option<bool> {
    let [argument] = ast::parameters(function)?[..] else {
        return None;
    };
    let [
        declarations @ ..,
        Statement::ForStatement(counting),
        Statement::ReturnStatement(returned),
    ] = function.body.as_ref()?.statements.as_slice()
    else {
        return None;
    };
    let mut declarators = vec![];
    for statement in declarations {
        let Statement::VariableDeclaration(declaration) = statement else {
            return None;
        };
        declarators.extend(&declaration.declarations)
    }
    let [low, count] = declarators[..] else {
        return None;
    };
    let low_id = ast::pattern_id(&low.id)?;
    let count_id = ast::pattern_id(&count.id)?;
    let mask = masked(low.init.as_ref()?, argument, analysis)?;
    let Expression::BinaryExpression(combined) = returned.argument.as_ref()?.get_inner_expression()
    else {
        return None;
    };
    let body = match &counting.body {
        Statement::BlockStatement(block) => block.body.as_slice(),
        statement => slice::from_ref(statement),
    };
    let [Statement::ExpressionStatement(increment)] = body else {
        return None;
    };
    let tested = counting.test.as_ref()?;
    let decrement = counting.update.as_ref()?;
    Some(
        mask >= 0
            && count.init.as_ref().and_then(ast::number) == Some(0.0)
            && counting.init.is_none()
            && analysis.expression_id(tested) == Some(low_id)
            && updated(decrement, UpdateOperator::Decrement, analysis) == Some(low_id)
            && updated(&increment.expression, UpdateOperator::Increment, analysis)
                == Some(count_id)
            && combined.operator == BinaryOperator::BitwiseOR
            && masked(&combined.left, argument, analysis) == Some(!mask)
            && analysis.expression_id(&combined.right) == Some(count_id),
    )
}

/// Checks whether an expression always evaluates to a signed 32-bit integer.
fn is_int32(expression: &Expression<'_>) -> bool {
    match expression.get_inner_expression() {
        Expression::BinaryExpression(binary) => {
            binary.operator.is_bitwise() && binary.operator != BinaryOperator::ShiftRightZeroFill
        }
        Expression::UnaryExpression(unary) => unary.operator.is_bitwise(),
        _ => ast::number(expression).is_some_and(|number| number == js::int32(number) as f64),
    }
}

struct Inline<'b, 'a> {
    analysis: &'b Analysis<'a>,
    helpers: &'b HashSet<Id>,
    replaced: HashMap<Id, usize>,
}

impl<'a> VisitMut<'a> for Inline<'_, 'a> {
    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        walk_mut::walk_expression(self, expression);
        if let Some((callee, [argument])) = ast::direct_call(expression)
            && let Some(id) = self.analysis.id(callee)
            && self.helpers.contains(&id)
            && let Some(argument) = argument.as_expression()
        {
            let builder = &self.analysis.ast;
            let span = callee.span;
            let value = argument.clone_in_with_semantic_ids(builder.allocator());
            *expression = if is_int32(&value) {
                value
            } else {
                let zero = ast::number_literal(span, 0.0, builder);
                Expression::new_binary_expression(
                    span,
                    value,
                    BinaryOperator::BitwiseOR,
                    zero,
                    builder,
                )
            };
            *self.replaced.entry(id).or_default() += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    const HELPER: &str = "function convert(x) {
        var low = x & 7, count = 0;
        for (; low; low--) { count++; }
        return x & -8 | count;
    }";

    #[test]
    fn inlines_helpers_whose_masks_complement() {
        let transform = |source: &str| testing::rewrite(source, super::run);
        let output = transform(&format!(
            "{HELPER}\nf(convert(a - b & 255), convert(a), convert(~a));"
        ));
        testing::assert_contains(&output, &["f(a - b & 255, a | 0, ~a)"]);
        assert!(!output.contains("function convert"), "{output}");
        let helper = HELPER.replace("-8", "-16");
        let output = transform(&format!("{helper}\nf(convert(a & 255));"));
        assert!(output.contains("convert(a & 255)"), "{output}");
    }
}
