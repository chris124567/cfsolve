//! The straight-line integer mixer used for instruction positions and string offsets. Match
//! every operation and recover its constants; leave all other functions to the interpreter.

use oxc::ast::ast::{
    AssignmentExpression, AssignmentOperator, AssignmentTarget, BinaryExpression, Expression,
    Function, Statement,
};
use oxc::semantic::SymbolId;
use oxc::syntax::operator::BinaryOperator;

use crate::js;
use crate::js::ast::{self, Script};
use crate::vm::extract;

#[derive(Clone, Copy)]
pub(crate) struct Mix32 {
    seed: i32,
    rounds: [Round; 2],
    final_shift: u32,
}

/// `x = (x ^ x >>> shift) * multiplier | 0`.
#[derive(Clone, Copy)]
struct Round {
    shift: u32,
    multiplier: f64,
}

impl Mix32 {
    pub(super) fn recognize(script: Script<'_>, function: &Function<'_>) -> Option<Self> {
        if function.r#async || function.generator {
            return None;
        }
        let [parameter] = extract::parameters(&function.params)?[..] else {
            return None;
        };
        let parameter = parameter.symbol_id();
        let body = function.body.as_deref()?;
        if !body.directives.is_empty() {
            return None;
        }
        // Statements after the `return` never run, unless they declare something.
        let statements = &body.statements;
        let end = statements
            .iter()
            .position(|statement| matches!(statement, Statement::ReturnStatement(_)))?
            + 1;
        if statements[end..].iter().any(Statement::is_declaration) {
            return None;
        }
        let [seed, first, second, returned] = &statements[..end] else {
            return None;
        };
        let Statement::ReturnStatement(returned) = returned else {
            return None;
        };
        let seed = assignment(seed)?;
        if !is_target(script, &seed.left, parameter)
            || seed.operator != AssignmentOperator::BitwiseXOR
        {
            return None;
        }
        Some(Self {
            seed: js::int32(number(&seed.right)?),
            rounds: [
                round(script, parameter, first)?,
                round(script, parameter, second)?,
            ],
            final_shift: mixed(script, parameter, returned.argument.as_ref()?)?,
        })
    }

    pub(super) fn call(self, number: f64) -> f64 {
        let mut value = js::int32(number) ^ self.seed;
        for Round { shift, multiplier } in self.rounds {
            let mixed = value ^ ((value as u32) >> shift) as i32;
            value = js::int32(f64::from(mixed) * multiplier);
        }
        f64::from(value ^ ((value as u32) >> self.final_shift) as i32)
    }
}

fn number(expression: &Expression<'_>) -> Option<f64> {
    ast::fold_number(expression, &|_| None)
}

/// Whether `expression`, inside any parentheses, is a reference to `symbol`.
pub(super) fn is_symbol(script: Script<'_>, expression: &Expression<'_>, symbol: SymbolId) -> bool {
    script.refers_to(expression.without_parentheses(), symbol)
}

/// Whether an assignment target is the identifier of `symbol`.
fn is_target(script: Script<'_>, target: &AssignmentTarget<'_>, symbol: SymbolId) -> bool {
    matches!(target, AssignmentTarget::AssignmentTargetIdentifier(name)
        if script.symbol(name) == Some(symbol))
}

/// The assignment an expression statement makes.
pub(super) fn assignment<'s, 'a>(
    statement: &'s Statement<'a>,
) -> Option<&'s AssignmentExpression<'a>> {
    match statement {
        Statement::ExpressionStatement(statement) => match &statement.expression {
            Expression::AssignmentExpression(assignment) => Some(assignment),
            _ => None,
        },
        _ => None,
    }
}

/// The binary expression inside any parentheses.
pub(super) fn binary<'s, 'a>(expression: &'s Expression<'a>) -> Option<&'s BinaryExpression<'a>> {
    match expression.without_parentheses() {
        Expression::BinaryExpression(binary) => Some(binary),
        _ => None,
    }
}

/// The shift of `x ^ x >>> shift`, where `x` is the `parameter`.
fn mixed(script: Script<'_>, parameter: SymbolId, expression: &Expression<'_>) -> Option<u32> {
    let is_parameter = |expression: &Expression<'_>| is_symbol(script, expression, parameter);
    let xor = binary(expression)?;
    if xor.operator != BinaryOperator::BitwiseXOR {
        return None;
    }
    let shifted = if is_parameter(&xor.left) {
        &xor.right
    } else if is_parameter(&xor.right) {
        &xor.left
    } else {
        return None;
    };
    let shifted = binary(shifted)?;
    if shifted.operator != BinaryOperator::ShiftRightZeroFill || !is_parameter(&shifted.left) {
        return None;
    }
    Some(js::int32(number(&shifted.right)?) as u32 & 31)
}

fn round(script: Script<'_>, parameter: SymbolId, statement: &Statement<'_>) -> Option<Round> {
    let assignment = assignment(statement)?;
    if assignment.operator != AssignmentOperator::Assign
        || !is_target(script, &assignment.left, parameter)
    {
        return None;
    }
    let truncated = binary(&assignment.right)?;
    if truncated.operator != BinaryOperator::BitwiseOR {
        return None;
    }
    let product = if number(&truncated.left) == Some(0.0) {
        &truncated.right
    } else if number(&truncated.right) == Some(0.0) {
        &truncated.left
    } else {
        return None;
    };
    let product = binary(product)?;
    if product.operator != BinaryOperator::Multiplication {
        return None;
    }
    let (shift, multiplier) = match number(&product.left) {
        Some(multiplier) => (mixed(script, parameter, &product.right)?, multiplier),
        None => (
            mixed(script, parameter, &product.left)?,
            number(&product.right)?,
        ),
    };
    Some(Round { shift, multiplier })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::interpret::register_helpers::tests::assert_native_matches_interpreted;

    #[test]
    fn native_mixers_match_their_scripts() {
        for source in [
            "function f(x) { x ^= 1265281276; x = (x ^ x >>> 16) * 40503 | 0; x = 13849 * (x ^ x >>> 13) | 0; return x >>> 16 ^ x; }",
            "function f(renamed) { renamed ^= -123; renamed = 0 | 7 * (renamed >>> 3 ^ renamed); renamed = ((renamed ^ renamed >>> 0) * 11) | 0; return renamed ^ renamed >>> 31; }",
            "function f(x) { x ^= 1265281276; x = (x >>> 16 ^ x) * 40503 | 0; x = 0 | 13849 * (x ^ x >>> 13); return x ^ x >>> 16; return; }",
        ] {
            assert_native_matches_interpreted(source, |script, function| {
                Mix32::recognize(script, function).is_some()
            });
        }
    }
}
