//! Integer formulas captured from scripts, evaluated with JavaScript's number semantics.
//!
//! The obfuscator varies the arithmetic of some helpers per build. A [`super::pattern`]
//! template captures such arithmetic as a formula over named inputs instead of fixing it.

use oxc::ast::ast::{Expression, IdentifierReference};
use oxc::syntax::operator::BinaryOperator;

use crate::js;
use crate::vm::convert;
use crate::vm::value::Value;

/// An expression of numeric literals, named inputs, indexed inputs, and arithmetic or bitwise
/// operators.
#[derive(Clone)]
pub(super) enum Formula {
    Number(f64),
    Input(String),
    Index {
        input: String,
        index: Box<Formula>,
    },
    Binary {
        operator: BinaryOperator,
        left: Box<Formula>,
        right: Box<Formula>,
    },
}

/// A formula input's value.
pub(super) enum Input<'a, 'ast> {
    Number(f64),
    Array(&'a [Value<'ast>]),
    Bytes(&'a [u8]),
}

impl Formula {
    /// Compiles `expression`, with each subexpression in the form `normal` gives it, naming each
    /// identifier with `name`. Returns `None` for anything outside the supported forms.
    pub(super) fn compile<'e>(
        expression: &'e Expression<'e>,
        normal: &impl Fn(&'e Expression<'e>) -> &'e Expression<'e>,
        name: &impl Fn(&IdentifierReference<'_>) -> Option<String>,
    ) -> Option<Self> {
        let compile = |expression| Self::compile(expression, normal, name);
        Some(match normal(expression).without_parentheses() {
            Expression::NumericLiteral(number) => Self::Number(number.value),
            Expression::Identifier(identifier) => Self::Input(name(identifier)?),
            Expression::ComputedMemberExpression(member) => {
                let Expression::Identifier(input) = normal(&member.object) else {
                    return None;
                };
                Self::Index {
                    input: name(input)?,
                    index: Box::new(compile(&member.expression)?),
                }
            }
            Expression::BinaryExpression(binary)
                if matches!(
                    binary.operator,
                    BinaryOperator::BitwiseAnd
                        | BinaryOperator::BitwiseOR
                        | BinaryOperator::BitwiseXOR
                        | BinaryOperator::Addition
                        | BinaryOperator::Subtraction
                        | BinaryOperator::Multiplication
                        | BinaryOperator::ShiftLeft
                        | BinaryOperator::ShiftRight
                        | BinaryOperator::ShiftRightZeroFill
                ) =>
            {
                Self::Binary {
                    operator: binary.operator,
                    left: Box::new(compile(&binary.left)?),
                    right: Box::new(compile(&binary.right)?),
                }
            }
            _ => return None,
        })
    }

    /// Evaluates the formula as the script would, given every input's value by name. Returns
    /// `None` where the script would see a non-number, such as an index out of range.
    pub(super) fn evaluate(&self, inputs: &[(&str, Input<'_, '_>)]) -> Option<f64> {
        let input = |name: &str| {
            let (_, input) = inputs.iter().find(|(found, _)| *found == name)?;
            Some(input)
        };
        Some(match self {
            Self::Number(number) => *number,
            Self::Input(name) => match input(name)? {
                Input::Number(number) => *number,
                Input::Array(_) | Input::Bytes(_) => return None,
            },
            Self::Index { input: name, index } => {
                let index = convert::index(index.evaluate(inputs)?)?;
                match input(name)? {
                    Input::Array(elements) => match elements.get(index)? {
                        Value::Number(number) => *number,
                        _ => return None,
                    },
                    Input::Bytes(bytes) => f64::from(*bytes.get(index)?),
                    Input::Number(_) => return None,
                }
            }
            Self::Binary {
                operator,
                left,
                right,
            } => {
                // Operands are numbers, so each operator is its numeric case.
                let (left, right) = (left.evaluate(inputs)?, right.evaluate(inputs)?);
                let shift = || js::int32(right) as u32 & 31;
                match operator {
                    BinaryOperator::BitwiseAnd => f64::from(js::int32(left) & js::int32(right)),
                    BinaryOperator::BitwiseOR => f64::from(js::int32(left) | js::int32(right)),
                    BinaryOperator::BitwiseXOR => f64::from(js::int32(left) ^ js::int32(right)),
                    BinaryOperator::Addition => left + right,
                    BinaryOperator::Subtraction => left - right,
                    BinaryOperator::Multiplication => left * right,
                    BinaryOperator::ShiftLeft => f64::from(js::int32(left).wrapping_shl(shift())),
                    BinaryOperator::ShiftRight => f64::from(js::int32(left) >> shift()),
                    BinaryOperator::ShiftRightZeroFill => {
                        f64::from(js::int32(left) as u32 >> shift())
                    }
                    _ => unreachable!("compile admits only these operators"),
                }
            }
        })
    }
}
