//! JavaScript conversions, equality, and operators for concrete byte-dependent values. Retains
//! register-dependent operations as symbolic terms.

use std::cell::RefCell;
use std::rc::Rc;
use std::{mem, ops};

use swc_core::ecma::ast::{BinaryOp, UnaryOp};
use swc_ecma_utils::number::{JsNumber, ToJsString};

use crate::js;
use crate::vm::HashMap;
use crate::vm::output::Term;
use crate::vm::value::{JsString, Value};

impl Value<'_> {
    /// Applies `ToNumber` to a concrete value.
    #[must_use]
    pub(crate) fn number(&self) -> Option<f64> {
        match self {
            Self::Number(number) => Some(*number),
            Self::Bool(value) => Some(f64::from(u8::from(*value))),
            Self::Null => Some(0.0),
            Self::Undefined => Some(f64::NAN),
            // A lone surrogate is neither whitespace nor a digit.
            Self::String(string) => Some(
                string
                    .text()
                    .map_or(f64::NAN, |text| js::string_number(&text)),
            ),
            _ => None,
        }
    }

    /// Applies JavaScript truthiness to a concrete value.
    #[must_use]
    pub(crate) fn truthy(&self) -> Option<bool> {
        Some(match self {
            Self::Undefined | Self::Null => false,
            Self::Bool(value) => *value,
            Self::Number(number) => *number != 0.0 && !number.is_nan(),
            Self::String(string) => !string.is_empty(),
            Self::Symbolic(_) => return None,
            _ => true,
        })
    }
}

/// Returns `typeof value` for concrete values. Allocates each result string once per thread.
fn type_of<'a>(value: &Value<'_>) -> Option<Value<'a>> {
    thread_local! {
        static NAMES: RefCell<HashMap<&'static str, JsString>> = RefCell::default();
    }
    let name = match value {
        Value::Undefined => "undefined",
        Value::Null => "object",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Function(_) => "function",
        Value::Symbol(_) => "symbol",
        Value::Symbolic(_) => return None,
        _ => "object",
    };
    let string = NAMES.with_borrow_mut(|names| {
        names
            .entry(name)
            .or_insert_with(|| JsString::from(name))
            .clone()
    });
    Some(Value::String(string))
}

pub(super) fn unary_value<'a>(operator: UnaryOp, argument: Value<'a>) -> Value<'a> {
    let concrete = match operator {
        UnaryOp::Bang => argument.truthy().map(|truthy| Value::Bool(!truthy)),
        UnaryOp::Minus => argument.number().map(|number| Value::Number(-number)),
        UnaryOp::Plus => argument.number().map(Value::Number),
        UnaryOp::Tilde => argument
            .number()
            .map(|number| Value::Number(js::bit_not(number))),
        UnaryOp::TypeOf => type_of(&argument),
        UnaryOp::Void => Some(Value::Undefined),
        UnaryOp::Delete => unreachable!("delete needs its operand's reference"),
    };
    concrete
        .filter(|_| !argument.is_symbolic())
        .unwrap_or_else(|| Value::symbolic(Term::Unary(operator, Box::new(argument.expr()))))
}

/// Compares concrete values with `===`. Returns `None` for register-dependent comparisons.
pub(super) fn strict_equal<'a>(left: &Value<'a>, right: &Value<'a>) -> Option<bool> {
    Some(match (left, right) {
        (Value::Symbolic(_), _) | (_, Value::Symbolic(_)) => return None,
        (Value::Undefined, Value::Undefined) | (Value::Null, Value::Null) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Number(a), Value::Number(b)) => a == b,
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Array(a), Value::Array(b)) => Rc::ptr_eq(a, b),
        (Value::Object(a), Value::Object(b)) => Rc::ptr_eq(a, b),
        (Value::Set(a), Value::Set(b)) => Rc::ptr_eq(a, b),
        (Value::Map(a), Value::Map(b)) => Rc::ptr_eq(a, b),
        (Value::Function(a), Value::Function(b)) => Rc::ptr_eq(a, b),
        (Value::Symbol(a), Value::Symbol(b)) => Rc::ptr_eq(a, b),
        (Value::Namespace(a), Value::Namespace(b)) => a == b,
        _ => false,
    })
}

/// Whether `value` is a JavaScript object, which `==` compares by identity.
fn is_object(value: &Value<'_>) -> bool {
    matches!(
        value,
        Value::Array(_)
            | Value::Object(_)
            | Value::Set(_)
            | Value::Map(_)
            | Value::Function(_)
            | Value::Namespace(_)
    )
}

/// Compares set members using `SameValueZero`: strict equality with NaN equal to itself.
/// Returns `None` for register-dependent comparisons.
pub(super) fn same_value_zero<'a>(left: &Value<'a>, right: &Value<'a>) -> Option<bool> {
    match (left, right) {
        (Value::Number(a), Value::Number(b)) if a.is_nan() && b.is_nan() => Some(true),
        _ => strict_equal(left, right),
    }
}

pub(super) fn binary_value<'a>(operator: BinaryOp, left: Value<'a>, right: Value<'a>) -> Value<'a> {
    // Take ownership of the left string so concatenation can grow it in place.
    let left = match (operator, left) {
        (BinaryOp::Add, Value::String(string)) => match text(&right) {
            Some(suffix) => return Value::String(string.concat(&suffix)),
            None => Value::String(string),
        },
        (_, left) => left,
    };
    concrete_binary(operator, &left, &right).unwrap_or_else(|| {
        let (mut left, mut right) = (left.expr(), right.expr());
        // `undefined === r` and `r === undefined` are one condition.
        let symmetric = matches!(
            operator,
            BinaryOp::EqEqEq | BinaryOp::NotEqEq | BinaryOp::EqEq | BinaryOp::NotEq
        );
        if symmetric && matches!(left, Term::Const(_)) && !matches!(right, Term::Const(_)) {
            mem::swap(&mut left, &mut right);
        }
        Value::symbolic(Term::Binary(operator, Box::new(left), Box::new(right)))
    })
}

fn concrete_binary<'a>(
    operator: BinaryOp,
    left: &Value<'a>,
    right: &Value<'a>,
) -> Option<Value<'a>> {
    if left.is_symbolic() || right.is_symbolic() {
        return None;
    }
    let numbers = || Some((left.number()?, right.number()?));
    // JavaScript's numeric operators, applied to both operands as numbers.
    let arithmetic =
        |operator: fn(f64, f64) -> f64| numbers().map(|(a, b)| Value::Number(operator(a, b)));
    Some(match operator {
        BinaryOp::EqEqEq => Value::Bool(strict_equal(left, right)?),
        BinaryOp::NotEqEq => Value::Bool(!strict_equal(left, right)?),
        BinaryOp::EqEq | BinaryOp::NotEq => {
            let equal = match (left, right) {
                (Value::Undefined | Value::Null, Value::Undefined | Value::Null) => true,
                (Value::Undefined | Value::Null, _) | (_, Value::Undefined | Value::Null) => false,
                (Value::String(a), Value::String(b)) => a == b,
                // Objects and symbols compare by identity.
                (a, b) if is_object(a) && is_object(b) => strict_equal(a, b)?,
                (Value::Symbol(a), Value::Symbol(b)) => Rc::ptr_eq(a, b),
                // Symbols do not coerce to another primitive type for equality comparison.
                (Value::Symbol(_), b) | (b, Value::Symbol(_)) if !is_object(b) => false,
                _ => {
                    let (a, b) = numbers()?;
                    a == b
                }
            };
            Value::Bool(equal == (operator == BinaryOp::EqEq))
        }
        BinaryOp::Add => match (left, right) {
            // A string operand triggers string conversion of both operands, in evaluation
            // order.
            (Value::String(_), _) | (_, Value::String(_)) => {
                Value::String(text(left)?.concat(&text(right)?))
            }
            _ => {
                let (a, b) = numbers()?;
                Value::Number(a + b)
            }
        },
        BinaryOp::Lt | BinaryOp::LtEq | BinaryOp::Gt | BinaryOp::GtEq => {
            // Compare two strings by UTF-16 code units; otherwise compare numbers.
            let ordering = match (left, right) {
                (Value::String(a), Value::String(b)) => Some(a.cmp(b)),
                _ => {
                    let (a, b) = numbers()?;
                    a.partial_cmp(&b)
                }
            };
            Value::Bool(ordering.is_some_and(|ordering| match operator {
                BinaryOp::Lt => ordering.is_lt(),
                BinaryOp::LtEq => ordering.is_le(),
                BinaryOp::Gt => ordering.is_gt(),
                _ => ordering.is_ge(),
            }))
        }
        operator => arithmetic(numeric(operator)?)?,
    })
}

/// Applies supported numeric operators after conversion. `+` performs numeric addition here.
/// Returns `None` for other operators.
#[inline]
#[must_use]
pub(crate) fn numeric(operator: BinaryOp) -> Option<fn(f64, f64) -> f64> {
    let operation: fn(f64, f64) -> f64 = match operator {
        BinaryOp::Add => ops::Add::add,
        BinaryOp::Sub => ops::Sub::sub,
        BinaryOp::Mul => ops::Mul::mul,
        BinaryOp::Div => ops::Div::div,
        BinaryOp::Mod => ops::Rem::rem,
        BinaryOp::Exp => |a, b| *JsNumber::from(a).pow(b.into()),
        BinaryOp::BitAnd => js::bit_and,
        BinaryOp::BitOr => js::bit_or,
        BinaryOp::BitXor => js::bit_xor,
        BinaryOp::LShift => js::shl,
        BinaryOp::RShift => js::shr,
        BinaryOp::ZeroFillRShift => js::ushr,
        _ => return None,
    };
    Some(operation)
}

/// Applies `ToString` to a concrete primitive.
pub(super) fn text(value: &Value<'_>) -> Option<JsString> {
    Some(match value {
        Value::String(string) => string.clone(),
        Value::Number(number) => JsString::from(&*number.to_js_string()),
        Value::Bool(value) => JsString::from(if *value { "true" } else { "false" }),
        Value::Undefined => JsString::from("undefined"),
        Value::Null => JsString::from("null"),
        _ => return None,
    })
}

/// Applies `ToPropertyKey` to concrete primitives, returning lookup text. Returns `None` for
/// strings containing lone surrogates.
pub(super) fn property_key(key: &Value<'_>) -> Option<String> {
    match key {
        Value::String(name) => name.text(),
        Value::Number(number) => Some(number.to_js_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Undefined => Some("undefined".into()),
        Value::Null => Some("null".into()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decide<'a>(operator: BinaryOp, left: &Value<'a>, right: &Value<'a>) -> bool {
        match concrete_binary(operator, left, right) {
            Some(Value::Bool(decided)) => decided,
            _ => panic!(
                "{operator:?} of {:?} and {:?} is not decided",
                left.expr(),
                right.expr()
            ),
        }
    }

    /// A supplementary character's leading surrogate sorts before U+FF61 even though the code
    /// point sorts after it. Nonstring operands compare numerically.
    #[test]
    fn strings_compare_by_code_units() {
        let less = |left: &str, right| decide(BinaryOp::Lt, &Value::string(left), &right);
        assert!(less("\u{1f1fa}", Value::string("\u{ff61}")));
        assert!(less("10", Value::string("9")));
        assert!(!less("10", Value::Number(9.0)));
    }

    /// Object and symbol identity comparisons are concrete, requiring no symbolic condition.
    #[test]
    fn loose_equality_compares_objects_and_symbols_by_identity() {
        let equal = |left: &_, right: &_| decide(BinaryOp::EqEq, left, right);
        let object = Value::Object(Rc::default());
        let other = Value::Object(Rc::default());
        let array = Value::array(Vec::new());
        assert!(equal(&object, &object));
        assert!(!equal(&object, &other));
        assert!(!equal(&object, &array));
        assert!(equal(&array, &array.clone()));
        let symbol = Value::Symbol(Rc::new(()));
        assert!(equal(&symbol, &symbol.clone()));
        assert!(!equal(&symbol, &Value::Symbol(Rc::new(()))));
        assert!(!equal(&symbol, &Value::string("x")));
        assert!(!equal(&symbol, &Value::Undefined));
        assert!(decide(BinaryOp::NotEq, &object, &other));
    }
}
