//! AST helpers for challenge-script expressions: `_cf_chl_opt` reads and writes, padded build
//! hashes, objects built in a block, and expressions used to construct options and payloads.

use anyhow::{Context, Result, bail, ensure};
use oxc::ast::ast::{
    ArrayExpressionElement, AssignmentExpression, AssignmentTarget, BinaryExpression, Expression,
    FunctionBody, MemberExpression, Statement,
};
use oxc::syntax::operator::{BinaryOperator, LogicalOperator, UnaryOperator};

use crate::js::ast::{self, Binding, Script};
use crate::js::{self, JsValue, Options, Window};

/// Reads the build hash from `"0…0" + <number>.toString(16)`. The zero literal sets the
/// hexadecimal width. Requires an integer literal that fits without truncation; accepts any
/// numeric base and ignores surrounding parentheses.
#[must_use]
pub(crate) fn padded_build(sum: &BinaryExpression<'_>) -> Option<String> {
    let zeros = ast::static_str(&sum.left)?;
    let Expression::CallExpression(call) = sum.right.without_parentheses() else {
        return None;
    };
    let member = call.callee.without_parentheses().as_member_expression()?;
    let (Expression::NumericLiteral(number), [radix]) =
        (member.object().without_parentheses(), &call.arguments[..])
    else {
        return None;
    };
    let padded = sum.operator == BinaryOperator::Addition
        && !zeros.is_empty()
        && zeros.bytes().all(|byte| byte == b'0');
    let hexadecimal = ast::member_str(member) == Some("toString")
        && radix.as_expression().and_then(ast::index_literal) == Some(16);
    let (number, width) = (number.value, zeros.len());
    // For padding wider than sixteen hex digits, the `u64` range limits the value.
    let limit = 16f64.powi(i32::try_from(width).ok()?).min(2f64.powi(64));
    (padded && hexadecimal && number.fract() == 0.0 && (0.0..limit).contains(&number))
        .then(|| format!("{:0width$x}", number as u64))
}

/// Resolves a static expression in `script` using known options (see [`evaluate`]). Unknown
/// options have no static value.
#[must_use]
pub(crate) fn static_value(
    script: Script<'_>,
    expression: &Expression<'_>,
    options: &Options,
) -> Option<JsValue> {
    evaluate(script, expression, options, &Window::new()).ok()?
}

/// The `_cf_chl_opt` property read by `<global>._cf_chl_opt.<name>`.
#[must_use]
pub(crate) fn option_key<'a>(expression: &Expression<'a>) -> Option<&'a str> {
    options_member(expression.as_member_expression()?)
}

/// The option assigned by `_cf_chl_opt.<name> = ...`.
#[must_use]
pub(crate) fn option_assignment<'a>(target: &AssignmentTarget<'a>) -> Option<&'a str> {
    options_member(target.as_member_expression()?)
}

/// The option `member` names, if it is a property of `_cf_chl_opt`.
fn options_member<'a>(member: &MemberExpression<'a>) -> Option<&'a str> {
    ast::member_str(member).filter(|_| is_options(member.object()))
}

/// Returns the assignment contained in an expression statement.
pub(crate) fn assignment<'b, 'a>(
    statement: &'b Statement<'a>,
) -> Option<&'b AssignmentExpression<'a>> {
    match statement {
        Statement::ExpressionStatement(statement) => match &statement.expression {
            Expression::AssignmentExpression(assignment) => Some(assignment),
            _ => None,
        },
        _ => None,
    }
}

/// Finds standalone assignment statements in `body`.
pub(crate) fn assignments<'b, 'a>(
    body: &'b FunctionBody<'a>,
) -> impl Iterator<Item = &'b AssignmentExpression<'a>> {
    body.statements.iter().filter_map(assignment)
}

/// An object held by a local variable in a block.
pub(crate) struct BuiltObject<'b, 'a> {
    pub local: Binding<'a>,
    pub fields: Vec<ObjectField<'b, 'a>>,
}

/// One field of an object, as `key: value` or `<local>.<key> = <value>`.
pub(crate) struct ObjectField<'b, 'a> {
    pub key: &'a str,
    pub value: &'b Expression<'a>,
}

/// Records an object assigned to a local, or a property write to one, in `built`. Returns
/// whether it matched. The deobfuscator may emit a literal, or an empty object followed by
/// property writes.
pub(crate) fn track<'b, 'a>(
    script: Script<'a>,
    built: &mut Vec<BuiltObject<'b, 'a>>,
    assignment: &'b AssignmentExpression<'a>,
) -> bool {
    let value = &assignment.right;
    if let AssignmentTarget::AssignmentTargetIdentifier(local) = &assignment.left {
        let Some(fields) = object_fields(value) else {
            return false;
        };
        built.push(BuiltObject {
            local: script.binding(local),
            fields,
        });
        return true;
    }
    let Some(member) = assignment.left.as_member_expression() else {
        return false;
    };
    let Expression::Identifier(object) = member.object() else {
        return false;
    };
    let object = script.binding(object);
    let target = built.iter_mut().rfind(|target| target.local == object);
    let (Some(key), Some(target)) = (ast::member_str(member), target) else {
        return false;
    };
    match target.fields.iter_mut().find(|field| field.key == key) {
        Some(field) => field.value = value,
        None => target.fields.push(ObjectField { key, value }),
    }
    true
}

/// The fields of an object literal whose keys are all names.
pub(crate) fn object_fields<'b, 'a>(
    expression: &'b Expression<'a>,
) -> Option<Vec<ObjectField<'b, 'a>>> {
    let Expression::ObjectExpression(object) = expression else {
        return None;
    };
    let fields = object.properties.iter().map(|property| {
        let property = ast::key_value(property)?;
        Some(ObjectField {
            key: ast::key_str(&property.key, property.computed)?,
            value: &property.value,
        })
    });
    fields.collect()
}

/// Evaluates expressions in `script` used to build options and payloads. Supports literals,
/// `undefined`, arrays, objects, `!`, `||`, `+`, `-`, `===`, `!==`, and `JSON.stringify`. Reads
/// options from `<global>._cf_chl_opt.<key>` and globals from `<global>.<key>`, including getters
/// called without arguments.
///
/// Objects keep static properties and omit callbacks, matching `JSON.stringify`. `None`
/// represents `undefined`. Unsupported expressions return errors.
pub(crate) fn evaluate(
    script: Script<'_>,
    expression: &Expression<'_>,
    options: &Options,
    globals: &Window,
) -> Result<Option<JsValue>> {
    let evaluate = |expression: &Expression<'_>| evaluate(script, expression, options, globals);
    Ok(match expression {
        Expression::ParenthesizedExpression(paren) => evaluate(&paren.expression)?,
        Expression::StringLiteral(_) | Expression::TemplateLiteral(_) => Some(JsValue::from(
            ast::static_str(expression).context("unsupported template or string literal")?,
        )),
        Expression::NumericLiteral(number) => Some(JsValue::Number(number.value)),
        Expression::BooleanLiteral(value) => Some(JsValue::Bool(value.value)),
        Expression::NullLiteral(_) => Some(JsValue::Null),
        Expression::Identifier(_) if script.is_global(expression, "undefined") => None,
        // `JSON.stringify` writes an undefined element as `null`.
        Expression::ArrayExpression(array) => {
            let mut elements = Vec::with_capacity(array.elements.len());
            for element in &array.elements {
                let element = match element {
                    ArrayExpressionElement::Elision(_) => bail!("unsupported array hole"),
                    ArrayExpressionElement::SpreadElement(_) => bail!("unsupported spread element"),
                    element => element.to_expression(),
                };
                elements.push(evaluate(element)?.unwrap_or(JsValue::Null));
            }
            Some(JsValue::Array(elements))
        }
        Expression::ObjectExpression(object) => Some(JsValue::Object(
            ast::key_values(object)
                .filter_map(|property| {
                    let value = evaluate(&property.value).ok()??;
                    Some((
                        ast::key_str(&property.key, property.computed)?.to_owned(),
                        value,
                    ))
                })
                .collect(),
        )),
        // `!x` is always a boolean; an unset option is `undefined`, so falsy.
        Expression::UnaryExpression(unary) if unary.operator == UnaryOperator::LogicalNot => Some(
            JsValue::Bool(!evaluate(&unary.argument)?.as_ref().is_some_and(js::truthy)),
        ),
        Expression::LogicalExpression(logical) => {
            let left = evaluate(&logical.left)?;
            match logical.operator {
                // The right-hand side runs only when the left is falsy.
                LogicalOperator::Or if left.as_ref().is_some_and(js::truthy) => left,
                LogicalOperator::Or => evaluate(&logical.right)?,
                operator => bail!("unsupported operator {}", operator.as_str()),
            }
        }
        Expression::BinaryExpression(binary) => {
            let left = evaluate(&binary.left)?;
            match binary.operator {
                BinaryOperator::Subtraction => Some(JsValue::Number(
                    js::number(left.as_ref()) - js::number(evaluate(&binary.right)?.as_ref()),
                )),
                BinaryOperator::Addition => {
                    let right = evaluate(&binary.right)?;
                    // Strings, arrays, and objects trigger string concatenation; other values
                    // use numeric addition.
                    let textual = |value: Option<&JsValue>| {
                        matches!(
                            value,
                            Some(JsValue::String(_) | JsValue::Array(_) | JsValue::Object(_))
                        )
                    };
                    let (left, right) = (left.as_ref(), right.as_ref());
                    Some(if textual(left) || textual(right) {
                        JsValue::String(format!("{}{}", js::string(left), js::string(right)))
                    } else {
                        JsValue::Number(js::number(left) + js::number(right))
                    })
                }
                BinaryOperator::StrictEquality | BinaryOperator::StrictInequality => {
                    let [left, right] = [left, evaluate(&binary.right)?]
                        .map(|value| value.unwrap_or(JsValue::Undefined));
                    // `JsValue` equality implements `===` for primitive values. Copies of
                    // objects have no identity to compare.
                    let object =
                        |value: &JsValue| matches!(value, JsValue::Array(_) | JsValue::Object(_));
                    ensure!(
                        !object(&left) || !object(&right),
                        "unsupported identity comparison of an object"
                    );
                    Some(JsValue::Bool(
                        (left == right) == (binary.operator == BinaryOperator::StrictEquality),
                    ))
                }
                operator => bail!("unsupported operator {}", operator.as_str()),
            }
        }
        Expression::StaticMemberExpression(_)
        | Expression::ComputedMemberExpression(_)
        | Expression::PrivateFieldExpression(_) => {
            let member = expression.to_member_expression();
            let key = ast::member_str(member).context("unsupported computed property")?;
            match member.object() {
                object if is_options(object) => options.get(key).cloned(),
                Expression::Identifier(_) => globals.get(key).cloned(),
                object => match evaluate(object)? {
                    Some(JsValue::Object(object)) => object.get(key).cloned(),
                    None | Some(JsValue::Undefined) => bail!("reads {key} of undefined"),
                    Some(other) => bail!("unsupported read of {key} from {other}"),
                },
            }
        }
        Expression::CallExpression(call) => {
            let member = call
                .callee
                .as_member_expression()
                .context("unsupported call")?;
            if script.is_method_of(member, "JSON", "stringify") {
                let [argument] = &call.arguments[..] else {
                    bail!("unsupported JSON.stringify arguments");
                };
                let argument = argument
                    .as_expression()
                    .context("unsupported spread argument")?;
                // `JSON.stringify(undefined)` is itself `undefined`.
                evaluate(argument)?
                    .and_then(|value| value.stringify())
                    .map(JsValue::String)
            } else if matches!(member.object(), Expression::Identifier(_))
                && call.arguments.is_empty()
            {
                // Use the getter's collected value instead of running the call.
                globals
                    .get(ast::member_str(member).context("unsupported computed getter")?)
                    .cloned()
            } else {
                bail!("unsupported call")
            }
        }
        _ => bail!("unsupported expression"),
    })
}

/// Whether an expression is the `_cf_chl_opt` object itself, rather than one of its properties.
#[must_use]
pub(crate) fn is_options(expression: &Expression<'_>) -> bool {
    expression
        .as_member_expression()
        .is_some_and(|member| ast::member_str(member) == Some("_cf_chl_opt"))
}
