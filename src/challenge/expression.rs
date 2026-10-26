//! AST helpers for challenge-script expressions: `_cf_chl_opt` reads and writes, padded build
//! hashes, objects built in a block, and expressions used to construct options and payloads.

use anyhow::{Context, Result, bail, ensure};
use swc_core::ecma::ast::{
    AssignExpr, AssignTarget, BinExpr, BinaryOp, BlockStmt, Expr, Lit, SimpleAssignTarget, Stmt,
    UnaryOp,
};

use crate::js::{self, JsValue, Options, Window, ast};

/// Reads the build hash from `"0…0" + <number>.toString(16)`. The zero literal sets the
/// hexadecimal width. Requires an integer literal that fits without truncation; accepts any
/// numeric base and ignores surrounding parentheses.
#[must_use]
pub(crate) fn padded_build(sum: &BinExpr) -> Option<String> {
    let zeros = ast::static_str(&sum.left)?;
    let call = sum.right.unwrap_parens().as_call()?;
    let member = call.callee.as_expr()?.unwrap_parens().as_member()?;
    let (Expr::Lit(Lit::Num(number)), [radix]) = (member.obj.unwrap_parens(), &call.args[..])
    else {
        return None;
    };
    let padded =
        sum.op == BinaryOp::Add && !zeros.is_empty() && zeros.bytes().all(|byte| byte == b'0');
    let hexadecimal = ast::member_str(&member.prop) == Some("toString")
        && radix.spread.is_none()
        && ast::index_literal(&radix.expr) == Some(16);
    let (number, width) = (number.value, zeros.len());
    // For padding wider than sixteen hex digits, the `u64` range limits the value.
    let limit = 16f64.powi(i32::try_from(width).ok()?).min(2f64.powi(64));
    (padded && hexadecimal && number.fract() == 0.0 && (0.0..limit).contains(&number))
        .then(|| format!("{:0width$x}", number as u64))
}

/// Resolves a static expression using known options (see [`evaluate`]). Unknown options have no
/// static value.
#[must_use]
pub(crate) fn static_value(expression: &Expr, options: &Options) -> Option<JsValue> {
    evaluate(expression, options, &Window::new()).ok()?
}

/// The `_cf_chl_opt` property read by `<global>._cf_chl_opt.<name>`.
#[must_use]
pub(crate) fn option_key(expression: &Expr) -> Option<&str> {
    let member = expression.as_member()?;
    ast::member_str(&member.prop).filter(|_| is_options(&member.obj))
}

/// The option assigned by `_cf_chl_opt.<name> = ...`.
#[must_use]
pub(crate) fn option_assignment(target: &AssignTarget) -> Option<&str> {
    let member = target.as_simple()?.as_member()?;
    ast::member_str(&member.prop).filter(|_| is_options(&member.obj))
}

/// Returns the assignment contained in an expression statement.
pub(crate) fn assignment(statement: &Stmt) -> Option<&AssignExpr> {
    statement.as_expr()?.expr.as_assign()
}

/// Finds standalone assignment statements in `body`.
pub(crate) fn assignments(body: &BlockStmt) -> impl Iterator<Item = &AssignExpr> {
    body.stmts.iter().filter_map(assignment)
}

/// An object held by a local variable in a block.
pub(crate) struct BuiltObject<'body> {
    pub local: &'body str,
    pub fields: Vec<ObjectField<'body>>,
}

/// One field of an object, as `key: value` or `<local>.<key> = <value>`.
pub(crate) struct ObjectField<'body> {
    pub key: &'body str,
    pub value: &'body Expr,
}

/// Records an object assigned to a local, or a property write to one, in `built`. Returns
/// whether it matched. The deobfuscator may emit a literal, or an empty object followed by
/// property writes.
pub(crate) fn track<'body>(
    built: &mut Vec<BuiltObject<'body>>,
    assignment: &'body AssignExpr,
) -> bool {
    let value = &*assignment.right;
    match assignment.left.as_simple() {
        Some(SimpleAssignTarget::Ident(local)) => {
            let Some(fields) = object_fields(value) else {
                return false;
            };
            built.push(BuiltObject {
                local: &local.id.sym,
                fields,
            });
        }
        Some(SimpleAssignTarget::Member(member)) => {
            let Expr::Ident(object) = &*member.obj else {
                return false;
            };
            let target = built
                .iter_mut()
                .rfind(|target| target.local == &*object.sym);
            let (Some(key), Some(target)) = (ast::member_str(&member.prop), target) else {
                return false;
            };
            match target.fields.iter_mut().find(|field| field.key == key) {
                Some(field) => field.value = value,
                None => target.fields.push(ObjectField { key, value }),
            }
        }
        _ => return false,
    }
    true
}

/// The fields of an object literal whose keys are all names.
pub(crate) fn object_fields(expression: &Expr) -> Option<Vec<ObjectField<'_>>> {
    let fields = expression.as_object()?.props.iter().map(|property| {
        let property = ast::key_value(property)?;
        Some(ObjectField {
            key: ast::key_str(&property.key)?,
            value: &property.value,
        })
    });
    fields.collect()
}

/// Evaluates expressions used to build options and payloads. Supports literals, `undefined`,
/// arrays, objects, `!`, `||`, `+`, `-`, `===`, `!==`, and `JSON.stringify`. Reads options from
/// `<global>._cf_chl_opt.<key>` and globals from `<global>.<key>`, including getters called
/// without arguments.
///
/// Objects keep static properties and omit callbacks, matching `JSON.stringify`. `None`
/// represents `undefined`. Unsupported expressions return errors.
pub(crate) fn evaluate(
    expression: &Expr,
    options: &Options,
    globals: &Window,
) -> Result<Option<JsValue>> {
    let evaluate = |expression: &Expr| evaluate(expression, options, globals);
    Ok(match expression {
        Expr::Paren(paren) => evaluate(&paren.expr)?,
        Expr::Lit(Lit::Str(_)) | Expr::Tpl(_) => Some(JsValue::from(
            ast::static_str(expression).context("unsupported template or string literal")?,
        )),
        Expr::Lit(Lit::Num(number)) => Some(JsValue::Number(number.value)),
        Expr::Lit(Lit::Bool(value)) => Some(JsValue::Bool(value.value)),
        Expr::Lit(Lit::Null(_)) => Some(JsValue::Null),
        Expr::Ident(ident) if ident.sym == "undefined" => None,
        // `JSON.stringify` writes an undefined element as `null`.
        Expr::Array(array) => {
            let mut elements = Vec::with_capacity(array.elems.len());
            for element in &array.elems {
                let element = element.as_ref().context("unsupported array hole")?;
                ensure!(element.spread.is_none(), "unsupported spread element");
                elements.push(evaluate(&element.expr)?.unwrap_or(JsValue::Null));
            }
            Some(JsValue::Array(elements))
        }
        Expr::Object(object) => Some(JsValue::Object(
            ast::key_values(object)
                .filter_map(|property| {
                    let value = evaluate(&property.value).ok()??;
                    Some((ast::key_str(&property.key)?.to_owned(), value))
                })
                .collect(),
        )),
        // `!x` is always a boolean; an unset option is `undefined`, so falsy.
        Expr::Unary(unary) if unary.op == UnaryOp::Bang => Some(JsValue::Bool(
            !evaluate(&unary.arg)?.as_ref().is_some_and(js::truthy),
        )),
        Expr::Bin(binary) => {
            let left = evaluate(&binary.left)?;
            match binary.op {
                // The right-hand side runs only when the left is falsy.
                BinaryOp::LogicalOr if left.as_ref().is_some_and(js::truthy) => left,
                BinaryOp::LogicalOr => evaluate(&binary.right)?,
                BinaryOp::Sub => Some(JsValue::Number(
                    js::number(left.as_ref()) - js::number(evaluate(&binary.right)?.as_ref()),
                )),
                BinaryOp::Add => {
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
                BinaryOp::EqEqEq | BinaryOp::NotEqEq => {
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
                        (left == right) == (binary.op == BinaryOp::EqEqEq),
                    ))
                }
                operator => bail!("unsupported operator {operator}"),
            }
        }
        Expr::Member(member) => {
            let key = ast::member_str(&member.prop).context("unsupported computed property")?;
            match &*member.obj {
                object if is_options(object) => options.get(key).cloned(),
                Expr::Ident(_) => globals.get(key).cloned(),
                object => match evaluate(object)? {
                    Some(JsValue::Object(object)) => object.get(key).cloned(),
                    None | Some(JsValue::Undefined) => bail!("reads {key} of undefined"),
                    Some(other) => bail!("unsupported read of {key} from {other}"),
                },
            }
        }
        Expr::Call(call) => {
            let member = call
                .callee
                .as_expr()
                .and_then(|callee| callee.as_member())
                .context("unsupported call")?;
            if ast::is_method_of(member, "JSON", "stringify") {
                let [argument] = &call.args[..] else {
                    bail!("unsupported JSON.stringify arguments");
                };
                ensure!(argument.spread.is_none(), "unsupported spread argument");
                // `JSON.stringify(undefined)` is itself `undefined`.
                evaluate(&argument.expr)?
                    .and_then(|value| value.stringify())
                    .map(JsValue::String)
            } else if matches!(&*member.obj, Expr::Ident(_)) && call.args.is_empty() {
                // Use the getter's collected value instead of running the call.
                globals
                    .get(ast::member_str(&member.prop).context("unsupported computed getter")?)
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
pub(crate) fn is_options(expression: &Expr) -> bool {
    matches!(
        expression,
        Expr::Member(member) if ast::member_str(&member.prop) == Some("_cf_chl_opt")
    )
}
