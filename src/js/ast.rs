//! JavaScript parsing, syntax matchers, and node constructors shared by extraction and
//! deobfuscation.
//!
//! Matchers accept different syntax depending on the extractor's requirements.

use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use swc_core::atoms::Wtf8Atom;
use swc_core::common::sync::Lrc;
use swc_core::common::{
    BytePos, DUMMY_SP, FileName, SourceFile, SourceMap, Spanned, SyntaxContext,
};
use swc_core::ecma::ast::{
    AssignExpr, AssignOp, BinaryOp, BlockStmt, Expr, ExprOrSpread, ExprStmt, FnDecl, Function, Id,
    Ident, KeyValueProp, Lit, MemberExpr, MemberProp, ObjectLit, ParenExpr, Pat, PropName,
    PropOrSpread, Script, Stmt, UnaryOp, VarDeclarator,
};
use swc_core::ecma::parser::{Parser, StringInput, Syntax};
use swc_core::ecma::visit::{Visit, VisitWith};

use crate::engine::{self, Lines};

/// A parsed script and its original source text.
pub(crate) struct ParsedScript {
    pub script: Script,
    file: Lrc<SourceFile>,
}

impl ParsedScript {
    /// Returns the original source text for `node`.
    ///
    /// # Panics
    ///
    /// Panics if `node` was not parsed from this script.
    #[must_use]
    pub(crate) fn text(&self, node: &dyn Spanned) -> &str {
        let span = node.span();
        let offset = |position: BytePos| (position.0 - self.file.start_pos.0) as usize;
        &self.file.src[offset(span.lo)..offset(span.hi)]
    }

    /// Returns the one-based line and UTF-16 column at `at`, matching V8 stack traces.
    ///
    /// # Panics
    ///
    /// Panics if `at` is outside this script.
    #[must_use]
    pub(crate) fn position(&self, at: BytePos) -> (usize, usize) {
        let before = &self.file.src[..(at.0 - self.file.start_pos.0) as usize];
        let (line, column) = engine::line_and_column(before, Lines::Script);
        (line as usize + 1, column as usize + 1)
    }
}

pub(crate) fn parse_iframe_javascript(source: &str) -> Result<ParsedScript> {
    parse_javascript("deobfuscated iframe", source)
}

/// Parses `source`, using `what` to identify it in errors.
pub(crate) fn parse_javascript(what: &str, source: &str) -> Result<ParsedScript> {
    let source_map = SourceMap::default();
    let file = source_map.new_source_file(FileName::Custom(what.into()).into(), source.to_owned());
    let mut parser = Parser::new(Syntax::default(), StringInput::from(&*file), None);
    let script = parser
        .parse_script()
        .map_err(|error| anyhow::anyhow!("cannot parse {what}: {error:?}"))?;
    ensure!(parser.take_errors().is_empty(), "{what} has parse errors");
    Ok(ParsedScript { script, file })
}

/// Parses one expression, without its surrounding parentheses.
#[cfg(test)]
pub(crate) fn parse_expression(what: &str, text: &str) -> Result<Expr> {
    // Parentheses make leading braces parse as an object literal.
    let parsed = parse_javascript(what, &format!("({text})"))?;
    let [Stmt::Expr(statement)] = parsed.script.body.as_slice() else {
        anyhow::bail!("{what} is not one expression");
    };
    Ok(statement.expr.unwrap_parens().clone())
}

/// Returns a string literal or template without substitutions as WTF-8, preserving lone
/// surrogates. Does not unwrap parentheses.
#[must_use]
pub(crate) fn static_wtf8(expression: &Expr) -> Option<&Wtf8Atom> {
    match expression {
        Expr::Lit(Lit::Str(value)) => Some(&value.value),
        Expr::Tpl(template) if template.exprs.is_empty() => {
            template.quasis.first()?.cooked.as_ref()
        }
        _ => None,
    }
}

/// Converts [`static_wtf8`] to a Rust string. Returns `None` for lone surrogates instead of
/// replacing them with U+FFFD and changing the recovered value.
#[must_use]
pub(crate) fn static_str(expression: &Expr) -> Option<&str> {
    static_wtf8(expression)?.as_str()
}

/// The static name of a member property: `object.name`, `object["name"]`, or
/// ``object[`name`]`` when the template has no substitutions.
#[must_use]
pub(crate) fn member_str(property: &MemberProp) -> Option<&str> {
    match property {
        MemberProp::Ident(name) => Some(&*name.sym),
        MemberProp::Computed(computed) => static_str(&computed.expr),
        _ => None,
    }
}

/// Matches a property read directly from an identifier, such as a namespace or local, using
/// [`member_str`].
#[must_use]
pub(crate) fn ident_property(member: &MemberExpr) -> Option<&str> {
    match &*member.obj {
        Expr::Ident(_) => member_str(&member.prop),
        _ => None,
    }
}

/// Reads an identifier or quoted object-literal key. Excludes numeric and computed keys.
#[must_use]
pub(crate) fn key_str(key: &PropName) -> Option<&str> {
    match key {
        PropName::Ident(name) => Some(&*name.sym),
        PropName::Str(name) => name.value.as_str(),
        _ => None,
    }
}

/// Reads keys accepted by [`key_str`], plus computed static strings such as `["name"]` or
/// ``[`name`]``.
#[must_use]
pub(crate) fn static_key_str(key: &PropName) -> Option<&str> {
    match key {
        PropName::Computed(name) => static_str(&name.expr),
        key => key_str(key),
    }
}

/// Matches `key: value` properties, excluding spreads, methods, accessors, and shorthand
/// entries.
#[must_use]
pub(crate) fn key_value(property: &PropOrSpread) -> Option<&KeyValueProp> {
    property.as_prop()?.as_key_value()
}

/// Returns only [`key_value`] properties from an object literal.
pub(crate) fn key_values(object: &ObjectLit) -> impl Iterator<Item = &KeyValueProp> {
    object.props.iter().filter_map(key_value)
}

/// Collects distinct static strings from `node`; see [`static_str`].
#[must_use]
pub(crate) fn string_literals(node: &impl VisitWith<StringLiterals>) -> BTreeSet<String> {
    let mut literals = StringLiterals(BTreeSet::new());
    node.visit_with(&mut literals);
    literals.0
}

pub(crate) struct StringLiterals(BTreeSet<String>);

impl Visit for StringLiterals {
    fn visit_expr(&mut self, expression: &Expr) {
        if let Some(literal) = static_str(expression) {
            self.0.insert(literal.to_owned());
        }
        expression.visit_children_with(self);
    }
}

/// Applies `read` to each function declaration in `script`, in source order, keeping what it
/// returns.
pub(crate) fn in_declared_functions<T>(script: &Script, read: fn(&FnDecl) -> Option<T>) -> Vec<T> {
    struct Found<T> {
        read: fn(&FnDecl) -> Option<T>,
        results: Vec<T>,
    }
    impl<T> Visit for Found<T> {
        fn visit_fn_decl(&mut self, declaration: &FnDecl) {
            self.results.extend((self.read)(declaration));
            declaration.visit_children_with(self);
        }
    }
    let mut found = Found {
        read,
        results: Vec::new(),
    };
    script.visit_with(&mut found);
    found.results
}

/// Returns function declarations in `script` by name, in source order.
#[must_use]
pub(crate) fn declared_functions(script: &Script) -> Vec<(String, Function)> {
    in_declared_functions(script, |declaration| {
        Some((
            declaration.ident.sym.to_string(),
            (*declaration.function).clone(),
        ))
    })
}

/// Returns declared, assigned, and variable-initialized functions by binding ID in source order.
#[must_use]
pub(crate) fn named_functions(node: &impl VisitWith<NamedFunctions>) -> Vec<(Id, Function)> {
    let mut functions = NamedFunctions(Vec::new());
    node.visit_with(&mut functions);
    functions.0
}

pub(crate) struct NamedFunctions(Vec<(Id, Function)>);

impl Visit for NamedFunctions {
    fn visit_fn_decl(&mut self, declaration: &FnDecl) {
        let function = (*declaration.function).clone();
        self.0.push((declaration.ident.to_id(), function));
        declaration.visit_children_with(self);
    }

    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        if assignment.op == AssignOp::Assign
            && let Some(name) = assignment.left.as_ident()
            && let Expr::Fn(function) = &*assignment.right
        {
            self.0.push((name.to_id(), (*function.function).clone()));
        }
        assignment.visit_children_with(self);
    }

    fn visit_var_declarator(&mut self, declaration: &VarDeclarator) {
        if let Pat::Ident(name) = &declaration.name
            && let Some(Expr::Fn(function)) = declaration.init.as_deref()
        {
            self.0.push((name.to_id(), (*function.function).clone()));
        }
        declaration.visit_children_with(self);
    }
}

/// Whether an expression is a `Date.now()` call.
#[must_use]
pub(crate) fn is_date_now(expression: &Expr) -> bool {
    expression
        .as_call()
        .and_then(|call| call.callee.as_expr()?.as_member())
        .is_some_and(|member| is_method_of(member, "Date", "now"))
}

/// Matches a method call on the plain identifier `object`, such as `<object>.<property>(...)`.
#[must_use]
pub(crate) fn is_method_of(member: &MemberExpr, object: &str, property: &str) -> bool {
    matches!(&*member.obj, Expr::Ident(ident) if ident.sym == object)
        && member_str(&member.prop) == Some(property)
}

/// Returns the binding and assigned value from `binding = value`.
#[must_use]
pub(crate) fn assignment(expression: &Expr) -> Option<(Id, &Expr)> {
    let assignment = expression.as_assign()?;
    if assignment.op != AssignOp::Assign {
        return None;
    }
    Some((assignment.left.as_ident()?.to_id(), &assignment.right))
}

/// Matches `callee(args)` when the callee is a plain identifier.
#[must_use]
pub(crate) fn direct_call(expression: &Expr) -> Option<(&Ident, &[ExprOrSpread])> {
    let call = expression.as_call()?;
    Some((call.callee.as_expr()?.as_ident()?, &call.args))
}

/// Returns the object and arguments from `object.name(args)` or `object["name"](args)`.
#[must_use]
pub(crate) fn method_call<'a>(
    expression: &'a Expr,
    name: &str,
) -> Option<(&'a Expr, &'a [ExprOrSpread])> {
    let call = expression.as_call()?;
    let member = call.callee.as_expr()?.as_member()?;
    (member_str(&member.prop) == Some(name)).then_some((&*member.obj, &call.args[..]))
}

/// A numeric literal, possibly signed or parenthesized.
#[must_use]
pub(crate) fn number(expression: &Expr) -> Option<f64> {
    match expression {
        Expr::Lit(Lit::Num(value)) => Some(value.value),
        Expr::Paren(value) => number(&value.expr),
        Expr::Unary(value) if value.op == UnaryOp::Minus => Some(-number(&value.arg)?),
        Expr::Unary(value) if value.op == UnaryOp::Plus => number(&value.arg),
        _ => None,
    }
}

/// Evaluates numeric arithmetic: literals, parentheses, and the unary and binary numeric
/// operators. `leaf` supplies the value of anything else, such as a known parameter.
#[must_use]
pub(crate) fn fold_number(expression: &Expr, leaf: &impl Fn(&Expr) -> Option<f64>) -> Option<f64> {
    let fold = |expression: &Expr| fold_number(expression, leaf);
    match expression {
        Expr::Lit(Lit::Num(value)) => Some(value.value),
        Expr::Paren(value) => fold(&value.expr),
        Expr::Unary(value) => {
            let operand = fold(&value.arg)?;
            match value.op {
                UnaryOp::Minus => Some(-operand),
                UnaryOp::Plus => Some(operand),
                UnaryOp::Tilde => Some(super::bit_not(operand)),
                _ => None,
            }
        }
        Expr::Bin(binary) => {
            let (left, right) = (fold(&binary.left)?, fold(&binary.right)?);
            match binary.op {
                BinaryOp::Add => Some(left + right),
                BinaryOp::Sub => Some(left - right),
                BinaryOp::Mul => Some(left * right),
                BinaryOp::Div => Some(left / right),
                BinaryOp::Mod => Some(left % right),
                BinaryOp::BitAnd => Some(super::bit_and(left, right)),
                BinaryOp::BitOr => Some(super::bit_or(left, right)),
                BinaryOp::BitXor => Some(super::bit_xor(left, right)),
                BinaryOp::LShift => Some(super::shl(left, right)),
                BinaryOp::RShift => Some(super::shr(left, right)),
                BinaryOp::ZeroFillRShift => Some(super::ushr(left, right)),
                _ => None,
            }
        }
        _ => leaf(expression),
    }
}

/// Converts `value` to a nonnegative array index, treating `-0` as zero. Rejects infinities and
/// NaN. Saturates finite values above `usize::MAX` so bounds checks still reject them.
#[must_use]
pub(crate) fn array_index(value: f64) -> Option<usize> {
    (value.fract() == 0.0 && value >= 0.0).then_some(value as usize)
}

/// Matches a numeric-literal [`array_index`]. Unlike [`number`], does not unwrap signs or
/// parentheses.
#[must_use]
pub(crate) fn index_literal(expression: &Expr) -> Option<usize> {
    match expression {
        Expr::Lit(Lit::Num(value)) => array_index(value.value),
        _ => None,
    }
}

/// Returns the expression from a function whose entire body is `return value;`.
#[must_use]
pub(crate) fn returned(function: &Function) -> Option<&Expr> {
    match function.body.as_ref()?.stmts.as_slice() {
        [Stmt::Return(returned)] => returned.arg.as_deref(),
        _ => None,
    }
}

/// A block grouping statements that came from one place.
#[must_use]
pub(crate) fn block(statements: Vec<Stmt>) -> Stmt {
    Stmt::Block(BlockStmt {
        span: DUMMY_SP,
        ctxt: SyntaxContext::default(),
        stmts: statements,
    })
}

/// Creates an expression statement with the expression's source span.
#[must_use]
pub(crate) fn expression_statement(expression: Box<Expr>) -> Stmt {
    Stmt::Expr(ExprStmt {
        span: expression.span(),
        expr: expression,
    })
}

/// Wraps an expression in parentheses with the same span so an inlined value remains a single
/// operand.
#[must_use]
pub(crate) fn parenthesized(expression: Box<Expr>) -> Expr {
    Expr::Paren(ParenExpr {
        span: expression.span(),
        expr: expression,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a static key reads through a computed string literal.
    #[test]
    fn static_keys_also_accept_computed_strings() {
        let Expr::Object(object) =
            parse_expression("t", r#"{a: 1, "b": 2, ["c"]: 3, [d]: 4, 5: 5}"#).unwrap()
        else {
            panic!("not an object")
        };
        let keys: Vec<_> = key_values(&object).map(|p| key_str(&p.key)).collect();
        assert_eq!(keys, [Some("a"), Some("b"), None, None, None]);
        let keys: Vec<_> = key_values(&object)
            .map(|p| static_key_str(&p.key))
            .collect();
        assert_eq!(keys, [Some("a"), Some("b"), Some("c"), None, None]);
    }
}
