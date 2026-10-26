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

use swc_core::ecma::ast::{
    BinExpr, BinaryOp, Decl, Expr, FnDecl, Function, Id, Lit, Number, Program, Stmt, UnaryOp,
    UpdateOp, VarDeclarator,
};
use swc_core::ecma::visit::{Visit, VisitMut, VisitMutWith, VisitWith};

use super::analysis::Analysis;
use super::{HashMap, HashSet, bitwise, removal};
use crate::js::ast;

pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    let bindings = analysis.bindings(program);
    let mut helpers = Helpers::default();
    program.visit_with(&mut helpers);
    helpers.0.retain(|id| bindings.is_written_once(id));
    if helpers.0.is_empty() {
        return false;
    }
    let mut inline = InlineCalls {
        helpers: &helpers.0,
        replaced: HashMap::default(),
    };
    program.visit_mut_with(&mut inline);
    let uncalled = removal::unread(&inline.replaced, bindings);
    program.visit_mut_with(&mut RemoveHelpers(uncalled));
    !inline.replaced.is_empty()
}

/// Declared helpers, by binding.
#[derive(Default)]
struct Helpers(Vec<Id>);

impl Visit for Helpers {
    fn visit_fn_decl(&mut self, declaration: &FnDecl) {
        if helper_mask(&declaration.function).is_some() {
            self.0.push(declaration.ident.to_id());
        }
        declaration.visit_children_with(self);
    }
}

/// The mask of a helper, or `None` if `function` is not one. Its declarations may be split:
///
/// ```js
/// function(x) {
///     var low = x & mask, count = 0;
///     for (; low; low--) count++;
///     return x & ~mask | count;
/// }
/// ```
fn helper_mask(function: &Function) -> Option<i32> {
    let [parameter] = &function.params[..] else {
        return None;
    };
    let [
        declarations @ ..,
        Stmt::For(counting),
        Stmt::Return(returned),
    ] = &function.body.as_ref()?.stmts[..]
    else {
        return None;
    };
    let mut declarators: Vec<&VarDeclarator> = Vec::new();
    for statement in declarations {
        declarators.extend(&statement.as_decl()?.as_var()?.decls);
    }
    let [low, count] = declarators[..] else {
        return None;
    };
    let argument = parameter.pat.as_ident()?.to_id();
    let low_name = low.name.as_ident()?.to_id();
    let count_name = count.name.as_ident()?.to_id();
    let mask = masked(low.init.as_deref()?, &argument)?;
    let combined = returned.arg.as_deref()?.unwrap_parens().as_bin()?;
    let increment = match &*counting.body {
        Stmt::Block(block) => match &block.stmts[..] {
            [statement] => statement,
            _ => return None,
        },
        statement => statement,
    };
    let reads = |expression: &Expr, id: &Id| {
        expression
            .as_ident()
            .is_some_and(|name| name.to_id() == *id)
    };
    let updates = |expression: &Expr, id: &Id, op: UpdateOp| {
        expression
            .as_update()
            .is_some_and(|update| update.op == op && reads(&update.arg, id))
    };
    let is_helper = mask >= 0
        && count.init.as_deref().and_then(ast::number) == Some(0.0)
        && counting.init.is_none()
        && counting
            .test
            .as_deref()
            .is_some_and(|test| reads(test, &low_name))
        && counting
            .update
            .as_deref()
            .is_some_and(|update| updates(update, &low_name, UpdateOp::MinusMinus))
        && increment
            .as_expr()
            .is_some_and(|statement| updates(&statement.expr, &count_name, UpdateOp::PlusPlus))
        && combined.op == BinaryOp::BitOr
        && masked(&combined.left, &argument) == Some(!mask)
        && reads(&combined.right, &count_name);
    is_helper.then_some(mask)
}

/// The `mask` of `argument & mask`, if it is a 32-bit integer.
fn masked(expression: &Expr, argument: &Id) -> Option<i32> {
    let Expr::Bin(BinExpr {
        op: BinaryOp::BitAnd,
        left,
        right,
        ..
    }) = expression.unwrap_parens()
    else {
        return None;
    };
    if left.as_ident()?.to_id() != *argument {
        return None;
    }
    let mask = ast::number(right)?;
    if mask.fract() != 0.0 {
        return None;
    }
    i32::try_from(mask as i64).ok()
}

/// Whether `expression` always evaluates to a 32-bit signed integer. `>>>` yields an unsigned
/// one.
fn is_int32(expression: &Expr) -> bool {
    match expression.unwrap_parens() {
        Expr::Bin(binary) => {
            bitwise::is_bitwise(binary.op) && binary.op != BinaryOp::ZeroFillRShift
        }
        Expr::Unary(unary) => unary.op == UnaryOp::Tilde,
        Expr::Lit(Lit::Num(number)) => f64::from(number.value as i32) == number.value,
        _ => false,
    }
}

/// Replaces `helper(x)` with `x`, or `x | 0` when `x` may not be a 32-bit integer.
struct InlineCalls<'helpers> {
    helpers: &'helpers [Id],
    replaced: HashMap<Id, usize>,
}

impl VisitMut for InlineCalls<'_> {
    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        expression.visit_mut_children_with(self);
        let Some((callee, [argument])) = ast::direct_call(expression) else {
            return;
        };
        if argument.spread.is_some() || !self.helpers.contains(&callee.to_id()) {
            return;
        }
        *self.replaced.entry(callee.to_id()).or_default() += 1;
        let span = callee.span;
        let argument = argument.expr.clone();
        *expression = if is_int32(&argument) {
            ast::parenthesized(argument)
        } else {
            Expr::Bin(BinExpr {
                span,
                op: BinaryOp::BitOr,
                left: Box::new(ast::parenthesized(argument)),
                right: Box::new(Expr::Lit(Lit::Num(Number {
                    span,
                    value: 0.0,
                    raw: None,
                }))),
            })
        };
    }
}

/// Removes the declarations of helpers nothing calls any longer.
struct RemoveHelpers(HashSet<Id>);

impl VisitMut for RemoveHelpers {
    fn visit_mut_stmts(&mut self, statements: &mut Vec<Stmt>) {
        statements.retain(|statement| {
            !matches!(statement, Stmt::Decl(Decl::Fn(declaration))
                if self.0.contains(&declaration.ident.to_id()))
        });
        statements.visit_mut_children_with(self);
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
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
        let output = transform(&format!(
            "{HELPER}\nf(convert(a - b & 255), convert(a), convert(~a));"
        ));
        testing::assert_contains(&output, &[], &["f(a - b & 255, a | 0, ~a)"]);
        assert!(!output.contains("function convert"), "{output}");
        let helper = HELPER.replace("-8", "-16");
        let output = transform(&format!("{helper}\nf(convert(a & 255));"));
        assert!(output.contains("convert(a & 255)"), "{output}");
    }
}
