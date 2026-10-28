//! Restores plain expressions from minifier forms:
//!
//! ```js
//! !0; void 0; (0, f)(x); (0, Date).now();  // becomes true; undefined; f(x); Date.now()
//! ```
//!
//! Folds `!` and `void` only for effect-free literal operands. Unwraps literal callee sequences
//! only when the final value is an identifier other than `eval`, preserving call behavior. Also
//! simplifies literal sequences used for property access. New `undefined` references resolve to the
//! global binding.

use swc_core::ecma::ast::{
    ArrayLit, Bool, Callee, Expr, Lit, MemberExpr, ObjectLit, Program, UnaryExpr, UnaryOp,
};
use swc_core::ecma::visit::{VisitMut, VisitMutWith};

use super::analysis::{Analysis, Globals};

pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    let mut restore = RestoreKeywords {
        globals: analysis.globals,
        changed: false,
    };
    program.visit_mut_with(&mut restore);
    restore.changed
}

struct RestoreKeywords {
    globals: Globals,
    changed: bool,
}

impl VisitMut for RestoreKeywords {
    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        expression.visit_mut_children_with(self);

        if let Expr::Unary(UnaryExpr { span, op, arg }) = expression
            && let Some(truthy) = literal_truthiness(arg)
        {
            *expression = match op {
                UnaryOp::Bang => Expr::Lit(Lit::Bool(Bool {
                    span: *span,
                    value: !truthy,
                })),
                UnaryOp::Void => Expr::Ident(self.globals.reference("undefined", *span)),
                _ => return,
            };
            self.changed = true;
        }
    }

    /// `(0, f)` and `f` both call without a receiver, except when `f` is named `eval`. Calling
    /// that name directly may invoke direct eval, even for a local binding holding the built-in
    /// function.
    fn visit_mut_callee(&mut self, callee: &mut Callee) {
        callee.visit_mut_children_with(self);

        if let Callee::Expr(expression) = callee
            && let Expr::Seq(sequence) = expression.unwrap_parens_mut()
            && let [discarded @ .., last] = &sequence.exprs[..]
            && let Expr::Ident(name) = &**last
            && name.sym != "eval"
            && discarded.iter().all(|operand| operand.is_lit())
        {
            let name = sequence.exprs.pop().expect("the sequence ends in a name");
            *expression = name;
            self.changed = true;
        }
    }

    /// `(0, o).p` and `o.p` read the same property and preserve the same receiver when called.
    fn visit_mut_member_expr(&mut self, member: &mut MemberExpr) {
        member.visit_mut_children_with(self);

        if let Expr::Seq(sequence) = member.obj.unwrap_parens_mut()
            && let [discarded @ .., _] = &sequence.exprs[..]
            && discarded.iter().all(|operand| operand.is_lit())
        {
            member.obj = sequence.exprs.pop().expect("the sequence is not empty");
            self.changed = true;
        }
    }
}

/// Truthiness of a side-effect-free literal, or `None` if it is not one.
fn literal_truthiness(expression: &Expr) -> Option<bool> {
    match expression {
        Expr::Lit(Lit::Num(number)) => Some(number.value != 0.0 && !number.value.is_nan()),
        Expr::Lit(Lit::Str(string)) => Some(!string.value.is_empty()),
        Expr::Lit(Lit::Bool(boolean)) => Some(boolean.value),
        Expr::Lit(Lit::Null(_)) => Some(false),
        Expr::Array(ArrayLit { elems, .. }) if elems.is_empty() => Some(true),
        Expr::Object(ObjectLit { props, .. }) if props.is_empty() => Some(true),
        Expr::Paren(paren) => literal_truthiness(&paren.expr),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn restores_literals_and_direct_calls() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
        let output =
            transform("function f() { return [!0, !1, !2, !'', !'a', !null, !![], !{}]; }");
        testing::assert_contains(
            &output,
            &[],
            &["true, false, false, true, false, true, true, false"],
        );
        assert!(!output.contains('!'), "{output}");
        assert_eq!(transform(&output), output);
        let output = transform("function f(x) { x = void 0; return x === void 0 ? void 1 : x; }");
        let expected = ["x = undefined;", "x === undefined ? undefined : x"];
        testing::assert_contains(&output, &expected, &[]);
        assert!(!output.contains("void"), "{output}");
        // Operands that may have effects stay.
        let output = transform("function f(x) { return [!x, !f(), !x.y, void f(), void x]; }");
        testing::assert_contains(&output, &["!x", "!f()", "!x.y", "void f()", "void x"], &[]);
        assert!(!output.contains("undefined"), "{output}");
        // Indirect calls of names other than `eval` become direct.
        let output = transform("function f(g, o) { (0, g)(this, 1); (0, o.m)(); (0, eval)('x'); }");
        testing::assert_contains(&output, &["g(this, 1);", "(0, o.m)();", "(0, eval)("], &[]);
        // A property access uses the final value of the sequence as its object.
        let output = transform(
            "function f(o) { return [(0, Date).now(), (1, o).p, (0, o.a).push(1), (g(), o).q]; }",
        );
        testing::assert_contains(&output, &[], &["Date.now(), o.p, o.a.push(1), (g(), o).q"]);
    }
}
