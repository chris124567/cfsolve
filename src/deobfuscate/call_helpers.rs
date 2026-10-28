//! Restores method calls that the obfuscator routes through `Function.prototype.call`:
//!
//! ```js
//! var call = function(self, method, a) { return (function() {}).call.call(method, self, a); };
//! call(xhr, xhr.send, body);        // becomes xhr.send(body)
//! call(o = xhr, o.open, "POST");    // becomes (o = xhr).open("POST"), or xhr.open("POST")
//!                                   // when nothing else reads o
//! ```
//!
//! The helper must be assigned once and forward parameters in order, except for swapping the
//! method and receiver. The method must be read from the receiver's local binding. This keeps
//! the same `this` value as a regular method call. Calls must supply exactly one argument per
//! parameter, without spreads, so the method receives the same arguments.

use swc_core::common::util::take::Take;
use swc_core::ecma::ast::{
    CallExpr, Callee, Expr, ExprOrSpread, FnDecl, Function, Id, MemberExpr, Pat, Program, Stmt,
    VarDeclarator,
};
use swc_core::ecma::visit::{Visit, VisitMut, VisitMutWith, VisitWith};

use super::HashMap;
use super::analysis::{Analysis, Bindings, Globals, names};
use crate::js::ast;

pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    let globals = analysis.globals;
    let bindings = analysis.bindings(program);
    let mut helpers = Helpers::default();
    program.visit_with(&mut helpers);
    helpers.0.retain(|id, _| bindings.is_written_once(id));
    if helpers.0.is_empty() {
        return false;
    }
    let mut restore = Restore {
        helpers: &helpers.0,
        bindings,
        globals,
        changed: false,
    };
    program.visit_mut_with(&mut restore);
    restore.changed
}

/// Checks for a helper of the form `function(self, method, ...rest) { return (function()
/// {}).call.call(method, self, ...rest); }` with plain parameters.
fn is_helper(function: &Function) -> bool {
    let is_call = |member: &MemberExpr| ast::member_str(&member.prop) == Some("call");
    if let Some(parameters) = names::parameter_ids(&function.params)
        && parameters.len() >= 2
        && !function.is_async
        && !function.is_generator
        && let Some([Stmt::Return(returned)]) = function.body.as_ref().map(|body| &body.stmts[..])
        && let Some(call) = returned.arg.as_deref().and_then(Expr::as_call)
        && let Some(callee) = call.callee.as_expr().and_then(|callee| callee.as_member())
        && let Some(inner) = callee.obj.as_member()
        && is_call(callee)
        && is_call(inner)
        && matches!(inner.obj.unwrap_parens(), Expr::Fn(_) | Expr::Arrow(_))
    {
        let passed = call.args.iter().map(|argument| {
            let id = argument
                .expr
                .as_ident()
                .filter(|_| argument.spread.is_none())?
                .to_id();
            parameters.iter().position(|parameter| *parameter == id)
        });
        let swapped = [1, 0].into_iter().chain(2..parameters.len()).map(Some);
        passed.eq(swapped)
    } else {
        false
    }
}

/// Helpers by binding, with the number of parameters they forward.
#[derive(Default)]
struct Helpers(HashMap<Id, usize>);

impl Visit for Helpers {
    fn visit_expr(&mut self, expression: &Expr) {
        if let Some((id, Expr::Fn(function))) = ast::assignment(expression)
            && is_helper(&function.function)
        {
            self.0.insert(id, function.function.params.len());
        }
        expression.visit_children_with(self);
    }

    fn visit_fn_decl(&mut self, declaration: &FnDecl) {
        if is_helper(&declaration.function) {
            self.0
                .insert(declaration.ident.to_id(), declaration.function.params.len());
        }
        declaration.visit_children_with(self);
    }

    fn visit_var_declarator(&mut self, declarator: &VarDeclarator) {
        if let Pat::Ident(name) = &declarator.name
            && let Some(Expr::Fn(function)) = declarator.init.as_deref()
            && is_helper(&function.function)
        {
            self.0.insert(name.to_id(), function.function.params.len());
        }
        declarator.visit_children_with(self);
    }
}

struct Restore<'a> {
    helpers: &'a HashMap<Id, usize>,
    bindings: &'a Bindings,
    globals: Globals,
    changed: bool,
}

impl Restore<'_> {
    /// Rewrites `helper(receiver, receiver.method, ...rest)` as a method call.
    fn method_call(&self, arguments: &mut Vec<ExprOrSpread>, parameters: usize) -> Option<Expr> {
        // The helper forwards every parameter, including missing ones as undefined, and ignores
        // extra arguments after evaluating them. Only a matching, spread-free call forwards the
        // same arguments directly to the method.
        if arguments.len() != parameters
            || arguments.iter().any(|argument| argument.spread.is_some())
        {
            return None;
        }
        let [receiver, method, ..] = &mut arguments[..] else {
            return None;
        };
        let Expr::Member(member) = &mut *method.expr else {
            return None;
        };
        let object = member.obj.as_ident()?.to_id();
        let (target, unread) = match &*receiver.expr {
            Expr::Ident(identifier) => (identifier.to_id(), false),
            assignment => {
                let (target, _) = ast::assignment(assignment)?;
                // The method access below is the only read of the assigned local.
                let unread = self.bindings.references(&target) == 1
                    && target.1 != self.globals.unresolved
                    && !self.bindings.is_mapped_parameter(&target);
                (target, unread)
            }
        };
        if target != object {
            return None;
        }
        let mut receiver = receiver.expr.take();
        if unread {
            receiver = receiver.expect_assign().right;
        }
        member.obj = receiver;
        Some(Expr::Call(CallExpr {
            callee: Callee::Expr(method.expr.take()),
            args: arguments.split_off(2),
            ..Default::default()
        }))
    }
}

impl VisitMut for Restore<'_> {
    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        expression.visit_mut_children_with(self);
        if let Expr::Call(call) = expression
            && let Some(callee) = call.callee.as_expr().and_then(|callee| callee.as_ident())
            && let Some(&parameters) = self.helpers.get(&callee.to_id())
            && let Some(replacement) = self.method_call(&mut call.args, parameters)
        {
            *expression = replacement;
            self.changed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn keeps_calls_whose_arguments_do_not_match_the_helpers_parameters() {
        let output = testing::rewrite(
            "function call(s, m, a) { return (function() {}).call.call(m, s, a); }
             call(x, x.send);
             call(x, x.send, 1, effect());
             call(x, x.send, ...values);
             call(x, x.send, 1, ...values);
             call(...values, x.send, 1);
             call(x, ...methods, 1);
             call(x, x.send, 1);",
            super::run,
            /* fix= */ true,
        );
        testing::assert_contains(
            &output,
            &[],
            &[
                "call(x, x.send);",
                "call(x, x.send, 1, effect());",
                "call(x, x.send, ...values);",
                "call(x, x.send, 1, ...values);",
                "call(...values, x.send, 1);",
                "call(x, ...methods, 1);",
                "x.send(1);",
            ],
        );
    }

    #[test]
    fn restores_method_calls_on_the_receiver_they_read() {
        let output = testing::rewrite(
            "var call = function(s, m, a, b) { return (function() {}).call.call(m, s, a, b); };
            function f(x) {
                var o, p, q;
                call(x, x.send, 1, 2);
                call(o = g(), o.open, 3, 4);
                call(p = g(), p.open, 5, 6); h(p);
                call(q = g(), x.open, 7, 8);
                call(x, x.y.z, 9, 10);
            }",
            super::run,
            /* fix= */ true,
        );
        testing::assert_contains(
            &output,
            &[],
            &[
                "x.send(1, 2);",
                "g().open(3, 4);",
                "(p = g()).open(5, 6);",
                "call(q = g(), x.open, 7, 8);",
                "call(x, x.y.z, 9, 10);",
            ],
        );
        for helper in [
            "function(s, m, a) { return (function() {}).call.call(m, s); }",
            "function(s, m, a) { return (function() {}).call.call(m, a, s); }",
            "function(s, m) { return (function() {}).apply.call(m, s); }",
            "function(s, m) { g(); return (function() {}).call.call(m, s); }",
        ] {
            let output = testing::rewrite(
                &format!("var call = {helper}; call(x, x.send, 1);"),
                super::run,
                /* fix= */ true,
            );
            assert!(output.contains("call(x, x.send"), "{output}");
        }
    }
}
