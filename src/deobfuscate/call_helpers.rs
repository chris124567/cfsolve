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
//! method and receiver. The method must be read from the same receiver binding. This keeps
//! the same `this` value as a regular method call. Calls must supply exactly one argument per
//! parameter, without spreads, so the method receives the same arguments.

use oxc::allocator::{CloneIn, GetAllocator, Vec};
use oxc::ast::ast::{Argument, Expression, Function, Program};
use oxc::ast_visit::{VisitMut, walk_mut};
use oxc::span::GetSpan;

use super::analysis::{Analysis, Id};
use super::{HashMap, ast};

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let helpers = ast::functions(program, analysis, &|function| is_helper(function, analysis));
    let mut restore = Restore {
        analysis,
        helpers: &helpers,
        changed: false,
    };
    restore.visit_program(program);
    restore.changed
}

/// Matches `function (receiver, method, ...rest) { return f.call.call(method, receiver, ...rest); }`
/// where `f` is a function literal.
fn is_helper(function: &Function<'_>, analysis: &Analysis<'_>) -> bool {
    if let Some(parameters) = ast::parameters(function)
        && parameters.len() >= 2
        && !function.r#async
        && !function.generator
        && let Some(Expression::CallExpression(call)) =
            ast::returned(function).map(Expression::get_inner_expression)
        && let Some(outer) = call.callee.as_member_expression()
        && let Some(inner) = outer.object().as_member_expression()
        && outer
            .static_property_name()
            .is_some_and(|name| name == "call")
        && inner
            .static_property_name()
            .is_some_and(|name| name == "call")
        && matches!(
            inner.object().get_inner_expression(),
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        )
    {
        let forwarded = call.arguments.iter().map(|argument| {
            let id = analysis.expression_id(argument.as_expression()?)?;
            parameters.iter().position(|&parameter| parameter == id)
        });
        return forwarded.eq([1, 0].into_iter().chain(2..parameters.len()).map(Some));
    }
    false
}

struct Restore<'b, 'a> {
    analysis: &'b Analysis<'a>,
    helpers: &'b HashMap<Id, &'a Function<'a>>,
    changed: bool,
}

impl<'a> Restore<'_, 'a> {
    /// Rewrites `helper(receiver, receiver.method, ...rest)` as `receiver.method(...rest)`.
    fn restore(&self, expression: &Expression<'a>) -> Option<Expression<'a>> {
        let (callee, arguments) = ast::direct_call(expression)?;
        let helper = self.helpers.get(&self.analysis.id(callee)?)?;
        if arguments.len() != helper.params.items.len() || arguments.iter().any(Argument::is_spread)
        {
            return None;
        }
        let [receiver, method, rest @ ..] = arguments else {
            return None;
        };
        let receiver = receiver.as_expression()?;
        let method = method.as_expression()?;
        let object = self
            .analysis
            .expression_id(method.as_member_expression()?.object())?;
        let (target, receiver) = match self.analysis.expression_id(receiver) {
            Some(id) => (id, receiver),
            None => {
                let (id, value) = self.analysis.assignment(receiver)?;
                let bindings = &self.analysis.bindings;
                let unread = bindings.references(&id) == 1 && !bindings.is_mapped_parameter(&id);
                (id, if unread { value } else { receiver })
            }
        };
        if target != object {
            return None;
        }
        let allocator = self.analysis.allocator();
        let mut method = method.clone_in_with_semantic_ids(allocator);
        let member = method.as_member_expression_mut()?;
        *member.object_mut() = receiver.clone_in_with_semantic_ids(allocator);
        let rest = rest
            .iter()
            .map(|argument| argument.clone_in_with_semantic_ids(allocator));
        let rest = Vec::from_iter_in(rest, self.analysis);
        Some(Expression::new_call_expression(
            expression.span(),
            method,
            None,
            rest,
            false,
            self.analysis,
        ))
    }
}

impl<'a> VisitMut<'a> for Restore<'_, 'a> {
    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        walk_mut::walk_expression(self, expression);
        if let Some(restored) = self.restore(expression) {
            *expression = restored;
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
        );
        testing::assert_contains(
            &output,
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
        );
        testing::assert_contains(
            &output,
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
            );
            assert!(output.contains("call(x, x.send"), "{output}");
        }
    }
}
