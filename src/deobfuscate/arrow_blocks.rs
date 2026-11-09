//! Replaces calls to arrow functions with their block bodies:
//!
//! ```js
//! function f() {
//!     var a, step;
//!     step = () => { a = g(); };
//!     h();
//!     { step(); }  // becomes { { a = g(); } }
//! }
//! ```
//!
//! The arrow must be synchronous, take no parameters, and have a block body with no `return`.
//! It must be assigned once in the enclosing function body and called once, without arguments,
//! in a later statement or nested block. The call can run at most once per enclosing call.
//!
//! Inlining preserves lexical `this` and `arguments`. Binding identities and final hygiene
//! keep moved locals distinct from the caller's locals. Bodies containing directives are kept
//! in the arrow. The unused-bindings pass removes the arrow definition afterwards.

use oxc::allocator::{CloneIn, GetAllocator};
use oxc::ast::ast::{
    ArrowFunctionBody, ArrowFunctionExpression, Expression, Function, FunctionBody, Program,
    ReturnStatement, Statement,
};
use oxc::ast_visit::{Visit, VisitMut, walk_mut};
use oxc::syntax::scope::ScopeFlags;

use super::analysis::{Analysis, Id};
use super::{HashMap, ast};

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let mut inline = Inline {
        analysis,
        changed: false,
    };
    inline.visit_program(program);
    inline.changed
}

struct Inline<'b, 'a> {
    analysis: &'b Analysis<'a>,
    changed: bool,
}

impl<'a> VisitMut<'a> for Inline<'_, 'a> {
    /// Covers function bodies and arrow block bodies.
    fn visit_function_body(&mut self, body: &mut FunctionBody<'a>) {
        walk_mut::walk_function_body(self, body);
        self.changed |= inline(&mut body.statements, self.analysis)
    }
}

/// Inlines the arrows that a function body defines into calls in its later statements.
fn inline<'a>(statements: &mut [Statement<'a>], analysis: &Analysis<'a>) -> bool {
    let mut arrows = HashMap::default();
    let mut bodies = HashMap::default();
    let mut called = vec![];
    for statement in statements.iter() {
        calls(statement, analysis, &mut called);
        for id in called.drain(..) {
            if let Some(body) = arrows.remove(&id) {
                bodies.insert(id, body);
            }
        }
        if let Statement::ExpressionStatement(statement) = statement
            && let Some((id, Expression::ArrowFunctionExpression(arrow))) =
                analysis.assignment(&statement.expression)
            && !arrow.r#async
            && arrow.params.items.is_empty()
            && arrow.params.rest.is_none()
            && let ArrowFunctionBody::FunctionBody(body) = &arrow.body
            && body.directives.is_empty()
            && !returns(body)
            && analysis.bindings.is_written_once(&id)
            && analysis.bindings.references(&id) == 1
        {
            arrows.insert(id, analysis.save(body.as_ref()));
        }
    }
    replace(statements, &bodies, analysis)
}

/// Matches a statement `binding();`.
fn called(statement: &Statement<'_>, analysis: &Analysis<'_>) -> Option<Id> {
    let Statement::ExpressionStatement(statement) = statement else {
        return None;
    };
    let (callee, []) = ast::direct_call(&statement.expression)? else {
        return None;
    };
    analysis.id(callee)
}

/// Collects the bindings that a statement or its nested blocks call.
fn calls(statement: &Statement<'_>, analysis: &Analysis<'_>, ids: &mut Vec<Id>) {
    if let Some(id) = called(statement, analysis) {
        ids.push(id)
    } else if let Statement::BlockStatement(block) = statement {
        for statement in &block.body {
            calls(statement, analysis, ids)
        }
    }
}

fn replace<'a>(
    statements: &mut [Statement<'a>],
    bodies: &HashMap<Id, &FunctionBody<'a>>,
    analysis: &Analysis<'a>,
) -> bool {
    let mut changed = false;
    for statement in statements {
        if let Some(body) = called(statement, analysis).and_then(|id| bodies.get(&id)) {
            let inlined = body
                .statements
                .clone_in_with_semantic_ids(analysis.allocator());
            *statement = Statement::new_block_statement(body.span, inlined, analysis);
            changed = true
        } else if let Statement::BlockStatement(block) = statement {
            changed |= replace(&mut block.body, bodies, analysis)
        }
    }
    changed
}

fn returns(body: &FunctionBody<'_>) -> bool {
    struct Returns(bool);

    impl<'a> Visit<'a> for Returns {
        fn visit_return_statement(&mut self, _: &ReturnStatement<'a>) {
            self.0 = true
        }

        fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}

        fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {}
    }

    let mut returns = Returns(false);
    returns.visit_function_body(body);
    returns.0
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn inlines_blocks_called_once_after_their_definition() {
        let transform = |source: &str| testing::rewrite(source, super::run);
        let output = transform(
            "function f() {
                var a, s, t;
                s = () => { a = g(); };
                t = () => { var b = a; h(b, this, arguments); };
                h();
                { t(); s(); }
            }",
        );
        testing::assert_contains(
            &output,
            &["{ { var b = a; h(b, this, arguments); } { a = g(); } }"],
        );
        let output =
            transform("class K { constructor() { var s; s = () => { this.a = 1; }; s(); } }");
        testing::assert_contains(&output, &["{ this.a = 1; }"]);
        for kept in [
            "function f() { var s; s(); s = () => { a(); }; }",
            "function f() { var s; s = () => { a(); }; s(); s(); }",
            "function f() { var s; s = () => { a(); }; if (b) s(); }",
            "function f() { var s; s = () => { a(); }; while (b) { s(); } }",
            "function f() { var s; s = () => { return a(); }; s(); }",
            "function f() { var s; s = (x) => { a(x); }; s(); }",
            "function f() { var s; s = () => { a(); }; g(s()); }",
            "function f() { var s; s = () => { a(); }; function g() { s(); } }",
            "function f() { var s; s = () => { a(); }; s = h; s(); }",
        ] {
            let output = transform(kept);
            assert!(output.contains("s()"), "{output}");
        }
    }
}
