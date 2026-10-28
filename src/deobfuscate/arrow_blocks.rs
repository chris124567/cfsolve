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
//! Inlining preserves `this`, `arguments`, and local variables because arrows share them with
//! the enclosing function. The unused-bindings pass removes the arrow definition afterwards.

use swc_core::ecma::ast::{
    ArrowExpr, BlockStmt, BlockStmtOrExpr, Constructor, Function, Id, Program, ReturnStmt, Stmt,
};
use swc_core::ecma::visit::{Visit, VisitMut, VisitMutWith, VisitWith};

use super::HashMap;
use super::analysis::{Analysis, Bindings};
use crate::js::ast;

pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    let mut inline = Inline {
        bindings: analysis.bindings(program),
        changed: false,
    };
    program.visit_mut_with(&mut inline);
    inline.changed
}

struct Inline<'bindings> {
    bindings: &'bindings Bindings,
    changed: bool,
}

/// The binding and body of `binding = () => { ... }` without `return`.
fn block_arrow(statement: &Stmt) -> Option<(Id, &BlockStmt)> {
    let (id, value) = ast::assignment(&statement.as_expr()?.expr)?;
    let ArrowExpr {
        params,
        body,
        is_async: false,
        is_generator: false,
        ..
    } = value.as_arrow()?
    else {
        return None;
    };
    let BlockStmtOrExpr::BlockStmt(body) = &**body else {
        return None;
    };
    (params.is_empty() && !returns(body)).then_some((id, body))
}

/// Returns the binding called by an argument-free statement such as `binding();`.
fn called(statement: &Stmt) -> Option<Id> {
    let (callee, []) = ast::direct_call(&statement.as_expr()?.expr)? else {
        return None;
    };
    Some(callee.to_id())
}

fn returns(body: &BlockStmt) -> bool {
    struct Returns(bool);
    impl Visit for Returns {
        fn visit_return_stmt(&mut self, _: &ReturnStmt) {
            self.0 = true;
        }
        fn visit_function(&mut self, _: &Function) {}
        fn visit_arrow_expr(&mut self, _: &ArrowExpr) {}
    }
    let mut returns = Returns(false);
    body.visit_with(&mut returns);
    returns.0
}

/// Replaces calls in `statements` and nested blocks with the arrow bodies.
fn replace_calls(statements: &mut [Stmt], bodies: &HashMap<Id, BlockStmt>) -> bool {
    let mut changed = false;
    for statement in statements {
        if let Some(body) = called(statement).and_then(|id| bodies.get(&id)) {
            *statement = Stmt::Block(body.clone());
            changed = true;
        } else if let Stmt::Block(block) = statement {
            changed |= replace_calls(&mut block.stmts, bodies);
        }
    }
    changed
}

/// Finds calls in `statement` and nested blocks.
fn calls(statement: &Stmt, found: &mut Vec<Id>) {
    if let Some(id) = called(statement) {
        found.push(id);
    } else if let Stmt::Block(block) = statement {
        for statement in &block.stmts {
            calls(statement, found);
        }
    }
}

impl Inline<'_> {
    fn inline(&mut self, statements: &mut [Stmt]) {
        let mut arrows: HashMap<Id, &BlockStmt> = HashMap::default();
        let mut bodies = HashMap::default();
        for statement in statements.iter() {
            let mut found = vec![];
            calls(statement, &mut found);
            // Only replace calls after the arrow definition in the same function.
            for id in found {
                if let Some(body) = arrows.remove(&id) {
                    bodies.insert(id, body.clone());
                }
            }
            if let Some((id, body)) = block_arrow(statement)
                && self.bindings.is_written_once(&id)
                && self.bindings.references(&id) == 1
            {
                arrows.insert(id, body);
            }
        }
        self.changed |= !bodies.is_empty() && replace_calls(statements, &bodies);
    }
}

impl VisitMut for Inline<'_> {
    fn visit_mut_function(&mut self, function: &mut Function) {
        function.visit_mut_children_with(self);
        if let Some(body) = &mut function.body {
            self.inline(&mut body.stmts);
        }
    }

    fn visit_mut_constructor(&mut self, constructor: &mut Constructor) {
        constructor.visit_mut_children_with(self);
        if let Some(body) = &mut constructor.body {
            self.inline(&mut body.stmts);
        }
    }

    fn visit_mut_arrow_expr(&mut self, arrow: &mut ArrowExpr) {
        arrow.visit_mut_children_with(self);
        if let BlockStmtOrExpr::BlockStmt(body) = &mut *arrow.body {
            self.inline(&mut body.stmts);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn inlines_blocks_called_once_after_their_definition() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
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
            &[],
            &["{ { var b = a; h(b, this, arguments); } { a = g(); } }"],
        );
        let output =
            transform("class K { constructor() { var s; s = () => { this.a = 1; }; s(); } }");
        testing::assert_contains(&output, &[], &["{ this.a = 1; }"]);
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
