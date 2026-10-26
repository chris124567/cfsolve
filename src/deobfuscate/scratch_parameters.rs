//! Replaces trailing scratch parameters with local declarations:
//!
//! ```js
//! function f(a, b, c) { c = a + 1; return c; }  // becomes function f(a) { var c; ... }
//! ```
//!
//! The obfuscator uses extra parameters as temporary variables. Converts them only when every
//! path assigns the parameter before reading its incoming value, and removes unused ones. This
//! changes the observable `fn.length`.
//!
//! If a function uses `arguments`, removes only unreferenced parameters unless an immediate
//! call proves that no argument reaches them. This preserves sloppy-mode aliasing between
//! parameters and `arguments[i]`.

use std::mem;

use swc_core::atoms::Atom;
use swc_core::common::DUMMY_SP;
use swc_core::ecma::ast::{
    ArrowExpr, AssignExpr, AssignOp, BinExpr, CallExpr, Callee, CondExpr, Decl, Expr, Function, Id,
    Ident, Pat, Program, Stmt, VarDecl, VarDeclKind, VarDeclarator,
};
use swc_core::ecma::visit::{Visit, VisitMut, VisitMutWith, VisitWith};

use super::HashSet;
use super::analysis::hoisting::{self, Hoisted, Hoisting};
use super::analysis::{Analysis, names};

pub(super) fn run(program: &mut Program, _: &mut Analysis) -> bool {
    let mut demote = DemoteScratchParameters { changed: false };
    program.visit_mut_with(&mut demote);
    demote.changed
}

struct DemoteScratchParameters {
    changed: bool,
}

impl VisitMut for DemoteScratchParameters {
    fn visit_mut_function(&mut self, function: &mut Function) {
        function.visit_mut_children_with(self);
        if function.params.is_empty() {
            return;
        }

        let scratch = Scratch::scan(function);
        // Keep parameters through the last one whose incoming value can be observed. With
        // mapped `arguments`, even a write can expose the parameter binding.
        let needed =
            if names::uses_arguments(&function.params) || names::uses_arguments(&function.body) {
                &scratch.used
            } else {
                &scratch.observed
            };
        let keep = function
            .params
            .iter()
            .rposition(|parameter| {
                parameter
                    .pat
                    .as_ident()
                    .is_none_or(|name| needed.contains(&name.to_id()))
            })
            .map_or(0, |last| last + 1);
        self.changed |= demote(function, keep, &scratch.used);
    }

    fn visit_mut_call_expr(&mut self, call: &mut CallExpr) {
        call.visit_mut_children_with(self);

        // An immediate anonymous-function call gives the argument count. Plain parameters
        // beyond it start as `undefined`, matching replacement locals. Patterns may include
        // defaults or rest parameters and need separate handling.
        if let Callee::Expr(callee) = &mut call.callee
            && let Expr::Fn(callee) = callee.unwrap_parens_mut()
            && callee.ident.is_none()
            && call.args.iter().all(|argument| argument.spread.is_none())
            && callee
                .function
                .params
                .iter()
                .skip(call.args.len())
                .all(|parameter| parameter.pat.is_ident())
        {
            let used = Scratch::scan(&callee.function).used;
            self.changed |= demote(&mut callee.function, call.args.len(), &used);
        }
    }
}

/// Removes parameters starting at `keep`, declaring those `used` as locals. Returns whether
/// parameters were removed.
fn demote(function: &mut Function, keep: usize, used: &HashSet<Id>) -> bool {
    if keep >= function.params.len() {
        return false;
    }
    let declarators: Vec<VarDeclarator> = function
        .params
        .drain(keep..)
        .filter_map(|parameter| match parameter.pat {
            Pat::Ident(name) if used.contains(&name.to_id()) => Some(VarDeclarator {
                span: DUMMY_SP,
                name: Pat::Ident(name),
                init: None,
                definite: false,
            }),
            _ => None,
        })
        .collect();

    if !declarators.is_empty()
        && let Some(body) = &mut function.body
    {
        // Insert after directives: moving `"use strict"` behind another statement would disable
        // strict mode.
        swc_ecma_utils::prepend_stmt(
            &mut body.stmts,
            Stmt::Decl(Decl::Var(Box::new(VarDecl {
                kind: VarDeclKind::Var,
                decls: declarators,
                ..Default::default()
            }))),
        );
    }
    true
}

/// Finds parameters that may be read before assignment. Tracks assignments along each path.
/// Assignments in optional or repeated paths are not guaranteed; branch joins keep only
/// assignments made on every path.
#[derive(Default)]
struct Scratch {
    parameters: HashSet<Id>,
    /// Read on some path before being assigned on it.
    observed: HashSet<Id>,
    /// Mentioned anywhere, and so still needing a binding.
    used: HashSet<Id>,
    /// The labelled statements around the node, innermost last.
    labels: Vec<Label>,
    /// Tracks parameters assigned on the path to the current node.
    hoisting: Hoisting<HashSet<Id>>,
}

/// A labelled statement around the node being scanned.
struct Label {
    name: Atom,
    /// Intersection of assignments from all `break` paths seen so far; absent before the first
    /// break.
    broken: Option<HashSet<Id>>,
}

impl Scratch {
    fn scan(function: &Function) -> Self {
        let mut scratch = Self {
            parameters: function
                .params
                .iter()
                .filter_map(|parameter| Some(parameter.pat.as_ident()?.to_id()))
                .collect(),
            ..Default::default()
        };
        if let Some(body) = &function.body {
            scratch.hoisting.function_body = true;
            scratch.statements(&body.stmts);
        }
        scratch
    }

    /// Scans statements and reports whether execution can continue after them. Visits hoisted
    /// declarations even after a return or throw, using assignments guaranteed at every
    /// possible call. See [`hoisting`].
    fn statements(&mut self, statements: &[Stmt]) -> bool {
        let mut reachable = true;
        hoisting::visit_stmts(self, statements, |scratch, statement| {
            reachable &= scratch.statement(statement);
        });
        reachable
    }

    /// Whether control can reach the statement after `statement`.
    fn statement(&mut self, statement: &Stmt) -> bool {
        match statement {
            Stmt::Block(block) => self.statements(&block.stmts),
            Stmt::Labeled(labeled) => {
                self.labels.push(Label {
                    name: labeled.label.sym.clone(),
                    broken: None,
                });
                let flows = self.statement(&labeled.body);
                let Label { broken, .. } = self.labels.pop().expect("the label was pushed above");
                // A `break` leaves this statement and joins the normal fallthrough path.
                match broken {
                    Some(broken) if flows => {
                        self.hoisting.facts.retain(|id| broken.contains(id));
                        true
                    }
                    Some(broken) => {
                        self.hoisting.facts = broken;
                        true
                    }
                    None => flows,
                }
            }
            Stmt::Break(jump) => {
                if let Some(label) = &jump.label
                    && let Some(Label { broken, .. }) = self
                        .labels
                        .iter_mut()
                        .rev()
                        .find(|enclosing| enclosing.name == label.sym)
                {
                    match broken {
                        Some(broken) => broken.retain(|id| self.hoisting.facts.contains(id)),
                        None => *broken = Some(self.hoisting.facts.clone()),
                    }
                }
                // An unlabelled `break` leaves a loop or `switch`, after which
                // nothing they assign is known anyway.
                false
            }
            Stmt::Return(_) | Stmt::Throw(_) | Stmt::Continue(_) => {
                statement.visit_children_with(self);
                false
            }
            Stmt::If(conditional) => {
                conditional.test.visit_with(self);

                let entry = self.hoisting.facts.clone();
                let consequent = self.path(&entry, |scratch| scratch.statement(&conditional.cons));
                let alternate = self.path(&entry, |scratch| {
                    conditional
                        .alt
                        .as_deref()
                        .is_none_or(|alternate| scratch.statement(alternate))
                });

                self.hoisting.facts = match (consequent.flows, alternate.flows) {
                    (true, false) => consequent.assigned,
                    (false, true) => alternate.assigned,
                    _ => &consequent.assigned & &alternate.assigned,
                };
                consequent.flows || alternate.flows
            }
            Stmt::Expr(_) | Stmt::Decl(_) | Stmt::Empty(_) | Stmt::Debugger(_) => {
                statement.visit_children_with(self);
                true
            }
            // The handler may start after any part of the block; the finalizer may start after
            // any part of the block or handler. Both therefore use assignments known before the
            // block.
            Stmt::Try(statement) => {
                self.fork(|scratch| statement.block.visit_with(scratch));
                self.fork(|scratch| statement.handler.visit_with(scratch));
                self.fork(|scratch| statement.finalizer.visit_with(scratch));
                true
            }
            // Cases may be entered by a matching test or by fallthrough. Conservatively start
            // each test and case with assignments known after the discriminant.
            Stmt::Switch(switch) => {
                switch.discriminant.visit_with(self);
                for case in &switch.cases {
                    self.fork(|scratch| case.test.visit_with(scratch));
                }
                for case in &switch.cases {
                    self.fork(|scratch| case.cons.visit_with(scratch));
                }
                true
            }
            // The update can follow the body or a `continue`, so only assignments before the
            // body are guaranteed.
            Stmt::For(loop_) => {
                self.fork(|scratch| {
                    loop_.init.visit_with(scratch);
                    loop_.test.visit_with(scratch);
                    scratch.fork(|scratch| _ = scratch.statement(&loop_.body));
                    loop_.update.visit_with(scratch);
                });
                true
            }
            // Likewise the test, which a `continue` jumps to.
            Stmt::DoWhile(loop_) => {
                self.fork(|scratch| {
                    scratch.fork(|scratch| _ = scratch.statement(&loop_.body));
                    loop_.test.visit_with(scratch);
                });
                true
            }
            // Other loops may execute an unknown number of times. Discard assignments made
            // inside them.
            statement => {
                self.fork(|scratch| statement.visit_children_with(scratch));
                true
            }
        }
    }

    /// Scans a path that may be skipped, keeping only what it reads.
    fn fork(&mut self, scan: impl FnOnce(&mut Self)) {
        let entry = self.hoisting.facts.clone();
        scan(self);
        self.hoisting.facts = entry;
    }

    /// Scans from `entry`.
    fn path(&mut self, entry: &HashSet<Id>, scan: impl FnOnce(&mut Self) -> bool) -> Branch {
        self.hoisting.facts.clone_from(entry);
        let flows = scan(self);
        Branch {
            assigned: mem::take(&mut self.hoisting.facts),
            flows,
        }
    }
}

/// What one branch of a conditional guarantees.
struct Branch {
    /// Parameters the branch is guaranteed to assign.
    assigned: HashSet<Id>,
    /// Whether execution can fall through the branch.
    flows: bool,
}

impl Visit for Scratch {
    fn visit_stmt(&mut self, statement: &Stmt) {
        self.statement(statement);
    }

    fn visit_stmts(&mut self, statements: &[Stmt]) {
        self.statements(statements);
    }

    fn visit_ident(&mut self, identifier: &Ident) {
        hoisting::reference(self, identifier);
        let id = identifier.to_id();
        if self.parameters.contains(&id) {
            if !self.hoisting.facts.contains(&id) {
                self.observed.insert(id.clone());
            }
            self.used.insert(id);
        }
    }

    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        if assignment.op == AssignOp::Assign
            && let Some(target) = assignment.left.as_ident()
        {
            // The value is evaluated before the store, so it reads first.
            assignment.right.visit_with(self);
            let id = target.to_id();
            if self.parameters.contains(&id) {
                self.used.insert(id.clone());
                self.hoisting.facts.insert(id);
            }
        } else {
            assignment.visit_children_with(self);
        }
    }

    fn visit_cond_expr(&mut self, conditional: &CondExpr) {
        conditional.test.visit_with(self);
        self.fork(|scratch| conditional.cons.visit_with(scratch));
        self.fork(|scratch| conditional.alt.visit_with(scratch));
    }

    fn visit_bin_expr(&mut self, binary: &BinExpr) {
        if binary.op.may_short_circuit() {
            binary.left.visit_with(self);
            self.fork(|scratch| binary.right.visit_with(scratch));
        } else {
            binary.visit_children_with(self);
        }
    }

    /// A function expression's body uses assignments known when it was created. Declarations
    /// use facts supplied by [`Scratch::statements`].
    fn visit_function(&mut self, function: &Function) {
        self.fork(|scratch| {
            function.decorators.visit_with(scratch);
            function.params.visit_with(scratch);
            if let Some(body) = &function.body {
                scratch.hoisting.function_body = true;
                scratch.statements(&body.stmts);
            }
        });
    }

    fn visit_arrow_expr(&mut self, arrow: &ArrowExpr) {
        self.fork(|scratch| arrow.visit_children_with(scratch));
    }
}

impl Hoisted for Scratch {
    type Facts = HashSet<Id>;

    fn hoisting(&mut self) -> &mut Hoisting<HashSet<Id>> {
        &mut self.hoisting
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn demotes_parameters_every_path_writes_first() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
        let output = transform("function f(a, b, c, d) { c = a + 1; return c; }");
        testing::assert_contains(&output, &["function f(a)", "var c;"], &[]);
        assert!(!output.contains('d'), "{output}");
        for source in [
            "function f(x, a) { if (x) { a = 1; use(a); } else { for (a = 0; a < 2; a++) use(a); } }",
            "function f(c, a) { l: { if (c) { a = 2; break l; } a = 1; } return a; }",
            "function f(c, a) { try { a = 1; } catch (e) {} return; }",
            "function f(a) { a = 1; g(); function g() { return a; } }",
        ] {
            let output = transform(source);
            assert!(output.contains("var a;"), "{source}: {output}");
        }
        // An immediate call leaves every parameter past its arguments unset.
        let output = transform("(function (a, b, c) { g(b); b = 1; return a + b + c; })(x);");
        testing::assert_contains(&output, &["function(a)", "var b, c;"], &[]);
    }

    #[test]
    fn keeps_parameters_that_may_hold_an_argument() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
        // Additional try, switch, label, and loop cases are covered in `tests/deobfuscate.rs`.
        for source in [
            "function f(a) { a = a || 1; return a; }",
            "function f(a) { if (x) a = 1; return a; }",
            "function f(a) { for(;;) a = 1; return a; }",
            "function f(a) { x ? a = 1 : 0; return a; }",
            "function f(a) { x && (a = 1); return a; }",
            "function f(a) { g(); a = 1; function g() { return a; } }",
            "function f(a) { g(a); a = 1; return a; }",
            "function f(a) { h(); a = 1; function h() { return g(); } function g() { return a; } }",
        ] {
            let output = transform(source);
            assert!(output.contains("function f(a)"), "{source}: {output}");
        }
        // Functions using `arguments`.
        let output = transform(
            "function f(a, b) { b = 2; return arguments[1]; } \
             function g(a, b) { b = 2; return () => arguments[1]; } \
             function h(a, b) { b = 2; return function () { return arguments[0]; }; } \
             function k(a, b, c) { return arguments.length; }",
        );
        testing::assert_contains(&output, &["function k()", "function f(a, b)"], &[]);
        testing::assert_contains(&output, &["function g(a, b)", "function h()"], &[]);
        // Patterns, defaults, and recursive calls that can fill a parameter.
        let output = transform("function f(a, b = 1, { c }, ...d) { b = 2; return [a, b, c, d]; }");
        testing::assert_contains(&output, &["function f(a, b = 1, { c }, ...d)"], &[]);
        let output = transform("(function (a, b = 1, ...c) { return [a, b, c]; })(x);");
        assert!(output.contains("function(a, b = 1, ...c)"), "{output}");
        let output = transform("(function g(a, b) { return b ? a : g(a, 1); })(x);");
        assert!(output.contains("function g(a, b)"), "{output}");
    }
}
