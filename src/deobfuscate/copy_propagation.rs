//! Replaces scratch copies with their assigned values:
//!
//! ```js
//! flag = true; listen(handler, flag);  // becomes listen(handler, true)
//! ```
//!
//! Requires exactly one assignment and proof that it ran before each replaced read. This
//! includes later statements in the same list and hoisted functions callable only after the
//! assignment (see [`hoisting`]). Removes assignments once no reads remain.

use std::rc::Rc;

use swc_core::ecma::ast::{
    AssignOp, BlockStmt, Decl, Expr, Function, Id, Ident, Lit, Program, Stmt,
};
use swc_core::ecma::visit::{VisitMut, VisitMutWith};

use super::analysis::hoisting::{self, Hoisted, Hoisting};
use super::analysis::{Analysis, Bindings};
use super::{HashMap, HashSet, removal};

pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    let bindings = analysis.bindings(program);
    let mut propagate = PropagateCopies {
        bindings,
        hoisting: Hoisting::default(),
        functions: HashSet::default(),
        substituted: HashMap::default(),
        changed: false,
    };
    program.visit_mut_with(&mut propagate);
    let unread = removal::unread(&propagate.substituted, bindings);
    let removed = removal::remove_definitions(program, &unread);
    propagate.changed || removed
}

struct PropagateCopies<'bindings> {
    bindings: &'bindings Bindings,
    /// Bindings with exactly one assignment that has run on every path to this node. Includes
    /// replacement values when known. Shares storage with declaration snapshots until changed.
    hoisting: Hoisting<Rc<HashMap<Id, Option<Expr>>>>,
    /// Single-write function declarations, which hold their value from the start of their
    /// scope.
    functions: HashSet<Id>,
    /// How many reads of each substitutable binding were substituted.
    substituted: HashMap<Id, usize>,
    changed: bool,
}

impl VisitMut for PropagateCopies<'_> {
    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        expression.visit_mut_children_with(self);

        if let Expr::Ident(identifier) = expression
            && let Some(Some(value)) = self.hoisting.facts.get(&identifier.to_id())
        {
            *self.substituted.entry(identifier.to_id()).or_default() += 1;
            *expression = value.clone();
            self.changed = true;
        }
    }

    /// Keep assignments known for the rest of their statement list. Visit function declarations
    /// last with facts valid at every possible call; discard list-local facts afterward.
    fn visit_mut_stmts(&mut self, statements: &mut Vec<Stmt>) {
        let outer = self.hoisting.facts.clone();
        for statement in statements.iter() {
            if let Stmt::Decl(Decl::Fn(declaration)) = statement
                && self.bindings.is_written_once(&declaration.ident.to_id())
            {
                self.functions.insert(declaration.ident.to_id());
            }
        }
        hoisting::visit_mut_stmts(self, statements, |propagate, statement| match statement {
            Stmt::Expr(statement) => propagate.statement_expression(&mut statement.expr),
            Stmt::Decl(Decl::Var(declaration)) => {
                for declarator in &mut declaration.decls {
                    declarator.init.visit_mut_with(propagate);
                    if let Some(target) = declarator.name.as_ident()
                        && let Some(value) = &declarator.init
                    {
                        propagate.record(target.to_id(), value);
                    }
                }
            }
            Stmt::If(conditional) => {
                propagate.statement_expression(&mut conditional.test);
                conditional.cons.visit_mut_with(propagate);
                conditional.alt.visit_mut_with(propagate);
            }
            statement => statement.visit_mut_with(propagate),
        });
        self.hoisting.facts = outer;
    }

    fn visit_mut_function(&mut self, function: &mut Function) {
        hoisting::visit_mut_function(self, function);
    }

    fn visit_mut_block_stmt(&mut self, block: &mut BlockStmt) {
        hoisting::visit_mut_block(self, block);
    }

    fn visit_mut_ident(&mut self, identifier: &mut Ident) {
        hoisting::reference(self, identifier);
    }
}

impl Hoisted for PropagateCopies<'_> {
    type Facts = Rc<HashMap<Id, Option<Expr>>>;

    fn hoisting(&mut self) -> &mut Hoisting<Self::Facts> {
        &mut self.hoisting
    }
}

impl PropagateCopies<'_> {
    /// Visits an expression that always runs with its statement. Records unconditional
    /// assignments in sequences, assigned values, and the left operands of short-circuit
    /// operators.
    fn statement_expression(&mut self, expression: &mut Expr) {
        match expression {
            Expr::Paren(paren) => self.statement_expression(&mut paren.expr),
            Expr::Seq(sequence) => {
                for operand in &mut sequence.exprs {
                    self.statement_expression(operand);
                }
            }
            Expr::Bin(binary) if binary.op.may_short_circuit() => {
                self.statement_expression(&mut binary.left);
                binary.right.visit_mut_with(self);
            }
            Expr::Assign(assignment) => {
                assignment.left.visit_mut_with(self);
                self.statement_expression(&mut assignment.right);
                if assignment.op == AssignOp::Assign
                    && let Some(target) = assignment.left.as_ident()
                {
                    self.record(target.to_id(), &assignment.right);
                }
            }
            expression => expression.visit_mut_with(self),
        }
    }

    /// Records that `target` now holds `value`, if this is its only write.
    fn record(&mut self, target: Id, value: &Expr) {
        if !self.bindings.is_written_once(&target) || self.bindings.is_mapped_parameter(&target) {
            return;
        }
        let value = self.is_stable(value).then(|| value.clone());
        if value.is_some() {
            self.substituted.entry(target.clone()).or_default();
        }
        Rc::make_mut(&mut self.hoisting.facts).insert(target, value);
    }

    /// Excludes regex literals, which have identity and state. A copied binding must already
    /// hold its only assigned value, or be a parameter whose argument is never overwritten.
    fn is_stable(&self, value: &Expr) -> bool {
        match value {
            Expr::Lit(literal) => !matches!(literal, Lit::Regex(_)),
            Expr::Tpl(template) => template.exprs.is_empty(),
            Expr::Ident(identifier) => {
                let id = identifier.to_id();
                let unchanged_parameter = self.bindings.is_parameter(&id)
                    && self.bindings.write_count(&id) == 0
                    && !self.bindings.is_mapped_parameter(&id);
                self.hoisting.facts.contains_key(&id)
                    || self.functions.contains(&id)
                    || unchanged_parameter
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn substitutes_copies_assigned_before_every_read() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
        let output = transform("function f(a, b, c) { a = {}; b = a; c = true; b.x = c; use(b); }");
        testing::assert_contains(&output, &["a.x = true;", "use(a);"], &[]);
        testing::assert_lacks(&output, &["b = a", "c = true"]);
        // Declarations, and values assigned alongside others.
        let output = transform(
            "function f(a, b, c) { c = (a = 1, b = g, function () { return a; }); \
             return b(c); function g() {} }",
        );
        testing::assert_contains(&output, &["return g(c);"], &["c = function() { return 1;"]);
        // Values assigned where a condition always runs.
        let output = transform(
            "function f(a, b, c) { if ((a = `m`, c) && (b = 1, g())) { return; } x[a](b); }",
        );
        testing::assert_contains(&output, &["x[`m`](b);"], &[]);
        testing::assert_lacks(&output, &["a = `m`"]);
        // A read before the write keeps the binding.
        let output = transform("function f(a) { use(a); a = 1; return a; }");
        testing::assert_contains(&output, &["return 1;"], &["use(a); a = 1;"]);
        // Parameters whose arguments are never overwritten.
        let output = transform("function f(p, q) { var a, b; a = p; b = q; q = 1; return a + b; }");
        testing::assert_contains(&output, &["return p + b;"], &[]);
        let output = transform("function f(p) { var a; a = p; return a + arguments[0]; }");
        testing::assert_contains(&output, &["return a + arguments[0];"], &[]);
    }

    #[test]
    fn preserves_reads_the_assignment_may_not_precede() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
        for (source, kept) in [
            (
                "function f(c, r) { if (c) { r = 1; } return r; }",
                "return r;",
            ),
            (
                "function f(c, r) { if (c && (r = 1)) { g(); } return r; }",
                "return r;",
            ),
            (
                "function f(a, b) { b = a; a = a.x; return b; }",
                "return b;",
            ),
            ("function f(a) { a = 1; return { a }; }", "a = 1;"),
            ("function f(a) { a = 1; a = 2; return a; }", "return a;"),
            (
                "function f(a, b) { b = a; a = 1; a = 2; return b; }",
                "return b;",
            ),
        ] {
            let output = transform(source);
            assert!(output.contains(kept), "{source}: {output}");
        }
    }
}
