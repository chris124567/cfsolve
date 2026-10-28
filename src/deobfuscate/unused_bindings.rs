//! Removes the declarations of unread locals, and their definitions when evaluating the value
//! has no side effects. If the value assigns another binding, removes only the unused definition:
//!
//! ```js
//! var unused, add, all, copy;
//! add = function(a, b) { var scratch; return a + b; };
//! all = [add];  // everything is removed, `all` first
//! copy = other = g();  // becomes other = g()
//! [add, other];  // removed, as are other statements without effects
//! ```
//!
//! Leaves globals, whose writes other scripts can observe, and parameters of functions using
//! `arguments`, whose writes `arguments` reflects.

use swc_core::common::util::take::Take;
use swc_core::ecma::ast::{Decl, Expr, Id, Lit, Program, SeqExpr, Stmt, VarDeclarator};
use swc_core::ecma::visit::{VisitMut, VisitMutWith};

use super::analysis::{Analysis, Bindings, Globals};
use super::{HashMap, removal};
use crate::js::ast;

pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    let globals = analysis.globals;
    let mut remove = RemoveUnused {
        bindings: analysis.bindings(program),
        globals,
        removed: HashMap::default(),
        changed: false,
    };
    program.visit_mut_with(&mut remove);
    remove.changed
}

struct RemoveUnused<'bindings> {
    bindings: &'bindings Bindings,
    globals: Globals,
    /// How many writes of each binding this pass has removed. Statement lists are visited
    /// after the lists they contain, so a declaration sees the definitions removed below it.
    removed: HashMap<Id, usize>,
    changed: bool,
}

impl RemoveUnused<'_> {
    fn is_unused(&self, id: &Id) -> bool {
        id.1 != self.globals.unresolved
            && self.bindings.references(id) == 0
            && !self.bindings.is_mapped_parameter(id)
    }

    /// Recognizes an assignment of an effect-free value to an unused binding. Records the
    /// removed write.
    fn remove_definition(&mut self, expression: &Expr) -> bool {
        match ast::assignment(expression) {
            Some((id, value)) if self.is_unused(&id) && self.is_pure(value) => {
                *self.removed.entry(id).or_default() += 1;
                true
            }
            _ => false,
        }
    }

    /// Whether evaluating `value` has no effects and cannot throw. Reading a global can throw
    /// or run a getter; reading a local cannot.
    fn is_pure(&self, value: &Expr) -> bool {
        match value {
            Expr::Fn(_) | Expr::Arrow(_) | Expr::Lit(_) => true,
            Expr::Ident(identifier) => identifier.ctxt != self.globals.unresolved,
            Expr::Tpl(template) => template.exprs.is_empty(),
            Expr::Paren(paren) => self.is_pure(&paren.expr),
            Expr::Array(array) => array
                .elems
                .iter()
                .flatten()
                .all(|element| element.spread.is_none() && self.is_pure(&element.expr)),
            _ => false,
        }
    }

    /// Matches an unused binding declaration, with or without an initializer, only when no
    /// remaining write needs the binding. Initializers must have no effects. Removing a
    /// declaration while keeping a write could turn that write into a global assignment.
    fn is_declaration(&self, declarator: &VarDeclarator) -> bool {
        let Some(name) = declarator.name.as_ident() else {
            return false;
        };
        let id = name.to_id();
        let removed = self.removed.get(&id).copied().unwrap_or(0);
        self.is_unused(&id)
            && self.bindings.write_count(&id) - removed == usize::from(declarator.init.is_some())
            && declarator
                .init
                .as_deref()
                .is_none_or(|value| self.is_pure(value))
    }
}

impl VisitMut for RemoveUnused<'_> {
    fn visit_mut_seq_expr(&mut self, sequence: &mut SeqExpr) {
        sequence.visit_mut_children_with(self);
        // The last operand supplies the sequence's value.
        if let Some(last) = sequence.exprs.pop() {
            self.changed |= removal::retain(&mut sequence.exprs, |operand| {
                !self.remove_definition(operand)
            });
            sequence.exprs.push(last);
        }
    }

    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        expression.visit_mut_children_with(self);
        if let Expr::Seq(sequence) = expression
            && sequence.exprs.len() == 1
        {
            *expression = *sequence.exprs.remove(0);
        }
        // Dropping `unused` preserves the value of `other = value`.
        if let Some((id, value)) = ast::assignment(expression)
            && value.is_assign()
            && self.is_unused(&id)
        {
            *self.removed.entry(id).or_default() += 1;
            *expression = *expression.take().expect_assign().right;
            self.changed = true;
        }
    }

    fn visit_mut_stmts(&mut self, statements: &mut Vec<Stmt>) {
        statements.visit_mut_children_with(self);
        // Remove unused definitions and statements with no side effects, including decoy arrays of
        // helpers. Keep strings that may be directives.
        self.changed |= removal::remove_expr_stmts(statements, |expression| {
            self.remove_definition(expression)
                || (!matches!(expression, Expr::Lit(Lit::Str(_))) && self.is_pure(expression))
        });
        for statement in statements.iter_mut() {
            if let Stmt::Decl(Decl::Var(declaration)) = statement {
                self.changed |= removal::retain(&mut declaration.decls, |declarator| {
                    !self.is_declaration(declarator)
                });
            }
        }
        removal::retain(statements, |statement| match statement {
            Stmt::Decl(Decl::Var(declaration)) => !declaration.decls.is_empty(),
            _ => true,
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn removes_unread_locals_but_keeps_globals_effects_and_mapped_parameters() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
        // Removing `all` leaves `add` unread, for the pipeline's next round.
        let output = transform(&transform(
            "function f(a, b) { var unused, add, all, kept = g(); \
             add = function(x) { var scratch; return x; }; all = [add, a]; return a + b; }",
        ));
        let expected = "function f(a, b) { var kept = g(); return a + b; }";
        testing::assert_contains(&output, &[], &[expected]);
        let output = transform(
            "global = function() {}; function f(a) { var v, w; v = g(); w = [missing]; \
             return arguments; } function h(p) { p = 1; return arguments; }",
        );
        let kept = ["global = function", "var v", "v = g()", "w = [", "p = 1"];
        testing::assert_contains(&output, &kept, &[]);
        let output = transform("function f(a) { 'use strict'; [a, function() {}]; a; g(a); }");
        testing::assert_contains(&output, &["'use strict';"], &["{ 'use strict'; g(a); }"]);
        let output = transform("function f() { var c, o; c = o = g(); h(c = o = 1); return o; }");
        testing::assert_contains(&output, &["var o;", "o = g();", "h(o = 1);"], &[]);
    }
}
