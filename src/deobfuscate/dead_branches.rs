//! Removes unreachable or effect-free code:
//!
//! ```js
//! if (false) { undefined; }   // removed
//! if (true) a(); else b();    // a();
//! true;                       // removed
//! ```
//!
//! Preserves branches containing declarations because `var` and function declarations may be
//! hoisted into the enclosing scope.

use swc_core::ecma::ast::{
    ArrowExpr, Decl, EmptyStmt, Expr, Function, Lit, Program, Stmt, VarDecl, VarDeclKind,
};
use swc_core::ecma::visit::{Visit, VisitMut, VisitMutWith};

use super::analysis::Analysis;
use super::removal;

pub(super) fn run(program: &mut Program, _: &mut Analysis) -> bool {
    let mut remove = RemoveDeadBranches { changed: false };
    program.visit_mut_with(&mut remove);
    remove.changed
}

struct RemoveDeadBranches {
    changed: bool,
}

impl VisitMut for RemoveDeadBranches {
    fn visit_mut_stmts(&mut self, statements: &mut Vec<Stmt>) {
        statements.visit_mut_children_with(self);
        self.changed |= removal::retain(statements, |statement| !is_inert(statement));
    }

    fn visit_mut_stmt(&mut self, statement: &mut Stmt) {
        statement.visit_mut_children_with(self);
        if let Stmt::If(conditional) = statement
            && let Expr::Lit(Lit::Bool(test)) = &*conditional.test
        {
            let (taken, dropped) = if test.value {
                (Some(&*conditional.cons), conditional.alt.as_deref())
            } else {
                (conditional.alt.as_deref(), Some(&*conditional.cons))
            };
            if dropped.is_none_or(|dropped| !declares(dropped)) {
                *statement = taken.cloned().unwrap_or(Stmt::Empty(EmptyStmt {
                    span: conditional.span,
                }));
                self.changed = true;
            }
        }
    }
}

/// Checks whether a statement is empty or has no effects. Keeps string statements because they
/// may be directives.
fn is_inert(statement: &Stmt) -> bool {
    match statement {
        Stmt::Empty(_) => true,
        Stmt::Expr(statement) => match &*statement.expr {
            Expr::Lit(Lit::Bool(_) | Lit::Num(_) | Lit::Null(_)) => true,
            Expr::Ident(id) => id.sym == "undefined",
            _ => false,
        },
        _ => false,
    }
}

fn declares(statement: &Stmt) -> bool {
    use swc_core::ecma::visit::VisitWith;

    let mut declarations = Declarations(false);
    statement.visit_with(&mut declarations);
    declarations.0
}

/// Checks whether a statement contains declarations hoisted into its enclosing scope.
struct Declarations(bool);

impl Visit for Declarations {
    fn visit_decl(&mut self, declaration: &Decl) {
        match declaration {
            Decl::Fn(_) => self.0 = true,
            Decl::Var(variables) => self.visit_var_decl(variables),
            _ => {}
        }
    }

    fn visit_var_decl(&mut self, declaration: &VarDecl) {
        self.0 |= declaration.kind == VarDeclKind::Var;
    }

    // Nested function declarations stay within their own function scope.
    fn visit_function(&mut self, _: &Function) {}
    fn visit_arrow_expr(&mut self, _: &ArrowExpr) {}
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn removes_dead_code_but_not_hoisted_declarations() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ false);
        let output = transform(
            "function f() { if (false) { undefined; } true; 0; if (true) a(); else b(); if (false) c(); else { d(); } return g(); }",
        );
        testing::assert_lacks(&output, &["undefined", "true", "b()", "c()"]);
        testing::assert_contains(&output, &["a();", "d();"], &[]);
        let output = transform(
            "function f() { if (false) { var x; } if (false) { function g() {} } return x; }",
        );
        testing::assert_contains(&output, &["var x", "function g"], &[]);
    }
}
