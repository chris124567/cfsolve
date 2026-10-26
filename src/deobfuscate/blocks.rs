//! Flattens blocks used only to group statements:
//!
//! ```js
//! { a(); { b(); } }  // becomes a(); b();
//! ```
//!
//! Only flattens blocks directly inside a statement list and without scoped declarations. Keeps
//! blocks containing string statements created by [`super::statements`], since unwrapping them
//! could introduce directives.

use std::mem;

use swc_core::ecma::ast::{BlockStmt, Decl, Expr, Lit, Program, Stmt, VarDeclKind};
use swc_core::ecma::visit::{VisitMut, VisitMutWith};

use super::analysis::Analysis;

pub(super) fn run(program: &mut Program, _: &mut Analysis) -> bool {
    let mut flatten = FlattenBlocks { changed: false };
    program.visit_mut_with(&mut flatten);
    flatten.changed
}

struct FlattenBlocks {
    changed: bool,
}

impl VisitMut for FlattenBlocks {
    fn visit_mut_stmts(&mut self, statements: &mut Vec<Stmt>) {
        statements.visit_mut_children_with(self);
        let mut flattened = Vec::with_capacity(statements.len());
        for statement in mem::take(statements) {
            match statement {
                Stmt::Block(block) if is_transparent(&block) => {
                    flattened.extend(block.stmts);
                    self.changed = true;
                }
                statement => flattened.push(statement),
            }
        }
        *statements = flattened;
    }
}

fn is_transparent(block: &BlockStmt) -> bool {
    block.stmts.iter().all(|statement| match statement {
        // Moving a function-scoped `var` out of this block preserves its scope.
        Stmt::Decl(Decl::Var(declaration)) => declaration.kind == VarDeclKind::Var,
        Stmt::Decl(_) => false,
        Stmt::Expr(statement) => !matches!(&*statement.expr, Expr::Lit(Lit::Str(_))),
        _ => true,
    })
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn flattens_only_grouping_blocks_in_statement_lists() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ false);
        let output = transform("function f() { { a(); { b(); } } var c; { var d = 1; } }");
        testing::assert_contains(&output, &["var d = 1;"], &["a(); b();"]);
        assert_eq!(output.matches('{').count(), 1, "{output}");
        let output =
            transform("function f() { { let a = 1; use(a); } if (a) { b(); } while (c) { d(); } }");
        testing::assert_contains(&output, &["if (a) {", "while(c){"], &["{ let a = 1;"]);
    }
}
