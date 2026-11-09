//! Flattens blocks used only to group statements:
//!
//! ```js
//! { a(); { b(); } }  // becomes a(); b();
//! ```
//!
//! Only flattens blocks directly inside a statement list and without scoped declarations. Keeps
//! blocks containing string statements created by [`super::statements`], since unwrapping them
//! could introduce directives.

use oxc::allocator::{TakeIn, Vec};
use oxc::ast::ast::{Expression, Program, Statement, VariableDeclarationKind};
use oxc::ast_visit::{VisitMut, walk_mut};

use super::analysis::Analysis;

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let mut flatten = Flatten {
        analysis,
        changed: false,
    };
    flatten.visit_program(program);
    flatten.changed
}

struct Flatten<'b, 'a> {
    analysis: &'b Analysis<'a>,
    changed: bool,
}

fn is_unscoped(statement: &Statement<'_>) -> bool {
    match statement {
        Statement::VariableDeclaration(declaration) => {
            declaration.kind == VariableDeclarationKind::Var
        }
        Statement::FunctionDeclaration(_) | Statement::ClassDeclaration(_) => false,
        Statement::ExpressionStatement(statement) => {
            !matches!(statement.expression, Expression::StringLiteral(_))
        }
        _ => true,
    }
}

impl<'a> VisitMut<'a> for Flatten<'_, 'a> {
    fn visit_statements(&mut self, statements: &mut Vec<'a, Statement<'a>>) {
        walk_mut::walk_statements(self, statements);
        let builder = &self.analysis.ast;
        let mut flattened = Vec::with_capacity_in(statements.len(), builder);
        for statement in statements.take_in(builder) {
            match statement {
                Statement::BlockStatement(block) if block.body.iter().all(is_unscoped) => {
                    flattened.extend(block.unbox().body);
                    self.changed = true
                }
                statement => flattened.push(statement),
            }
        }
        *statements = flattened;
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn flattens_only_grouping_blocks_in_statement_lists() {
        let transform = |source: &str| testing::rewrite(source, super::run);
        let output = transform("function f() { { a(); { b(); } } var c; { var d = 1; } }");
        testing::assert_contains(&output, &["var d = 1;", "a(); b();"]);
        assert_eq!(output.matches('{').count(), 1, "{output}");
        let output =
            transform("function f() { { let a = 1; use(a); } if (a) { b(); } while (c) { d(); } }");
        testing::assert_contains(&output, &["if (a) {", "while(c){", "{ let a = 1;"]);
    }
}
