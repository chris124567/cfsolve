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

use oxc::allocator::{CloneIn, GetAllocator, Vec};
use oxc::ast::ast::{
    ArrowFunctionExpression, Expression, Function, FunctionType, Program, Statement,
    VariableDeclaration, VariableDeclarationKind,
};
use oxc::ast_visit::{Visit, VisitMut, walk, walk_mut};
use oxc::syntax::scope::ScopeFlags;

use super::analysis::Analysis;
use super::ast;

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let mut dead = Dead {
        analysis,
        changed: false,
    };
    dead.visit_program(program);
    dead.changed
}

struct Dead<'b, 'a> {
    analysis: &'b Analysis<'a>,
    changed: bool,
}

impl<'a> VisitMut<'a> for Dead<'_, 'a> {
    fn visit_statement(&mut self, statement: &mut Statement<'a>) {
        walk_mut::walk_statement(self, statement);
        if let Statement::IfStatement(branch) = statement
            && let Some(test) = ast::truthiness(&branch.test)
        {
            let (taken, dropped) = if test {
                (Some(&branch.consequent), branch.alternate.as_ref())
            } else {
                (branch.alternate.as_ref(), Some(&branch.consequent))
            };
            if dropped.is_none_or(|dropped| !declares(dropped)) {
                *statement = match taken {
                    Some(taken) => taken.clone_in_with_semantic_ids(self.analysis.allocator()),
                    None => Statement::new_empty_statement(branch.span, &self.analysis.ast),
                };
                self.changed = true;
            }
        }
    }

    fn visit_statements(&mut self, statements: &mut Vec<'a, Statement<'a>>) {
        walk_mut::walk_statements(self, statements);
        let before = statements.len();
        statements.retain(|statement| match statement {
            Statement::EmptyStatement(_) => false,
            Statement::ExpressionStatement(statement) => match &statement.expression {
                Expression::BooleanLiteral(_)
                | Expression::NumericLiteral(_)
                | Expression::NullLiteral(_) => false,
                Expression::Identifier(identifier) => {
                    !self.analysis.is_global(identifier, "undefined")
                }
                _ => true,
            },
            _ => true,
        });
        self.changed |= statements.len() != before;
    }
}

/// Checks for `var` or function declarations that would hoist out of the statement.
fn declares(statement: &Statement<'_>) -> bool {
    struct Declares(bool);

    impl<'a> Visit<'a> for Declares {
        fn visit_variable_declaration(&mut self, declaration: &VariableDeclaration<'a>) {
            self.0 |= declaration.kind == VariableDeclarationKind::Var;
            walk::walk_variable_declaration(self, declaration)
        }

        fn visit_function(&mut self, function: &Function<'a>, _: ScopeFlags) {
            self.0 |= function.r#type == FunctionType::FunctionDeclaration
        }

        fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {}
    }

    let mut declares = Declares(false);
    declares.visit_statement(statement);
    declares.0
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn removes_dead_code_but_not_hoisted_declarations() {
        let transform = |source: &str| testing::rewrite(source, super::run);
        let output = transform(
            "function f() { if (false) { undefined; } true; 0; if (true) a(); else b(); if (false) c(); else { d(); } return g(); }",
        );
        testing::assert_lacks(&output, &["undefined", "true", "b()", "c()"]);
        testing::assert_contains(&output, &["a();", "d();"]);
        let output = transform(
            "function f() { if (false) { var x; } if (false) { function g() {} } return x; }",
        );
        testing::assert_contains(&output, &["var x", "function g"]);
    }
}
