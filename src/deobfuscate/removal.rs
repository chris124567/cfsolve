//! Removes definitions after a rewrite has replaced all reads of their bindings.

use oxc::allocator::Vec;
use oxc::ast::ast::{Expression, Program, SequenceExpression, Statement, VariableDeclarator};
use oxc::ast_visit::{VisitMut, walk_mut};

use super::analysis::{Analysis, Id};
use super::{HashMap, HashSet, ast};

/// Returns the bindings whose replacement counts account for every value read.
pub(super) fn unread(replaced: &HashMap<Id, usize>, analysis: &Analysis<'_>) -> HashSet<Id> {
    replaced
        .iter()
        .filter(|&(id, &count)| count == analysis.bindings.references(id))
        .map(|(&id, _)| id)
        .collect()
}

/// Removes assignments to `unread` bindings where their values are discarded. The final operand
/// of a sequence supplies its value and is kept.
pub(super) fn remove_definitions<'a>(
    program: &mut Program<'a>,
    analysis: &Analysis<'a>,
    unread: &HashSet<Id>,
) -> bool {
    let mut remove = Remove {
        analysis,
        unread,
        changed: false,
    };
    remove.visit_program(program);
    remove.changed
}

struct Remove<'b, 'a> {
    analysis: &'b Analysis<'a>,
    unread: &'b HashSet<Id>,
    changed: bool,
}

impl Remove<'_, '_> {
    fn is_dead(&self, expression: &Expression<'_>) -> bool {
        let Expression::AssignmentExpression(assignment) = expression.get_inner_expression() else {
            return false;
        };
        let target = self.analysis.target_id(&assignment.left);
        target.is_some_and(|id| self.unread.contains(&id))
    }
}

impl<'a> VisitMut<'a> for Remove<'_, 'a> {
    fn visit_sequence_expression(&mut self, sequence: &mut SequenceExpression<'a>) {
        walk_mut::walk_sequence_expression(self, sequence);
        if let Some(last) = sequence.expressions.pop() {
            let before = sequence.expressions.len();
            sequence
                .expressions
                .retain(|expression| !self.is_dead(expression));
            self.changed |= sequence.expressions.len() != before;
            sequence.expressions.push(last)
        }
    }

    fn visit_statements(&mut self, statements: &mut Vec<'a, Statement<'a>>) {
        walk_mut::walk_statements(self, statements);
        let before = statements.len();
        statements.retain(|statement| match statement {
            Statement::ExpressionStatement(statement) => !self.is_dead(&statement.expression),
            _ => true,
        });
        self.changed |= statements.len() != before;
    }
}

/// Drops the initializers of `unread` bindings' declarations. Callers ensure the initializers
/// have no side effects.
pub(super) fn remove_initializers(program: &mut Program<'_>, unread: &HashSet<Id>) {
    struct Uninitialize<'b> {
        unread: &'b HashSet<Id>,
    }

    impl<'a> VisitMut<'a> for Uninitialize<'_> {
        fn visit_variable_declarator(&mut self, declarator: &mut VariableDeclarator<'a>) {
            if ast::pattern_id(&declarator.id).is_some_and(|id| self.unread.contains(&id)) {
                declarator.init = None;
            }
            walk_mut::walk_variable_declarator(self, declarator)
        }
    }

    Uninitialize { unread }.visit_program(program)
}

/// Removes the function declarations of `unread` bindings.
pub(super) fn remove_function_declarations(program: &mut Program<'_>, unread: &HashSet<Id>) {
    struct RemoveDeclarations<'b> {
        unread: &'b HashSet<Id>,
    }

    impl<'a> VisitMut<'a> for RemoveDeclarations<'_> {
        fn visit_statements(&mut self, statements: &mut Vec<'a, Statement<'a>>) {
            walk_mut::walk_statements(self, statements);
            statements.retain(|statement| match statement {
                Statement::FunctionDeclaration(function) => {
                    !ast::function_id(function).is_some_and(|id| self.unread.contains(&id))
                }
                _ => true,
            })
        }
    }

    RemoveDeclarations { unread }.visit_program(program)
}
