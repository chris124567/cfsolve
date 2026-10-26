//! Removes definitions after a rewrite has replaced all reads of their bindings.

use swc_core::ecma::ast::{Expr, Id, Program, SeqExpr, Stmt};
use swc_core::ecma::visit::{VisitMut, VisitMutWith};

use super::analysis::Bindings;
use super::{HashMap, HashSet};

/// Returns bindings whose reads have all been replaced, using replacement counts for each
/// binding.
#[must_use]
pub(super) fn unread(replaced: &HashMap<Id, usize>, bindings: &Bindings) -> HashSet<Id> {
    replaced
        .iter()
        .filter(|(id, replaced)| **replaced == bindings.references(id))
        .map(|(id, _)| id.clone())
        .collect()
}

/// Removes assignments to `unread` bindings when their values are discarded. Preserves the
/// final value of a sequence.
pub(super) fn remove_definitions(program: &mut Program, unread: &HashSet<Id>) -> bool {
    let mut remove = RemoveDefinitions {
        unread,
        changed: false,
    };
    if !unread.is_empty() {
        program.visit_mut_with(&mut remove);
    }
    remove.changed
}

struct RemoveDefinitions<'unread> {
    unread: &'unread HashSet<Id>,
    changed: bool,
}

impl RemoveDefinitions<'_> {
    fn is_definition(&self, expression: &Expr) -> bool {
        expression
            .as_assign()
            .and_then(|assignment| assignment.left.as_ident())
            .is_some_and(|identifier| self.unread.contains(&identifier.to_id()))
    }
}

impl VisitMut for RemoveDefinitions<'_> {
    fn visit_mut_seq_expr(&mut self, sequence: &mut SeqExpr) {
        sequence.visit_mut_children_with(self);
        // The last operand supplies the sequence's value.
        if let Some(last) = sequence.exprs.pop() {
            self.changed |= retain(&mut sequence.exprs, |expression| {
                !self.is_definition(expression)
            });
            sequence.exprs.push(last);
        }
    }

    fn visit_mut_stmts(&mut self, statements: &mut Vec<Stmt>) {
        statements.visit_mut_children_with(self);
        self.changed |= remove_expr_stmts(statements, |expression| self.is_definition(expression));
    }
}

/// Retains items accepted by `keep` and returns whether any were removed.
pub(super) fn retain<T>(items: &mut Vec<T>, keep: impl FnMut(&T) -> bool) -> bool {
    let count = items.len();
    items.retain(keep);
    items.len() != count
}

/// Removes expression statements accepted by `dead` and returns whether any were removed.
pub(super) fn remove_expr_stmts(
    statements: &mut Vec<Stmt>,
    mut dead: impl FnMut(&Expr) -> bool,
) -> bool {
    retain(statements, |statement| {
        statement
            .as_expr()
            .is_none_or(|statement| !dead(&statement.expr))
    })
}
