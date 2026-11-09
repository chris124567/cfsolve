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

use oxc::allocator::{CloneIn, GetAllocator, Vec};
use oxc::ast::ast::{Expression, Program, SequenceExpression, Statement, VariableDeclarator};
use oxc::ast_visit::{VisitMut, walk_mut};
use oxc_ecmascript::side_effects::MayHaveSideEffects;

use super::analysis::{Analysis, Id};
use super::{HashMap, ast};

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let mut remove = Remove {
        analysis,
        removed: HashMap::default(),
        changed: false,
    };
    remove.visit_program(program);
    remove.changed
}

struct Remove<'b, 'a> {
    analysis: &'b Analysis<'a>,
    removed: HashMap<Id, usize>,
    changed: bool,
}

impl<'a> Remove<'_, 'a> {
    fn is_unused(&self, id: Id) -> bool {
        !id.is_global()
            && self.analysis.bindings.references(&id) == 0
            && !self.analysis.bindings.is_mapped_parameter(&id)
    }

    fn is_pure(&self, expression: &Expression<'a>) -> bool {
        !matches!(expression, Expression::ObjectExpression(_))
            && !expression.may_have_side_effects(self.analysis)
    }

    /// Checks for a removable definition of an unused binding, and counts it as removed.
    fn remove_definition(&mut self, expression: &Expression<'a>) -> bool {
        let Some((id, value)) = self.analysis.assignment(expression) else {
            return false;
        };
        let removable = self.is_unused(id) && self.is_pure(value);
        if removable {
            *self.removed.entry(id).or_default() += 1;
        }
        removable
    }

    fn is_dead_statement(&mut self, statement: &Statement<'a>) -> bool {
        let Statement::ExpressionStatement(statement) = statement else {
            return false;
        };
        let expression = &statement.expression;
        self.remove_definition(expression)
            || (!matches!(expression, Expression::StringLiteral(_)) && self.is_pure(expression))
    }

    /// Checks that every write to an unused declared binding has been removed except its
    /// initializer, which must be pure.
    fn is_dead_declarator(&self, declarator: &VariableDeclarator<'a>) -> bool {
        let Some(id) = ast::pattern_id(&declarator.id) else {
            return false;
        };
        let removed = self.removed.get(&id).copied().unwrap_or(0);
        let writes = self
            .analysis
            .bindings
            .write_count(&id)
            .saturating_sub(removed);
        let init = declarator.init.as_ref();
        self.is_unused(id)
            && writes == usize::from(init.is_some())
            && init.is_none_or(|value| self.is_pure(value))
    }
}

impl<'a> VisitMut<'a> for Remove<'_, 'a> {
    fn visit_sequence_expression(&mut self, sequence: &mut SequenceExpression<'a>) {
        walk_mut::walk_sequence_expression(self, sequence);
        if let Some(last) = sequence.expressions.pop() {
            let before = sequence.expressions.len();
            sequence
                .expressions
                .retain(|expression| !self.remove_definition(expression));
            self.changed |= sequence.expressions.len() != before;
            sequence.expressions.push(last)
        }
    }

    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        walk_mut::walk_expression(self, expression);
        let allocator = self.analysis.allocator();
        if let Some((id, value)) = self.analysis.assignment(expression)
            && matches!(value, Expression::AssignmentExpression(_))
            && self.is_unused(id)
        {
            *self.removed.entry(id).or_default() += 1;
            *expression = value.clone_in_with_semantic_ids(allocator);
            self.changed = true
        } else if let Expression::SequenceExpression(sequence) = expression
            && let [only] = sequence.expressions.as_slice()
        {
            *expression = only.clone_in_with_semantic_ids(allocator);
            self.changed = true;
        }
    }

    fn visit_statements(&mut self, statements: &mut Vec<'a, Statement<'a>>) {
        walk_mut::walk_statements(self, statements);
        let before = statements.len();
        statements.retain(|statement| !self.is_dead_statement(statement));
        statements.retain_mut(|statement| {
            let Statement::VariableDeclaration(declaration) = statement else {
                return true;
            };
            let declarations = &mut declaration.declarations;
            let count = declarations.len();
            declarations.retain(|declarator| !self.is_dead_declarator(declarator));
            self.changed |= declarations.len() != count;
            !declarations.is_empty()
        });
        self.changed |= statements.len() != before;
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn removes_unread_locals_but_keeps_globals_effects_and_mapped_parameters() {
        let transform = |source: &str| testing::rewrite(source, super::run);
        // Removing `all` leaves `add` unread, for the pipeline's next round.
        let output = transform(&transform(
            "function f(a, b) { var unused, add, all, kept = g(); \
             add = function(x) { var scratch; return x; }; all = [add, a]; return a + b; }",
        ));
        let expected = "function f(a, b) { var kept = g(); return a + b; }";
        testing::assert_contains(&output, &[expected]);
        let output = transform(
            "global = function() {}; function f(a) { var v, w; v = g(); w = [missing]; \
             return arguments; } function h(p) { p = 1; return arguments; }",
        );
        let kept = ["global = function", "var v", "v = g()", "w = [", "p = 1"];
        testing::assert_contains(&output, &kept);
        let output = transform("function f(a) { 'use strict'; [a, function() {}]; a; g(a); }");
        testing::assert_contains(&output, &["'use strict';", "{ 'use strict'; g(a); }"]);
        let output = transform("function f() { var c, o; c = o = g(); h(c = o = 1); return o; }");
        testing::assert_contains(&output, &["var o;", "o = g();", "h(o = 1);"]);
    }
}
