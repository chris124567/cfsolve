//! Removes unread helper-object properties:
//!
//! ```js
//! h = { keep: function (a) { return a; }, drop: function (a) { return a; } };
//! h.keep(1);  // the drop entry goes
//! ```
//!
//! After [`super::helper_objects`] inlines calls, unused properties and their object or alias
//! assignments may remain. Removal requires a single-assignment object used only through static
//! keys (see [`Properties`]), with no reads of the property through any alias.

use std::mem;

use oxc::allocator::Vec;
use oxc::ast::ast::{
    AssignmentExpression, Expression, ExpressionStatement, ObjectPropertyKind, Program,
    PropertyKind, SequenceExpression, Statement,
};
use oxc::ast_visit::{Visit, VisitMut, walk, walk_mut};
use oxc::syntax::operator::AssignmentOperator;

use super::analysis::properties::Properties;
use super::analysis::{Analysis, Id};
use super::{HashSet, ast};

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let properties = Properties::collect(program, analysis);
    let mut definitions = Definitions {
        analysis,
        roots: HashSet::default(),
        poisoned: HashSet::default(),
        discarded: false,
        conditional: 0,
    };
    definitions.visit_program(program);
    let mut remove = Remove {
        analysis,
        properties: &properties,
        roots: &definitions.roots,
        poisoned: &definitions.poisoned,
        changed: false,
    };
    remove.visit_program(program);
    remove.changed
}

/// Checks for property values whose definitions can be discarded without evaluating side effects.
fn removable(value: &Expression<'_>) -> bool {
    match value {
        Expression::FunctionExpression(_) => true,
        Expression::TemplateLiteral(template) => template.expressions.is_empty(),
        value => value.is_literal(),
    }
}

fn is_removable_property(property: &ObjectPropertyKind<'_>) -> bool {
    matches!(property, ObjectPropertyKind::ObjectProperty(property)
        if ast::key(&property.key, property.computed).is_some()
            && removable(&property.value)
            && property.kind == PropertyKind::Init
            && !property.method)
}

/// Finds the object roots assigned a literal, and poisons those with a definition whose value is
/// used, a conditional or unremovable definition, or an unremovable literal entry.
struct Definitions<'b, 'a> {
    analysis: &'b Analysis<'a>,
    roots: HashSet<Id>,
    poisoned: HashSet<Id>,
    /// Whether the value of the expression being visited is discarded.
    discarded: bool,
    /// The number of enclosing conditional or loop statements.
    conditional: usize,
}

impl<'a> Definitions<'_, 'a> {
    fn visit_with(&mut self, expression: &Expression<'a>, discarded: bool) {
        let outer = mem::replace(&mut self.discarded, discarded);
        self.visit_expression(expression);
        self.discarded = outer;
    }

    fn assignment(&mut self, assignment: &AssignmentExpression<'a>, discarded: bool) {
        let member = assignment.left.as_member_expression();
        let target = self.analysis.target_id(&assignment.left);
        let target = target.or_else(|| self.analysis.expression_id(member?.object()));
        let Some(root) = target.map(|id| self.analysis.bindings.root(&id)) else {
            return;
        };
        if !discarded || (member.is_some() && !removable(&assignment.right)) {
            self.poisoned.insert(root);
        }
        if let Expression::ObjectExpression(object) = &assignment.right {
            self.roots.insert(root);
            if !object.properties.iter().all(is_removable_property) {
                self.poisoned.insert(root);
            }
        }
    }
}

impl<'a> Visit<'a> for Definitions<'_, 'a> {
    fn visit_expression_statement(&mut self, statement: &ExpressionStatement<'a>) {
        self.visit_with(&statement.expression, self.conditional == 0)
    }

    fn visit_statement(&mut self, statement: &Statement<'a>) {
        let conditional = usize::from(
            statement.is_iteration_statement() || matches!(statement, Statement::IfStatement(_)),
        );
        self.conditional += conditional;
        walk::walk_statement(self, statement);
        self.conditional -= conditional;
    }

    fn visit_expression(&mut self, expression: &Expression<'a>) {
        let discarded = mem::replace(&mut self.discarded, false);
        match expression {
            Expression::SequenceExpression(sequence) => {
                let last = sequence.expressions.len().saturating_sub(1);
                for (index, operand) in sequence.expressions.iter().enumerate() {
                    self.visit_with(operand, index < last || discarded)
                }
            }
            Expression::AssignmentExpression(assignment)
                if assignment.operator == AssignmentOperator::Assign =>
            {
                self.assignment(assignment, discarded);
                walk::walk_expression(self, expression)
            }
            _ => walk::walk_expression(self, expression),
        }
        self.discarded = discarded;
    }
}

struct Remove<'b, 'a> {
    analysis: &'b Analysis<'a>,
    properties: &'b Properties<'a>,
    roots: &'b HashSet<Id>,
    poisoned: &'b HashSet<Id>,
    changed: bool,
}

impl<'a> Remove<'_, 'a> {
    /// Requires one literal assignment, removable definitions, and no opaque observations through
    /// any alias. Definitions in value-producing or conditional positions keep the object alive.
    fn eligible(&self, id: Id) -> bool {
        let id = self.analysis.bindings.root(&id);
        self.roots.contains(&id)
            && !self.poisoned.contains(&id)
            && self.analysis.bindings.is_written_once(&id)
            && self
                .properties
                .get(id, self.analysis)
                .is_some_and(|uses| uses.is_tracked())
    }

    /// Checks whether any alias reads, calls, or updates the static property.
    fn live(&self, id: Id, key: &str) -> bool {
        let uses = self.properties.get(id, self.analysis);
        uses.is_none_or(|uses| uses.read.contains(key))
    }

    /// Recognizes discarded definitions of dead properties, unused aliases, and empty helper
    /// objects. An object or alias remains while another binding copies it; repeated passes
    /// collapse chains.
    fn dead(&self, expression: &Expression<'a>) -> bool {
        let Expression::AssignmentExpression(assignment) = expression.get_inner_expression() else {
            return false;
        };
        if assignment.operator != AssignmentOperator::Assign {
            return false;
        }
        let bindings = &self.analysis.bindings;
        if let Some(id) = self.analysis.target_id(&assignment.left) {
            return self.eligible(id)
                && match &assignment.right {
                    Expression::ObjectExpression(object) => {
                        object.properties.is_empty()
                            && !bindings.is_copied(&id)
                            && self
                                .properties
                                .get(id, self.analysis)
                                .is_some_and(|uses| uses.read.is_empty())
                    }
                    Expression::Identifier(reference) => {
                        let source = self.analysis.id(reference);
                        source.is_some_and(|source| bindings.copy_source(&id) == Some(&source))
                            && bindings.references(&id) == 0
                    }
                    _ => false,
                };
        }
        if let Some(member) = assignment.left.as_member_expression()
            && let Some(id) = self.analysis.expression_id(member.object())
            && let Some(key) = member.static_property_name().and_then(|name| name.as_str())
        {
            return self.eligible(id) && !self.live(id, key) && removable(&assignment.right);
        }
        false
    }
}

impl<'a> VisitMut<'a> for Remove<'_, 'a> {
    fn visit_assignment_expression(&mut self, assignment: &mut AssignmentExpression<'a>) {
        walk_mut::walk_assignment_expression(self, assignment);
        if let Some(id) = self.analysis.target_id(&assignment.left)
            && self.eligible(id)
            && let Expression::ObjectExpression(object) = &mut assignment.right
        {
            let before = object.properties.len();
            object.properties.retain(|property| match property {
                ObjectPropertyKind::ObjectProperty(property) => {
                    let key = ast::key(&property.key, property.computed);
                    !(key.is_some_and(|key| !self.live(id, key)) && removable(&property.value))
                }
                ObjectPropertyKind::SpreadProperty(_) => true,
            });
            self.changed |= object.properties.len() != before;
        }
    }

    fn visit_statements(&mut self, statements: &mut Vec<'a, Statement<'a>>) {
        walk_mut::walk_statements(self, statements);
        let before = statements.len();
        statements.retain(|statement| match statement {
            Statement::ExpressionStatement(statement) => match &statement.expression {
                Expression::SequenceExpression(sequence) => !sequence
                    .expressions
                    .iter()
                    .all(|operand| self.dead(operand)),
                expression => !self.dead(expression),
            },
            _ => true,
        });
        self.changed |= statements.len() != before;
    }

    fn visit_sequence_expression(&mut self, sequence: &mut SequenceExpression<'a>) {
        walk_mut::walk_sequence_expression(self, sequence);
        let expressions = &mut sequence.expressions;
        if expressions.len() > 1 && expressions.iter().any(|operand| !self.dead(operand)) {
            let before = expressions.len();
            expressions.retain(|operand| !self.dead(operand));
            self.changed |= expressions.len() != before;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn removes_unread_properties_dead_aliases_and_dead_objects() {
        let transform = |source: &str| testing::rewrite(source, super::run);
        let output = transform(
            "function f(h) { h = { live: function(a) { return a + 1; }, \
             dead: function(a) { return a - 1; }, name: \"n\", gone: \"g\" }; \
             return [h.live(1), h.name]; }",
        );
        testing::assert_contains(&output, &["live", "\"n\""]);
        testing::assert_lacks(&output, &["dead", "gone"]);
        let output = transform(
            "function f(c, G) { c = {}; c.keep = function(a) { return a; }; \
             c.drop = function(a) { return a; }; G = c; return c.keep(1); }",
        );
        testing::assert_contains(&output, &["c = {};", "c.keep = function"]);
        testing::assert_lacks(&output, &["c.drop", "G = c"]);
        // One level of an alias chain collapses per pass.
        let output = transform(
            "function f(c, G, H) { c = {}; c.drop = function(a) { return a; }; \
             G = c; H = G; return 1; }",
        );
        testing::assert_lacks(&output, &["c.drop", "H = G"]);
        let output = transform(&output);
        assert!(!output.contains("G = c"), "{output}");
        let output = transform(&output);
        assert!(!output.contains("c = {};"), "{output}");
    }

    #[test]
    fn preserves_objects_that_escape_or_keep_a_definition() {
        let transform = |source: &str| testing::rewrite(source, super::run);
        for source in [
            "function f(c, k) { c = {}; c.a = function() {}; use(c[k]); return c.a(); }",
            "function f(c) { c = {}; c.a = function() {}; c.__proto__ = {}; return c.a(); }",
            "function f(c) { c = {}; c.a = function() {}; use(c); return c.a(); }",
            "function f(c, G) { c = {}; c.a = function() {}; G = c; use(G); return 1; }",
            "function f(c) { c = {}; c.a = effect(); return 1; }",
        ] {
            testing::assert_contains(&transform(source), &["c = {};", "c.a = "]);
        }
        for source in [
            "function f(c, x) { c = {}; c.a = function() {}; if (x) c.b = 1; return 1; }",
            "function f(c, G, k) { c = {}; c.a = function() {}; G = c; use(G[k]); return 1; }",
            "function f(c, x) { c = {}; c.a = function() {}; return x && (c.b = 1); }",
        ] {
            let output = transform(source);
            assert!(output.contains("c = {};"), "{output}");
        }
        // Properties that methods read through `this`.
        for (source, kept) in [
            (
                "function f(s) { s = { n: 0, inc: function () { this.n++; } }; s.inc(); }",
                "n: 0",
            ),
            (
                "function f(h) { h = { a: 1 }; return h.hasOwnProperty('a'); }",
                "a: 1",
            ),
        ] {
            let output = transform(source);
            assert!(output.contains(kept), "{output}");
        }
    }
}
