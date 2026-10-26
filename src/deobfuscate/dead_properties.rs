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

use swc_core::atoms::Atom;
use swc_core::ecma::ast::{
    AssignExpr, AssignOp, AssignTarget, Expr, Id, Program, PropOrSpread, SeqExpr,
    SimpleAssignTarget, Stmt,
};
use swc_core::ecma::visit::{Visit, VisitMut, VisitMutWith, VisitWith};

use super::analysis::{self, Analysis, Bindings, Properties};
use super::{HashSet, removal};
use crate::js::ast;

pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    let (bindings, properties) = analysis.properties(program);
    let mut remove = RemoveDeadProperties {
        bindings,
        properties,
        literals: HashSet::default(),
        member_definitions: HashSet::default(),
        poisoned: HashSet::default(),
        changed: false,
    };
    program.visit_with(&mut remove);
    program.visit_mut_with(&mut remove);
    remove.changed
}

struct RemoveDeadProperties<'analysis> {
    bindings: &'analysis Bindings,
    properties: &'analysis Properties,
    /// Bindings defined by `binding = { ... }`.
    literals: HashSet<Id>,
    /// The binding and property of each `binding.property = <Fn|Lit>`.
    member_definitions: HashSet<(Id, Atom)>,
    /// Roots of bindings with definitions that cannot be removed: unsupported property values
    /// or assignments outside removable positions.
    poisoned: HashSet<Id>,
    changed: bool,
}

impl VisitMut for RemoveDeadProperties<'_> {
    fn visit_mut_assign_expr(&mut self, assignment: &mut AssignExpr) {
        assignment.visit_mut_children_with(self);

        if let Expr::Object(object) = &mut *assignment.right
            && let Some(identifier) = assignment.left.as_ident()
            && self.is_dead_root(&identifier.to_id())
        {
            let root = identifier.to_id();
            self.changed |= removal::retain(&mut object.props, |property| {
                removable_key(property).is_none_or(|key| self.is_live(&root, &key))
            });
        }
    }

    /// Removes statements that are one dead assignment or a sequence of only dead assignments.
    fn visit_mut_stmts(&mut self, statements: &mut Vec<Stmt>) {
        statements.visit_mut_children_with(self);
        self.changed |= removal::remove_expr_stmts(statements, |expression| match expression {
            Expr::Seq(sequence) => sequence.exprs.iter().all(|item| self.is_dead_operand(item)),
            expression => self.is_dead_operand(expression),
        });
    }

    fn visit_mut_seq_expr(&mut self, sequence: &mut SeqExpr) {
        sequence.visit_mut_children_with(self);
        // The final sequence operand supplies its value. A later round removes the whole
        // sequence if every operand is a dead assignment.
        if sequence.exprs.len() > 1
            && sequence
                .exprs
                .iter()
                .any(|expression| !self.is_dead_operand(expression))
        {
            self.changed |= removal::retain(&mut sequence.exprs, |expression| {
                !self.is_dead_operand(expression)
            });
        }
    }
}

impl RemoveDeadProperties<'_> {
    /// Checks whether an object can be removed after its unread properties. Requires one
    /// literal assignment and definitions in removable positions. Aliases must be used only for
    /// static property access and must not expose the object as `this`.
    fn is_dead_root(&self, identifier: &Id) -> bool {
        let root = self.bindings.root(identifier);
        self.bindings.is_written_once(&root)
            && self.literals.contains(&root)
            && !self.poisoned.contains(&root)
            && !self.properties.is_opaque(&root)
    }

    /// Whether `property` is read through `root` or one of its aliases.
    fn is_live(&self, root: &Id, property: &Atom) -> bool {
        self.properties.object(root).accessed.contains(property)
    }

    fn is_dead_operand(&self, expression: &Expr) -> bool {
        let Expr::Assign(assignment) = expression else {
            return false;
        };
        if assignment.op != AssignOp::Assign {
            return false;
        }
        if let Some(identifier) = assignment.left.as_ident() {
            let identifier = identifier.to_id();
            let uses = self.properties.binding(&identifier);
            return match assignment.right.unwrap_parens() {
                // Remove unused `alias = object` assignments only when no other alias depends
                // on them. Repeated rounds collapse chains. Property writes keep an alias until
                // those writes are removed.
                Expr::Ident(object) => {
                    self.bindings.copy_source(&identifier) == Some(&object.to_id())
                        && !uses.is_used_dynamically()
                        && uses.accessed.is_empty()
                        && !uses.written_through
                        && !self.bindings.is_copied(&identifier)
                }
                // `root = {}` once every property is gone and nothing reads it.
                Expr::Object(object) => {
                    object.props.is_empty()
                        && self.is_dead_root(&identifier)
                        && self.properties.object(&identifier).accessed.is_empty()
                }
                _ => false,
            };
        }
        if let AssignTarget::Simple(SimpleAssignTarget::Member(member)) = &assignment.left
            && let Some(identifier) = member.obj.as_ident()
            && let Some(property) = analysis::member_key(&member.prop)
            && matches!(&*assignment.right, Expr::Fn(_) | Expr::Lit(_))
            && self
                .member_definitions
                .contains(&(identifier.to_id(), property.clone()))
        {
            let root = self.bindings.root(&identifier.to_id());
            return self.is_dead_root(&root) && !self.is_live(&root, &property);
        }
        false
    }

    /// Records the definition `expression` makes, if any.
    fn define(&mut self, expression: &Expr, position: Position) {
        expression.visit_children_with(self);
        let Expr::Assign(assignment) = expression else {
            return;
        };
        if assignment.op != AssignOp::Assign {
            return;
        }
        if let Some(identifier) = assignment.left.as_ident()
            && let Expr::Object(object) = assignment.right.unwrap_parens()
        {
            let identifier = identifier.to_id();
            if object
                .props
                .iter()
                .any(|property| removable_key(property).is_none())
            {
                self.poisoned.insert(self.bindings.root(&identifier));
            }
            self.literals.insert(identifier);
        } else if let AssignTarget::Simple(SimpleAssignTarget::Member(member)) = &assignment.left
            && let Some(identifier) = member.obj.as_ident()
        {
            let identifier = identifier.to_id();
            match analysis::member_key(&member.prop) {
                Some(property) if matches!(&*assignment.right, Expr::Fn(_) | Expr::Lit(_)) => {
                    // Keep the object while this property definition remains.
                    if position == Position::Fixed {
                        self.poisoned.insert(self.bindings.root(&identifier));
                    }
                    self.member_definitions.insert((identifier, property));
                }
                _ => {
                    self.poisoned.insert(self.bindings.root(&identifier));
                }
            }
        }
    }
}

/// Collects definitions and whether their positions allow removal.
impl Visit for RemoveDeadProperties<'_> {
    fn visit_stmts(&mut self, statements: &[Stmt]) {
        for statement in statements {
            // Remove entire statements containing only dead assignments.
            match statement {
                Stmt::Expr(statement) => match &*statement.expr {
                    Expr::Seq(sequence) => {
                        for operand in &sequence.exprs {
                            self.define(operand, Position::Removable);
                        }
                    }
                    expression => self.define(expression, Position::Removable),
                },
                statement => statement.visit_with(self),
            }
        }
    }

    fn visit_seq_expr(&mut self, sequence: &SeqExpr) {
        // Remove dead sequence operands only if a retained operand remains.
        let keeps_live = sequence.exprs.iter().any(|operand| !may_be_dead(operand));
        let position = if keeps_live {
            Position::Removable
        } else {
            Position::Fixed
        };
        for operand in &sequence.exprs {
            self.define(operand, position);
        }
    }

    fn visit_expr(&mut self, expression: &Expr) {
        self.define(expression, Position::Fixed);
    }
}

/// Whether a definition's position lets it be removed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Position {
    /// A standalone statement, or a sequence operand beside a retained operand.
    Removable,
    Fixed,
}

/// Recognizes assignments that may be removable: `alias = object`, `root = {}`, or
/// `object.property = <Fn|Lit>`.
fn may_be_dead(expression: &Expr) -> bool {
    let Expr::Assign(assignment) = expression else {
        return false;
    };
    let value = assignment.right.unwrap_parens();
    assignment.op == AssignOp::Assign
        && match &assignment.left {
            AssignTarget::Simple(SimpleAssignTarget::Ident(_)) => {
                value.is_ident()
                    || value
                        .as_object()
                        .is_some_and(|object| object.props.is_empty())
            }
            AssignTarget::Simple(SimpleAssignTarget::Member(_)) => {
                matches!(&*assignment.right, Expr::Fn(_) | Expr::Lit(_))
            }
            _ => false,
        }
}

/// Returns the static key of a removable function or literal property definition.
fn removable_key(property: &PropOrSpread) -> Option<Atom> {
    let property = ast::key_value(property)?;
    let removable = matches!(&*property.value, Expr::Fn(_) | Expr::Lit(_));
    analysis::prop_key(&property.key).filter(|_| removable)
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn removes_unread_properties_dead_aliases_and_dead_objects() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
        let output = transform(
            "function f(h) { h = { live: function(a) { return a + 1; }, \
             dead: function(a) { return a - 1; }, name: \"n\", gone: \"g\" }; \
             return [h.live(1), h.name]; }",
        );
        testing::assert_contains(&output, &["live", "\"n\""], &[]);
        testing::assert_lacks(&output, &["dead", "gone"]);
        let output = transform(
            "function f(c, G) { c = {}; c.keep = function(a) { return a; }; \
             c.drop = function(a) { return a; }; G = c; return c.keep(1); }",
        );
        testing::assert_contains(&output, &["c = {};", "c.keep = function"], &[]);
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
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
        for source in [
            "function f(c, k) { c = {}; c.a = function() {}; use(c[k]); return c.a(); }",
            "function f(c) { c = {}; c.a = function() {}; c.__proto__ = {}; return c.a(); }",
            "function f(c) { c = {}; c.a = function() {}; use(c); return c.a(); }",
            "function f(c, G) { c = {}; c.a = function() {}; G = c; use(G); return 1; }",
            "function f(c) { c = {}; c.a = effect(); return 1; }",
        ] {
            testing::assert_contains(&transform(source), &["c = {};", "c.a = "], &[]);
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
