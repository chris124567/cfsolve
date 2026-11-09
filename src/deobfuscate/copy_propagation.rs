//! Replaces scratch copies with their assigned values:
//!
//! ```js
//! flag = true; listen(handler, flag);  // becomes listen(handler, true)
//! ```
//!
//! Requires exactly one assignment and proof that it ran before each replaced read. This
//! includes later statements in the same list and hoisted functions callable only after the
//! assignment (see [`hoisting`]). Removes assignments once no reads remain.

use std::rc::Rc;

use oxc::allocator::{CloneIn, GetAllocator, Vec};
use oxc::ast::ast::{
    AssignmentExpression, BlockStatement, Expression, Function, IdentifierReference,
    ObjectProperty, Program, Statement, VariableDeclarator,
};
use oxc::ast_visit::{VisitMut, walk_mut};
use oxc::syntax::operator::AssignmentOperator;
use oxc::syntax::scope::ScopeFlags;

use super::analysis::hoisting::{self, Hoisted, Hoisting};
use super::analysis::unconditional::Unconditional;
use super::analysis::{Analysis, Id};
use super::{HashMap, HashSet, ast, removal};

/// The value each single-write binding holds once its assignment has run, or `None` if that value
/// cannot be substituted. Arena nodes do not implement `Clone`, so snapshots share them by `Rc`.
type Values<'a> = Rc<HashMap<Id, Option<&'a Expression<'a>>>>;

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let mut propagate = Propagate {
        analysis,
        hoisting: Hoisting::default(),
        functions: HashSet::default(),
        replaced: HashMap::default(),
        changed: false,
    };
    propagate.visit_program(program);
    let unread = removal::unread(&propagate.replaced, analysis);
    removal::remove_definitions(program, analysis, &unread) || propagate.changed
}

struct Propagate<'b, 'a> {
    analysis: &'b Analysis<'a>,
    hoisting: Hoisting<Values<'a>>,
    /// Single-write function declarations, whose values are stable everywhere.
    functions: HashSet<Id>,
    replaced: HashMap<Id, usize>,
    changed: bool,
}

impl<'a> Hoisted<'a> for Propagate<'_, 'a> {
    type Facts = Values<'a>;

    fn analysis(&self) -> &Analysis<'a> {
        self.analysis
    }

    fn hoisting(&mut self) -> &mut Hoisting<Self::Facts> {
        &mut self.hoisting
    }
}

impl<'a> Propagate<'_, 'a> {
    /// Records a binding's only assigned value after that assignment has run. Only primitives,
    /// static templates, and references known to hold a stable value can be substituted; regular
    /// expressions keep identity and state.
    fn record(&mut self, id: Id, value: &Expression<'a>) {
        let bindings = &self.analysis.bindings;
        if !bindings.is_written_once(&id) || bindings.is_mapped_parameter(&id) {
            return;
        }
        let stable = match value.get_inner_expression() {
            Expression::Identifier(reference) => {
                self.analysis.id(reference).is_some_and(|source| {
                    self.functions.contains(&source)
                        || self.hoisting.facts.contains_key(&source)
                        || (bindings.is_parameter(&source) && bindings.is_never_written(&source))
                })
            }
            value => ast::is_constant(value),
        };
        let value = stable.then(|| self.analysis.save(value));
        if stable {
            self.replaced.entry(id).or_default();
        }
        Rc::make_mut(&mut self.hoisting.facts).insert(id, value);
    }
}

impl<'a> Unconditional<'a> for Propagate<'_, 'a> {
    fn assigned(&mut self, assignment: &AssignmentExpression<'a>) {
        if assignment.operator == AssignmentOperator::Assign
            && let Some(id) = self.analysis.target_id(&assignment.left)
        {
            self.record(id, &assignment.right)
        }
    }

    fn declared(&mut self, declarator: &VariableDeclarator<'a>) {
        if let Some(id) = ast::pattern_id(&declarator.id)
            && let Some(value) = &declarator.init
        {
            self.record(id, value)
        }
    }
}

impl<'a> VisitMut<'a> for Propagate<'_, 'a> {
    fn visit_object_property(&mut self, property: &mut ObjectProperty<'a>) {
        if !property.shorthand {
            walk_mut::walk_object_property(self, property)
        } else if let Expression::Identifier(reference) = &property.value {
            hoisting::reference(self, reference)
        }
    }

    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        walk_mut::walk_expression(self, expression);
        if let Some(id) = self.analysis.expression_id(expression)
            && let Some(Some(value)) = self.hoisting.facts.get(&id)
        {
            *self.replaced.entry(id).or_default() += 1;
            *expression = value.clone_in_with_semantic_ids(self.analysis.allocator());
            self.changed = true;
        }
    }

    fn visit_statements(&mut self, statements: &mut Vec<'a, Statement<'a>>) {
        let outer = self.hoisting.facts.clone();
        for statement in statements.iter() {
            if let Statement::FunctionDeclaration(function) = statement
                && let Some(id) = ast::function_id(function)
                && self.analysis.bindings.is_written_once(&id)
            {
                self.functions.insert(id);
            }
        }
        hoisting::statements(self, statements, Self::unconditional_statement);
        self.hoisting.facts = outer;
    }

    fn visit_function(&mut self, function: &mut Function<'a>, _: ScopeFlags) {
        hoisting::function(self, function)
    }

    fn visit_block_statement(&mut self, block: &mut BlockStatement<'a>) {
        hoisting::block(self, block)
    }

    fn visit_identifier_reference(&mut self, reference: &mut IdentifierReference<'a>) {
        hoisting::reference(self, reference)
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn substitutes_copies_assigned_before_every_read() {
        let transform = |source: &str| testing::rewrite(source, super::run);
        let output = transform("function f(a, b, c) { a = {}; b = a; c = true; b.x = c; use(b); }");
        testing::assert_contains(&output, &["a.x = true;", "use(a);"]);
        testing::assert_lacks(&output, &["b = a", "c = true"]);
        // Declarations, and values assigned alongside others.
        let output = transform(
            "function f(a, b, c) { c = (a = 1, b = g, function () { return a; }); \
             return b(c); function g() {} }",
        );
        testing::assert_contains(&output, &["return g(c);", "c = (function() { return 1;"]);
        // Values assigned where a condition always runs.
        let output = transform(
            "function f(a, b, c) { if ((a = `m`, c) && (b = 1, g())) { return; } x[a](b); }",
        );
        testing::assert_contains(&output, &["x[`m`](b);"]);
        testing::assert_lacks(&output, &["a = `m`"]);
        // A read before the write keeps the binding.
        let output = transform("function f(a) { use(a); a = 1; return a; }");
        testing::assert_contains(&output, &["return 1;", "use(a); a = 1;"]);
        // Parameters whose arguments are never overwritten.
        let output = transform("function f(p, q) { var a, b; a = p; b = q; q = 1; return a + b; }");
        testing::assert_contains(&output, &["return p + b;"]);
        let output = transform("function f(p) { var a; a = p; return a + arguments[0]; }");
        testing::assert_contains(&output, &["return a + arguments[0];"]);
    }

    #[test]
    fn preserves_reads_the_assignment_may_not_precede() {
        let transform = |source: &str| testing::rewrite(source, super::run);
        for (source, kept) in [
            (
                "function f(c, r) { if (c) { r = 1; } return r; }",
                "return r;",
            ),
            (
                "function f(c, r) { if (c && (r = 1)) { g(); } return r; }",
                "return r;",
            ),
            (
                "function f(a, b) { b = a; a = a.x; return b; }",
                "return b;",
            ),
            ("function f(a) { a = 1; return { a }; }", "a = 1;"),
            ("function f(a) { a = 1; a = 2; return a; }", "return a;"),
            (
                "function f(a, b) { b = a; a = 1; a = 2; return b; }",
                "return b;",
            ),
        ] {
            let output = transform(source);
            assert!(output.contains(kept), "{source}: {output}");
        }
    }
}
