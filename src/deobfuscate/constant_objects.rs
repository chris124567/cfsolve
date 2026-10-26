//! Replaces numeric properties used to obscure string-array indices:
//!
//! ```js
//! map = { a: 2192 }; decode(map.a);  // becomes decode(2192)
//! ```
//!
//! Requires one object assignment and stable literal properties (see
//! [`Properties::is_stable`]), and removes definitions once all reads are replaced. Hoisted
//! function bodies use only definitions available wherever they can be called (see
//! [`hoisting`]).

use swc_core::atoms::Atom;
use swc_core::ecma::ast::{
    AssignExpr, AssignOp, Expr, Function, Id, Ident, Lit, Number, Program, Stmt,
};
use swc_core::ecma::visit::{VisitMut, VisitMutWith};

use super::analysis::hoisting::{self, Hoisted, Hoisting};
use super::analysis::{self, Analysis, Bindings, Properties};
use super::{HashMap, removal};
use crate::js::ast;

pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    let (bindings, properties) = analysis.properties(program);
    let mut inline = InlineConstantObjects {
        bindings,
        properties,
        hoisting: Hoisting::default(),
        replaced: HashMap::default(),
        changed: false,
    };
    program.visit_mut_with(&mut inline);
    // Keep the object if a read precedes its definition or accesses a missing property.
    let unread = removal::unread(&inline.replaced, bindings);
    let removed = removal::remove_definitions(program, &unread);
    inline.changed || removed
}

struct InlineConstantObjects<'analysis> {
    bindings: &'analysis Bindings,
    properties: &'analysis Properties,
    /// Tracks objects and properties defined before the current node.
    hoisting: Hoisting<HashMap<Id, HashMap<Atom, Number>>>,
    /// How many reads of each object were replaced.
    replaced: HashMap<Id, usize>,
    changed: bool,
}

impl VisitMut for InlineConstantObjects<'_> {
    fn visit_mut_assign_expr(&mut self, assignment: &mut AssignExpr) {
        assignment.visit_mut_children_with(self);

        if assignment.op == AssignOp::Assign
            && let Some(identifier) = assignment.left.as_ident()
            && self.bindings.is_written_once(&identifier.to_id())
            && let Some(object) = assignment.right.as_object()
        {
            let values: Option<HashMap<Atom, Number>> = object
                .props
                .iter()
                .map(|property| {
                    let property = ast::key_value(property)?;
                    let value = property.value.as_lit()?.as_num()?;
                    Some((analysis::prop_key(&property.key)?, value.clone()))
                })
                .collect();
            if let Some(values) = values.filter(|values| !values.is_empty()) {
                self.replaced.insert(identifier.to_id(), 0);
                self.hoisting.facts.insert(identifier.to_id(), values);
            }
        }
    }

    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        expression.visit_mut_children_with(self);

        if let Expr::Member(member) = expression
            && let Some(identifier) = member.obj.as_ident()
            && let Some(values) = self.hoisting.facts.get(&identifier.to_id())
            && let Some(name) = analysis::member_key(&member.prop)
            && let Some(value) = values.get(&name)
            && self.properties.is_stable(&identifier.to_id(), &name)
        {
            *self.replaced.entry(identifier.to_id()).or_default() += 1;
            *expression = Expr::Lit(Lit::Num(value.clone()));
            self.changed = true;
        }
    }

    /// Visit function declarations last, using definitions available at every possible call.
    fn visit_mut_stmts(&mut self, statements: &mut Vec<Stmt>) {
        hoisting::visit_mut_stmts(self, statements, |inline, statement| {
            statement.visit_mut_with(inline);
        });
    }

    fn visit_mut_function(&mut self, function: &mut Function) {
        hoisting::visit_mut_function(self, function);
    }

    fn visit_mut_ident(&mut self, identifier: &mut Ident) {
        hoisting::reference(self, identifier);
    }
}

impl Hoisted for InlineConstantObjects<'_> {
    type Facts = HashMap<Id, HashMap<Atom, Number>>;

    fn hoisting(&mut self) -> &mut Hoisting<Self::Facts> {
        &mut self.hoisting
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn inlines_single_write_objects_and_removes_unread_ones() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
        let output = transform(
            "function f(m, out) { m = { A: 10, K: 20 }; out = [decode(m.A), decode(m.K)]; \
             return out; }",
        );
        testing::assert_contains(&output, &["decode(10)", "decode(20)"], &[]);
        testing::assert_lacks(&output, &["m = {", "m.A"]);
        let output = transform(
            "function f(m, n, g) { g = function () { return n.A; }; m = { A: 10 }; \
             n = { A: 1 }; return [m['A'], m.A, n.A, n.B, g()]; }",
        );
        testing::assert_contains(&output, &[], &["10, 10,"]);
        assert!(!output.contains("m = {"), "{output}");
        assert!(
            output.contains("n = {"),
            "`g` and `n.B` still read the object: {output}"
        );
        assert!(
            output.contains("return n.A;"),
            "`g` reads `n` before the traversal reaches its definition: {output}"
        );
        assert!(
            output.contains("n.B"),
            "`n.B` names a property the object does not have: {output}"
        );
    }

    #[test]
    fn preserves_reassigned_escaping_and_updated_objects() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
        let output = transform(
            "function f(m, out) { m = { A: 10, K: 20 }; out = [m.A, m.K]; m = 5; \
             out.push(m); m = { A: 1 }; out.push(m.A); return out; }",
        );
        testing::assert_contains(&output, &["m = {", "m = 5;", "out.push(m);", "m.A"], &[]);
        assert!(!output.contains("out.push(1)"), "{output}");
        for source in [
            "function f(m) { m = { A: 10 }; use(m); return m.A; }",
            "function f(m) { m = { A: 10 }; m.A = 3; return m.A; }",
        ] {
            testing::assert_contains(&transform(source), &["m = {", "m.A"], &[]);
        }
    }
}
