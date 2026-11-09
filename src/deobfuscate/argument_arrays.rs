//! Replaces reads from scratch argument arrays with their elements:
//!
//! ```js
//! function (a, b) { var f; f = [a, b]; return f[1] ^ f[0]; }  // return b ^ a
//! ```
//!
//! Requires a single array assignment and reads at constant indices only (see
//! [`Properties::only_indexed`]). Elements must be literals or bindings unchanged by assignments
//! or `arguments`. Excludes globals because repeated reads could throw or invoke getters.

use oxc::allocator::{CloneIn, GetAllocator};
use oxc::ast::ast::{ArrayExpressionElement, Expression, Program};
use oxc::ast_visit::{Visit, VisitMut, walk, walk_mut};
use oxc::span::GetSpanMut;

use super::analysis::properties::Properties;
use super::analysis::{Analysis, Id};
use super::{HashMap, ast, removal};

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let properties = Properties::collect(program, analysis);
    let mut packed = Packed {
        analysis,
        arrays: HashMap::default(),
    };
    packed.visit_program(program);
    let mut arrays = packed.arrays;
    arrays.retain(|&id, _| {
        analysis.bindings.is_written_once(&id) && properties.only_indexed(id, analysis)
    });
    if arrays.is_empty() {
        return false;
    }
    let mut unpack = Unpack {
        analysis,
        arrays: &arrays,
        changed: false,
    };
    unpack.visit_program(program);
    removal::remove_definitions(program, analysis, &arrays.keys().copied().collect())
        || unpack.changed
}

/// Collects the elements of arrays assigned to bindings.
struct Packed<'b, 'a> {
    analysis: &'b Analysis<'a>,
    arrays: HashMap<Id, Vec<Expression<'a>>>,
}

impl<'a> Packed<'_, 'a> {
    fn element(&self, element: &ArrayExpressionElement<'a>) -> Option<Expression<'a>> {
        let element = element.as_expression()?;
        let fixed = match element {
            Expression::Identifier(identifier) => self
                .analysis
                .id(identifier)
                .is_some_and(|id| self.analysis.bindings.is_never_written(&id)),
            element => element.is_literal(),
        };
        fixed.then(|| element.clone_in_with_semantic_ids(self.analysis.allocator()))
    }
}

impl<'a> Visit<'a> for Packed<'_, 'a> {
    fn visit_expression(&mut self, expression: &Expression<'a>) {
        if let Some((id, Expression::ArrayExpression(array))) = self.analysis.assignment(expression)
        {
            let elements = array.elements.iter().map(|element| self.element(element));
            if let Some(elements) = elements.collect() {
                self.arrays.insert(id, elements);
            }
        }
        walk::walk_expression(self, expression)
    }
}

struct Unpack<'b, 'a> {
    analysis: &'b Analysis<'a>,
    arrays: &'b HashMap<Id, Vec<Expression<'a>>>,
    changed: bool,
}

impl<'a> VisitMut<'a> for Unpack<'_, 'a> {
    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        walk_mut::walk_expression(self, expression);
        if let Expression::ComputedMemberExpression(member) = expression
            && let Some(id) = self.analysis.expression_id(&member.object)
            && let Some(array) = self.arrays.get(&id)
            && let Some(index) = ast::index(&member.expression)
        {
            let span = member.span;
            let mut value = match array.get(index) {
                Some(element) => element.clone_in_with_semantic_ids(self.analysis.allocator()),
                None => Expression::new_identifier(span, "undefined", &self.analysis.ast),
            };
            *value.span_mut() = span;
            *expression = value;
            self.changed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn unpacks_arrays_that_neither_change_nor_escape() {
        let unpack = |source: &str| testing::rewrite(source, super::run);
        let output = unpack(
            "g = function (a, b) { var f; f = [a, b, 3]; return f[1] ^ f[0] + f[2] + f[5]; };",
        );
        assert!(output.contains("return b ^ a + 3 + undefined;"), "{output}");
        assert!(!output.contains("f = ["), "{output}");
        for source in [
            "g = function (a) { var f; f = [a]; f[0] = 2; return f[0]; };",
            "g = function (a) { var f; f = [a]; a = 2; return f[0]; };",
            "g = function (a) { var f; f = [a]; f = [1]; return f[0]; };",
        ] {
            let output = unpack(source);
            assert!(output.contains("f = ["), "{output}");
        }
    }
}
