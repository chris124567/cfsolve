//! Replaces cached strings and arrays of switch labels with their values:
//!
//! ```js
//! var cache, order;
//! f(cache || (cache = "apply"));  // becomes f("apply")
//! f(option || cache || (cache = "apply"));  // becomes f(option || "apply")
//! steps = order || (order = "1|0".split("|"));  // becomes steps = "1|0".split("|")
//! ```
//!
//! The cache must be declared without an initializer and must not be a parameter. Every read and
//! write must use this pattern with the same value, except for resets to undefined. Replacing
//! these expressions leaves no reads of the cache.
//!
//! Splitting a string creates a new array on each evaluation instead of reusing one. This is
//! safe for the dispatchers that consume these arrays because they never modify them.

use oxc::allocator::{CloneIn, GetAllocator};
use oxc::ast::ast::{Expression, Program, VariableDeclarator};
use oxc::ast_visit::{Visit, VisitMut, walk, walk_mut};
use oxc::span::GetSpan;
use oxc::str::JSStr;
use oxc::syntax::operator::LogicalOperator;

use super::analysis::{Analysis, Id};
use super::{HashMap, HashSet, ast};

/// A cached string, or an array formed by splitting a constant string by a constant separator.
#[derive(PartialEq)]
struct Constant<'a> {
    string: JSStr<'a>,
    separator: Option<JSStr<'a>>,
}

impl<'a> Constant<'a> {
    fn of(value: &Expression<'a>) -> Option<Self> {
        let (string, separator) = match ast::method_call(value, "split") {
            Some((string, [separator])) => (
                string,
                Some(ast::static_string(separator.as_expression()?)?),
            ),
            _ => (value, None),
        };
        Some(Self {
            string: ast::static_string(string)?,
            separator,
        })
    }
}

/// A matched `[fallback ||] cache || (cache = value)`.
struct Memoized<'b, 'a> {
    id: Id,
    fallback: Option<&'b Expression<'a>>,
    value: &'b Expression<'a>,
    constant: Constant<'a>,
}

impl<'b, 'a> Memoized<'b, 'a> {
    /// Matches only when the read and the store name the same binding.
    fn of(expression: &'b Expression<'a>, analysis: &Analysis<'a>) -> Option<Self> {
        let Expression::LogicalExpression(logical) = expression.get_inner_expression() else {
            return None;
        };
        if logical.operator != LogicalOperator::Or {
            return None;
        }
        let (fallback, cache) = match logical.left.get_inner_expression() {
            Expression::Identifier(identifier) => (None, &**identifier),
            Expression::LogicalExpression(inner) if inner.operator == LogicalOperator::Or => {
                (Some(&inner.left), inner.right.get_identifier_reference()?)
            }
            _ => return None,
        };
        let id = analysis.id(cache)?;
        let (target, value) = analysis.assignment(&logical.right)?;
        if target != id {
            return None;
        }
        Some(Self {
            id,
            fallback,
            value,
            constant: Constant::of(value)?,
        })
    }
}

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let mut caches = Caches {
        analysis,
        values: HashMap::default(),
        resets: HashMap::default(),
        uninitialized: HashSet::default(),
    };
    caches.visit_program(program);
    let bindings = &analysis.bindings;
    let constant: HashSet<Id> = caches
        .values
        .iter()
        .filter(|(id, values)| {
            let resets = caches.resets.get(id).copied().unwrap_or(0);
            values.iter().all(|value| *value == values[0])
                && bindings.write_count(id) == values.len() + resets
                && bindings.references(id) == values.len()
                && caches.uninitialized.contains(id)
                && !bindings.is_parameter(id)
        })
        .map(|(&id, _)| id)
        .collect();
    let mut inline = Inline {
        analysis,
        constant: &constant,
        changed: false,
    };
    inline.visit_program(program);
    inline.changed
}

struct Caches<'b, 'a> {
    analysis: &'b Analysis<'a>,
    /// The constant stored by each memoized read of a binding.
    values: HashMap<Id, Vec<Constant<'a>>>,
    /// Counts assignments of `void` expressions or `undefined`.
    resets: HashMap<Id, usize>,
    uninitialized: HashSet<Id>,
}

impl<'a> Visit<'a> for Caches<'_, 'a> {
    fn visit_expression(&mut self, expression: &Expression<'a>) {
        if let Some((id, value)) = self.analysis.assignment(expression)
            && (value.get_inner_expression().is_void()
                || value
                    .get_identifier_reference()
                    .is_some_and(|undefined| self.analysis.is_global(undefined, "undefined")))
        {
            *self.resets.entry(id).or_default() += 1
        }
        if let Some(memoized) = Memoized::of(expression, self.analysis) {
            self.values
                .entry(memoized.id)
                .or_default()
                .push(memoized.constant)
        }
        walk::walk_expression(self, expression)
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        if declarator.init.is_none()
            && let Some(id) = ast::pattern_id(&declarator.id)
        {
            self.uninitialized.insert(id);
        }
        walk::walk_variable_declarator(self, declarator)
    }
}

struct Inline<'b, 'a> {
    analysis: &'b Analysis<'a>,
    constant: &'b HashSet<Id>,
    changed: bool,
}

impl<'a> VisitMut<'a> for Inline<'_, 'a> {
    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        walk_mut::walk_expression(self, expression);
        if let Some(memoized) = Memoized::of(expression, self.analysis)
            && self.constant.contains(&memoized.id)
        {
            let allocator = self.analysis.allocator();
            *expression = match memoized.fallback {
                Some(fallback) => Expression::new_logical_expression(
                    fallback.span(),
                    fallback.clone_in_with_semantic_ids(allocator),
                    LogicalOperator::Or,
                    memoized.value.clone_in_with_semantic_ids(allocator),
                    &self.analysis.ast,
                ),
                None => memoized.value.clone_in_with_semantic_ids(allocator),
            };
            self.changed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn inlines_values_only_their_caches_hold() {
        let output = testing::rewrite(
            "(function(p) {
                var a, b, c, d, e = 'x', o, p;
                o = void 0; o = undefined;
                f(a || (a = 'apply'), x || a || (a = 'apply'), o || (o = '1|0'.split('|')));
                f(b || (b = 'one'), b || (b = 'two'));
                f(c || (c = 'read'), c);
                f(d || (d = 'written'));
                d = other;
                f(e || (e = 'initialized'));
                f(p || (p = 'parameter'), ((q) => q || (q = 'arrow'))());
                f(g || (g = 'global'));
            })();",
            super::run,
        );
        testing::assert_contains(
            &output,
            &[
                "f('apply', x || 'apply', '1|0'.split('|'));",
                "b || (b = 'one'), b || (b = 'two')",
                "c || (c = 'read'), c",
                "d || (d = 'written')",
                "e || (e = 'initialized')",
                "p || (p = 'parameter')",
                "q || (q = 'arrow')",
                "g || (g = 'global')",
            ],
        );
    }
}
