//! Replaces cached strings and arrays of switch labels with their values:
//!
//! ```js
//! var cache, order;
//! f(cache || (cache = "apply"));  // becomes f("apply")
//! f(option || cache || (cache = "apply"));  // becomes f(option || "apply")
//! steps = order || (order = "1|0".split("|"));  // becomes steps = "1|0".split("|")
//! ```
//!
//! The cache must be an uninitialized `var`, not a parameter. Every read and write must use
//! this pattern with the same value, except for resets to undefined. Replacing these
//! expressions leaves no reads of the cache.
//!
//! Splitting a string creates a new array on each evaluation instead of reusing one. This is
//! safe for the dispatchers that consume these arrays because they never modify them.

use swc_core::atoms::Wtf8Atom;
use swc_core::ecma::ast::{
    BinExpr, BinaryOp, Expr, ExprOrSpread, Id, Ident, Program, UnaryOp, VarDeclarator,
};
use swc_core::ecma::visit::{Visit, VisitMut, VisitMutWith, VisitWith};

use super::analysis::{Analysis, Globals};
use super::{HashMap, HashSet};
use crate::js::ast;

pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    let mut caches = Caches {
        globals: analysis.globals,
        memoized: HashMap::default(),
        resets: HashMap::default(),
        uninitialized: HashSet::default(),
    };
    let bindings = analysis.bindings(program);
    program.visit_with(&mut caches);
    let constant: HashSet<Id> = caches
        .memoized
        .into_iter()
        .filter(|(id, constants)| {
            let count = constants.len();
            let resets = caches.resets.get(id).copied().unwrap_or(0);
            constants.iter().all(|constant| *constant == constants[0])
                && bindings.write_count(id) == count + resets
                && bindings.references(id) == count
                && caches.uninitialized.contains(id)
                && !bindings.is_parameter(id)
        })
        .map(|(id, _)| id)
        .collect();
    if constant.is_empty() {
        return false;
    }
    program.visit_mut_with(&mut Inline(&constant));
    true
}

/// A cached string or an array created by splitting a string.
#[derive(PartialEq)]
struct Constant {
    string: Wtf8Atom,
    separator: Option<Wtf8Atom>,
}

impl Constant {
    fn of(value: &Expr) -> Option<Self> {
        if let Some(string) = ast::static_wtf8(value) {
            return Some(Self {
                string: string.clone(),
                separator: None,
            });
        }
        let (
            string,
            [
                ExprOrSpread {
                    spread: None,
                    expr: separator,
                },
            ],
        ) = ast::method_call(value, "split")?
        else {
            return None;
        };
        Some(Self {
            string: ast::static_wtf8(string)?.clone(),
            separator: Some(ast::static_wtf8(separator)?.clone()),
        })
    }
}

/// Matches `[fallback ||] cache || (cache = value)`.
struct Memoized<'a> {
    fallback: Option<&'a Expr>,
    cache: &'a Ident,
    value: &'a Expr,
    constant: Constant,
}

impl<'a> Memoized<'a> {
    fn of(expression: &'a Expr) -> Option<Self> {
        let either = expression
            .as_bin()
            .filter(|either| either.op == BinaryOp::LogicalOr)?;
        let (fallback, cache) = match either.left.unwrap_parens() {
            Expr::Ident(cache) => (None, cache),
            Expr::Bin(BinExpr {
                op: BinaryOp::LogicalOr,
                left,
                right,
                ..
            }) => (Some(&**left), right.unwrap_parens().as_ident()?),
            _ => return None,
        };
        let (target, value) = ast::assignment(either.right.unwrap_parens())?;
        if target != cache.to_id() {
            return None;
        }
        Some(Self {
            fallback,
            cache,
            value,
            constant: Constant::of(value)?,
        })
    }
}

struct Caches {
    globals: Globals,
    /// Cached value for each matched expression.
    memoized: HashMap<Id, Vec<Constant>>,
    /// Number of resets to undefined for each binding, including `binding = void value`.
    resets: HashMap<Id, usize>,
    uninitialized: HashSet<Id>,
}

impl Visit for Caches {
    fn visit_expr(&mut self, expression: &Expr) {
        if let Some((id, value)) = ast::assignment(expression)
            && match value {
                Expr::Unary(value) => value.op == UnaryOp::Void,
                Expr::Ident(value) => self.globals.is(value, "undefined"),
                _ => false,
            }
        {
            *self.resets.entry(id).or_default() += 1;
        }
        if let Some(memoized) = Memoized::of(expression) {
            let constants = self.memoized.entry(memoized.cache.to_id()).or_default();
            constants.push(memoized.constant);
        }
        expression.visit_children_with(self);
    }

    fn visit_var_declarator(&mut self, declarator: &VarDeclarator) {
        if declarator.init.is_none()
            && let Some(name) = declarator.name.as_ident()
        {
            self.uninitialized.insert(name.to_id());
        }
        declarator.visit_children_with(self);
    }
}

/// Replaces memoized reads of the constant caches with their values.
struct Inline<'constant>(&'constant HashSet<Id>);

impl VisitMut for Inline<'_> {
    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        expression.visit_mut_children_with(self);
        let Some(memoized) =
            Memoized::of(expression).filter(|memoized| self.0.contains(&memoized.cache.to_id()))
        else {
            return;
        };
        *expression = match memoized.fallback {
            Some(fallback) => Expr::Bin(BinExpr {
                span: memoized.cache.span,
                op: BinaryOp::LogicalOr,
                left: Box::new(fallback.clone()),
                right: Box::new(memoized.value.clone()),
            }),
            None => memoized.value.clone(),
        };
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
            /* fix= */ true,
        );
        testing::assert_contains(
            &output,
            &[],
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
