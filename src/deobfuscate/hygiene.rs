//! Preserves binding identity when rewrites move code across scope boundaries.
//!
//! ```js
//! function f(x) { var a; a = x; return function(x) { return a + x; }; }
//! // After copy propagation, hygiene keeps the captured and parameter bindings distinct:
//! function f(x) { return function(x_1) { return x + x_1; }; }
//! ```
//!
//! Finds references that another binding with the same spelling now hides, and locals with the
//! same spelling that arrow inlining moved into one function. Those locals get unused names while
//! references keep their symbols. Renamed shorthand properties keep their original keys.

use std::cell::Cell;

use oxc::ast::ast::{BindingIdentifier, IdentifierReference, ObjectProperty, Program};
use oxc::ast_visit::{Visit, VisitMut, walk_mut};
use oxc::str::Ident;
use oxc::syntax::scope::{ScopeFlags, ScopeId};

use super::analysis::{Analysis, Id};
use super::{HashMap, HashSet, ast};

/// The bindings declared in each scope, by name.
type Bindings<'a> = HashMap<ScopeId, HashMap<Ident<'a>, HashSet<Id>>>;

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) {
    let mut declarations = Declarations {
        analysis,
        stack: vec![],
        bindings: HashMap::default(),
    };
    declarations.visit_program(program);
    let bindings = declarations.bindings;
    // Every binding but the first of each name declared in one scope conflicts.
    let mut conflicts = HashSet::default();
    for names in bindings.values() {
        for ids in names.values() {
            let first = ids.iter().min();
            conflicts.extend(ids.iter().filter(|&id| Some(id) != first));
        }
    }
    let mut references = References {
        analysis,
        bindings: &bindings,
        stack: vec![],
        conflicts,
    };
    references.visit_program(program);
    let mut conflicts: Vec<Id> = references.conflicts.into_iter().collect();
    conflicts.sort_unstable();
    let mut renamed = HashMap::default();
    for id in conflicts {
        let name = analysis.suffixed_name(analysis.name(id));
        let name = Ident::from_str_in(&name, &analysis.ast);
        let symbol = id.local().expect("a conflicting binding is declared");
        analysis.scoping.set_symbol_name(symbol, name);
        renamed.insert(id, name);
    }
    Rename {
        analysis,
        renamed: &renamed,
    }
    .visit_program(program);
}

/// Collects the bindings declared in each scope of the rewritten tree. A binding moved out of
/// its original scope belongs to the nearest enclosing function scope.
struct Declarations<'b, 'a> {
    analysis: &'b Analysis<'a>,
    /// The entered scopes and their flags.
    stack: Vec<(ScopeId, ScopeFlags)>,
    bindings: Bindings<'a>,
}

impl<'a> Visit<'a> for Declarations<'_, 'a> {
    fn enter_scope(&mut self, flags: ScopeFlags, scope: &Cell<Option<ScopeId>>) {
        let scope = scope.get().unwrap_or_else(|| {
            let parent = self.stack.last();
            parent.map_or(self.analysis.scoping.root_scope_id(), |&(parent, _)| parent)
        });
        self.stack.push((scope, flags))
    }

    fn leave_scope(&mut self) {
        self.stack.pop();
    }

    fn visit_binding_identifier(&mut self, binding: &BindingIdentifier<'a>) {
        let Some(symbol) = binding.symbol_id.get() else {
            return;
        };
        let id = Id::Local(symbol);
        let original = self.analysis.scope(id);
        let scope = if self.stack.iter().any(|&(scope, _)| scope == original) {
            original
        } else {
            let mut scopes = self.stack.iter().rev();
            let function = scopes.find(|(_, flags)| flags.contains(ScopeFlags::Function));
            function.map_or(self.analysis.scoping.root_scope_id(), |&(scope, _)| scope)
        };
        let names = self.bindings.entry(scope).or_default();
        names.entry(binding.name).or_default().insert(id);
    }
}

/// Collects the bindings that hide a reference's own binding.
struct References<'b, 'a> {
    analysis: &'b Analysis<'a>,
    bindings: &'b Bindings<'a>,
    stack: Vec<ScopeId>,
    conflicts: HashSet<Id>,
}

impl<'a> Visit<'a> for References<'_, 'a> {
    fn enter_scope(&mut self, _: ScopeFlags, scope: &Cell<Option<ScopeId>>) {
        let scope = scope.get().unwrap_or_else(|| {
            let parent = self.stack.last().copied();
            parent.unwrap_or(self.analysis.scoping.root_scope_id())
        });
        self.stack.push(scope)
    }

    fn leave_scope(&mut self) {
        self.stack.pop();
    }

    fn visit_identifier_reference(&mut self, reference: &IdentifierReference<'a>) {
        let expected = self.analysis.id(reference);
        for scope in self.stack.iter().rev() {
            let names = self.bindings.get(scope);
            if let Some(ids) = names.and_then(|names| names.get(&reference.name)) {
                if expected.is_none_or(|id| !ids.contains(&id)) {
                    self.conflicts.extend(ids);
                }
                break;
            }
        }
    }
}

struct Rename<'b, 'a> {
    analysis: &'b Analysis<'a>,
    renamed: &'b HashMap<Id, Ident<'a>>,
}

impl<'a> VisitMut<'a> for Rename<'_, 'a> {
    fn visit_binding_identifier(&mut self, binding: &mut BindingIdentifier<'a>) {
        if let Some(symbol) = binding.symbol_id.get()
            && let Some(&name) = self.renamed.get(&Id::Local(symbol))
        {
            binding.name = name;
        }
    }

    fn visit_object_property(&mut self, property: &mut ObjectProperty<'a>) {
        walk_mut::walk_object_property(self, property);
        ast::normalize_property(property, &self.analysis.ast)
    }

    fn visit_identifier_reference(&mut self, reference: &mut IdentifierReference<'a>) {
        let id = self.analysis.id(reference);
        if let Some(&name) = id.and_then(|id| self.renamed.get(&id)) {
            reference.name = name;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn preserves_references_moved_under_shadowing_parameters() {
        let output = testing::transform("function f(x){var a;a=x;return function(x){return a+x;}}");
        testing::assert_contains(&output, &["return x + x_1;"]);
    }

    #[test]
    fn separates_bindings_when_an_arrow_body_moves_into_its_parent() {
        let output = testing::transform(
            "function f(){var x=g(),step;step=()=>{var x=h();use(x)};step();return x;}",
        );
        testing::assert_contains(
            &output,
            &["var x = g()", "var x_1 = h()", "use(x_1)", "return x;"],
        );
    }

    #[test]
    fn preserves_global_undefined_and_shorthand_keys() {
        let output = testing::transform("function f(undefined){return [void 0,{undefined}];}");
        testing::assert_contains(
            &output,
            &["function f(undefined_1)", "undefined: undefined_1"],
        );
    }
}
