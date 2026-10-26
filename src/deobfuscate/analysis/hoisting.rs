//! Tracks which analysis facts hold when a hoisted function runs.
//!
//! A function declaration can be called before the statements above it execute. Facts learned
//! from those statements are safe to use in the function only if they hold at every reference
//! that could make it callable. References through other declarations in the same list also
//! count. Visitors process ordinary statements first and record identifier uses through
//! [`reference`]. They then visit declarations with the facts valid for each one.
//!
//! This treatment applies only to declarations in function bodies. Top-level functions can be
//! called by other scripts at any time. Block functions exist only once the block executes.
//! Both use the facts known on entry.

use std::mem;
use std::rc::Rc;

use swc_core::ecma::ast::{Decl, Function, Id, Ident, Stmt};
use swc_core::ecma::visit::{Visit, VisitMut, VisitMutWith, VisitWith};

use crate::deobfuscate::{HashMap, HashSet};

/// Facts known at a point in the program.
pub(crate) trait HoistFacts: Clone {
    /// Keeps facts shared with `other`.
    fn meet(&mut self, other: &Self);
}

impl HoistFacts for HashSet<Id> {
    fn meet(&mut self, other: &Self) {
        self.retain(|id| other.contains(id));
    }
}

/// Facts about bindings assigned once. Any known values for the same binding must agree.
impl<V: Clone> HoistFacts for HashMap<Id, V> {
    fn meet(&mut self, other: &Self) {
        self.retain(|id, _| other.contains_key(id));
    }
}

/// Copy-on-write facts, shared between the current node and declaration snapshots.
impl<F: HoistFacts> HoistFacts for Rc<F> {
    fn meet(&mut self, other: &Self) {
        if !Rc::ptr_eq(self, other) {
            Rc::make_mut(self).meet(other);
        }
    }
}

/// A function declaration, which its whole scope sees from the start.
fn is_declaration(statement: &Stmt) -> bool {
    matches!(statement, Stmt::Decl(Decl::Fn(_)))
}

/// Tracks current facts, active function declarations, and facts collected at references to
/// those declarations.
#[derive(Default)]
pub(crate) struct Hoisting<F> {
    /// Facts known at the current node.
    pub(crate) facts: F,
    /// Intersection of facts at references to each declaration; `None` before its first
    /// reference.
    pending: HashMap<Id, Option<F>>,
    /// Whether the next statement list is a function body.
    pub(crate) function_body: bool,
}

/// The function declarations of one statement list, from
/// [`Hoisting::enter`] to [`Hoisting::leave`].
struct Declarations<F> {
    declarations: Vec<Declaration>,
    /// For each declaration, the declarations in this list that reference it.
    callers: Vec<Vec<usize>>,
    /// Facts at list entry, saved when the list contains declarations.
    entry: Option<F>,
    function_body: bool,
}

/// One function declaration of a statement list, at `position` in it.
struct Declaration {
    position: usize,
    id: Id,
}

impl<F: HoistFacts> Hoisting<F> {
    /// Starts visiting `statements` with the entry facts.
    #[must_use]
    fn enter(&mut self, statements: &[Stmt]) -> Declarations<F> {
        let function_body = mem::take(&mut self.function_body);
        let declarations: Vec<Declaration> = statements
            .iter()
            .enumerate()
            .filter_map(|(position, statement)| {
                let id = statement.as_decl()?.as_fn_decl()?.ident.to_id();
                Some(Declaration { position, id })
            })
            .collect();
        let mut callers = vec![];
        if function_body {
            let mut indices: HashMap<Id, Vec<usize>> = HashMap::default();
            for (index, declaration) in declarations.iter().enumerate() {
                indices
                    .entry(declaration.id.clone())
                    .or_default()
                    .push(index);
                self.pending.entry(declaration.id.clone()).or_insert(None);
            }
            callers = vec![vec![]; declarations.len()];
            for (caller, declaration) in declarations.iter().enumerate() {
                statements[declaration.position].visit_with(&mut Named {
                    indices: &indices,
                    callers: &mut callers,
                    caller,
                });
            }
        }
        Declarations {
            entry: (!declarations.is_empty()).then(|| self.facts.clone()),
            declarations,
            callers,
            function_body,
        }
    }

    /// Finishes ordinary statements and returns each declaration's position and facts valid
    /// whenever it can run. Unreferenced declarations receive the entry facts.
    #[must_use]
    fn leave(&mut self, declarations: Declarations<F>) -> Vec<(usize, F)> {
        let Declarations {
            declarations,
            callers,
            entry,
            function_body,
        } = declarations;
        let Some(entry) = entry else {
            return vec![];
        };
        if !function_body {
            return declarations
                .into_iter()
                .map(|declaration| (declaration.position, entry.clone()))
                .collect();
        }
        let direct: Vec<Option<F>> = declarations
            .iter()
            .map(|declaration| self.pending.get(&declaration.id).cloned().flatten())
            .collect();
        for declaration in &declarations {
            self.pending.remove(&declaration.id);
        }
        // A declaration becomes callable when another declaration that references it, directly
        // or indirectly, is referenced.
        let mut declared = Vec::with_capacity(declarations.len());
        for (index, declaration) in declarations.iter().enumerate() {
            let mut facts = None;
            let mut seen = vec![false; declarations.len()];
            let mut pending = vec![index];
            seen[index] = true;
            while let Some(current) = pending.pop() {
                if let Some(known) = &direct[current] {
                    meet(&mut facts, known);
                }
                for &caller in &callers[current] {
                    if !mem::replace(&mut seen[caller], true) {
                        pending.push(caller);
                    }
                }
            }
            declared.push((declaration.position, facts.unwrap_or_else(|| entry.clone())));
        }
        declared
    }
}

/// A rewrite that tracks facts across hoisted declarations.
pub(crate) trait Hoisted {
    type Facts: HoistFacts;

    fn hoisting(&mut self) -> &mut Hoisting<Self::Facts>;
}

/// Visits ordinary statements through `statement`, then function declarations with facts valid
/// at every possible call. Restores the facts left by ordinary statements afterward.
pub(crate) fn visit_mut_stmts<V: Hoisted + VisitMut>(
    visitor: &mut V,
    statements: &mut [Stmt],
    mut statement: impl FnMut(&mut V, &mut Stmt),
) {
    let declarations = visitor.hoisting().enter(statements);
    for other in statements.iter_mut() {
        if !is_declaration(other) {
            statement(visitor, other);
        }
    }
    let declared = visitor.hoisting().leave(declarations);
    for (position, facts) in declared {
        with_facts(visitor, facts, |visitor| {
            statements[position].visit_mut_with(visitor);
        });
    }
}

/// [`visit_mut_stmts`] for a visitor that only reads the tree.
pub(crate) fn visit_stmts<V: Hoisted + Visit>(
    visitor: &mut V,
    statements: &[Stmt],
    mut statement: impl FnMut(&mut V, &Stmt),
) {
    let declarations = visitor.hoisting().enter(statements);
    for other in statements {
        if !is_declaration(other) {
            statement(visitor, other);
        }
    }
    let declared = visitor.hoisting().leave(declarations);
    for (position, facts) in declared {
        with_facts(visitor, facts, |visitor| {
            statements[position].visit_with(visitor);
        });
    }
}

/// Marks a function body for [`Hoisting::enter`] before visiting it.
pub(crate) fn visit_mut_function<V: Hoisted + VisitMut>(visitor: &mut V, function: &mut Function) {
    function.decorators.visit_mut_with(visitor);
    function.params.visit_mut_with(visitor);
    if let Some(body) = &mut function.body {
        visitor.hoisting().function_body = true;
        body.visit_mut_with(visitor);
    }
}

/// Records current facts at a reference to `identifier`. Direct `eval` can reference any
/// declaration in scope.
pub(crate) fn reference<V: Hoisted>(visitor: &mut V, identifier: &Ident) {
    let Hoisting { facts, pending, .. } = visitor.hoisting();
    if identifier.sym == "eval" {
        for known in pending.values_mut() {
            meet(known, facts);
        }
    } else if let Some(known) = pending.get_mut(&identifier.to_id()) {
        meet(known, facts);
    }
}

/// Visits with `facts`, then restores the previous facts.
fn with_facts<V: Hoisted>(visitor: &mut V, facts: V::Facts, visit: impl FnOnce(&mut V)) {
    let current = mem::replace(&mut visitor.hoisting().facts, facts);
    visit(visitor);
    visitor.hoisting().facts = current;
}

fn meet<F: HoistFacts>(known: &mut Option<F>, facts: &F) {
    match known {
        Some(known) => known.meet(facts),
        None => *known = Some(facts.clone()),
    }
}

/// Records references between function declarations in the same statement list.
struct Named<'declarations> {
    indices: &'declarations HashMap<Id, Vec<usize>>,
    callers: &'declarations mut [Vec<usize>],
    caller: usize,
}

impl Visit for Named<'_> {
    fn visit_ident(&mut self, identifier: &Ident) {
        if identifier.sym == "eval" {
            let every_index = self.indices.values().flatten();
            for &index in every_index {
                self.callers[index].push(self.caller);
            }
        } else if let Some(indices) = self.indices.get(&identifier.to_id()) {
            for &index in indices {
                self.callers[index].push(self.caller);
            }
        }
    }
}
