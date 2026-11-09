//! Tracks which analysis facts hold when a hoisted function runs.
//!
//! A function declaration can be called before the statements above it execute. Facts learned
//! from those statements are safe to use in the function only if they hold at every reference
//! that could make it callable, including references through other declarations in the same
//! list. Visitors process ordinary statements first and record identifier uses through
//! [`reference()`]. They then visit declarations with the facts valid for each one.
//!
//! Block declarations work the same way, with an extra rule for sloppy mode: after a block
//! function declaration runs, the function is also accessible through the enclosing function's
//! `var` binding, so the facts known at that declaration are included too.
//!
//! Other scripts can call top-level functions at any time, and any switch case can call
//! functions declared in another case. For both, only the facts known on entry are used.

use std::mem;
use std::rc::Rc;

use oxc::ast::ast::{BlockStatement, Function, IdentifierReference, Statement};
use oxc::ast_visit::{Visit, VisitMut};

use super::{Analysis, Id};
use crate::deobfuscate::{HashMap, ast};

/// Facts known at a point in the program.
pub(in crate::deobfuscate) trait Facts: Clone {
    /// Keeps only the facts that also hold in `other`.
    fn meet(&mut self, other: &Self);
}

impl<V: Clone> Facts for HashMap<Id, V> {
    fn meet(&mut self, other: &Self) {
        self.retain(|id, _| other.contains_key(id))
    }
}

impl<F: Facts> Facts for Rc<F> {
    fn meet(&mut self, other: &Self) {
        if !Rc::ptr_eq(self, other) {
            Rc::make_mut(self).meet(other)
        }
    }
}

/// The kind of statement list that contains declarations.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::deobfuscate) enum List {
    #[default]
    Other,
    FunctionBody,
    Block,
}

#[derive(Default)]
pub(in crate::deobfuscate) struct Hoisting<F> {
    /// Facts known at the current point in traversal.
    pub facts: F,
    /// Facts shared by every reference to each declaration; `None` before its first reference.
    pending: HashMap<Id, Option<F>>,
    /// The kind of the next statement list.
    pub list: List,
}

/// A rewrite that tracks facts across hoisted function declarations.
pub(in crate::deobfuscate) trait Hoisted<'a>: VisitMut<'a> {
    type Facts: Facts;

    fn analysis(&self) -> &Analysis<'a>;

    fn hoisting(&mut self) -> &mut Hoisting<Self::Facts>;
}

fn meet<F: Facts>(slot: &mut Option<F>, facts: &F) {
    match slot {
        Some(slot) => slot.meet(facts),
        None => *slot = Some(facts.clone()),
    }
}

/// Records the current facts where an identifier makes a declaration callable. A reference to
/// `eval` makes every pending declaration callable.
pub(in crate::deobfuscate) fn reference<'a, V: Hoisted<'a>>(
    visitor: &mut V,
    reference: &IdentifierReference<'a>,
) {
    let id = visitor.analysis().id(reference);
    let hoisting = visitor.hoisting();
    if reference.name == "eval" {
        for slot in hoisting.pending.values_mut() {
            meet(slot, &hoisting.facts)
        }
    } else if let Some(slot) = id.and_then(|id| hoisting.pending.get_mut(&id)) {
        meet(slot, &hoisting.facts)
    }
}

/// Visits ordinary statements first, then each declaration with the facts valid at every direct
/// or transitive caller, and finally restores the facts left by the ordinary statements.
/// Unreferenced and top-level declarations use the entry facts.
pub(in crate::deobfuscate) fn statements<'a, V: Hoisted<'a>>(
    visitor: &mut V,
    statements: &mut [Statement<'a>],
    mut visit: impl FnMut(&mut V, &mut Statement<'a>),
) {
    let mut declarations = Vec::new();
    for (position, statement) in statements.iter().enumerate() {
        if let Statement::FunctionDeclaration(function) = statement
            && let Some(id) = ast::function_id(function)
        {
            declarations.push(Declaration { position, id });
        }
    }
    let mut list = mem::take(&mut visitor.hoisting().list);
    if list == List::Block
        && declarations
            .iter()
            .any(|declaration| visitor.hoisting().pending.contains_key(&declaration.id))
    {
        list = List::Other
    }
    let entry = visitor.hoisting().facts.clone();
    let mut callers = vec![vec![]; declarations.len()];
    if list != List::Other {
        for declaration in &declarations {
            visitor
                .hoisting()
                .pending
                .entry(declaration.id)
                .or_default();
        }
        for (caller, declaration) in declarations.iter().enumerate() {
            let mut callees = Callees {
                analysis: visitor.analysis(),
                declarations: &declarations,
                called: vec![],
            };
            callees.visit_statement(&statements[declaration.position]);
            for callee in callees.called {
                callers[callee].push(caller)
            }
        }
    }
    let mut reached = vec![];
    for statement in statements.iter_mut() {
        if !matches!(statement, Statement::FunctionDeclaration(_)) {
            visit(visitor, statement)
        } else if list == List::Block {
            reached.push(visitor.hoisting().facts.clone())
        }
    }
    let direct: Vec<_> = declarations
        .iter()
        .map(|declaration| visitor.hoisting().pending.remove(&declaration.id).flatten())
        .collect();
    let exit = visitor.hoisting().facts.clone();
    for (index, declaration) in declarations.iter().enumerate() {
        let mut facts = None;
        if list != List::Other {
            let mut seen = vec![false; declarations.len()];
            let mut pending = vec![index];
            while let Some(current) = pending.pop() {
                if mem::replace(&mut seen[current], true) {
                    continue;
                }
                if let Some(known) = &direct[current] {
                    meet(&mut facts, known)
                }
                pending.extend(&callers[current]);
            }
            if let Some(known) = reached.get(index) {
                meet(&mut facts, known)
            }
        }
        visitor.hoisting().facts = facts.unwrap_or_else(|| entry.clone());
        visitor.visit_statement(&mut statements[declaration.position]);
        visitor.hoisting().facts = exit.clone();
    }
}

/// Visits the parameters, then the body as a function-body statement list.
pub(in crate::deobfuscate) fn function<'a, V: Hoisted<'a>>(
    visitor: &mut V,
    function: &mut Function<'a>,
) {
    visitor.visit_formal_parameters(&mut function.params);
    if let Some(body) = &mut function.body {
        visitor.hoisting().list = List::FunctionBody;
        visitor.visit_function_body(body)
    }
}

/// Visits the block's statements as a block statement list.
pub(in crate::deobfuscate) fn block<'a, V: Hoisted<'a>>(
    visitor: &mut V,
    block: &mut BlockStatement<'a>,
) {
    if visitor.hoisting().list == List::Other {
        visitor.hoisting().list = List::Block
    }
    visitor.visit_statements(&mut block.body)
}

struct Declaration {
    position: usize,
    id: Id,
}

/// Collects the indexes of the declarations a statement can call.
struct Callees<'b, 'a> {
    analysis: &'b Analysis<'a>,
    declarations: &'b [Declaration],
    called: Vec<usize>,
}

impl<'a> Visit<'a> for Callees<'_, 'a> {
    fn visit_identifier_reference(&mut self, reference: &IdentifierReference<'a>) {
        let id = self.analysis.id(reference);
        for (index, declaration) in self.declarations.iter().enumerate() {
            if reference.name == "eval" || id == Some(declaration.id) {
                self.called.push(index)
            }
        }
    }
}
