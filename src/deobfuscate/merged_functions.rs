//! Splits functions that the obfuscator merged behind a selector back into separate functions:
//!
//! ```js
//! function merged(selector, a) {
//!     switch (selector ^ 5) {
//!         case 1: return a + 1;
//!         case 2: g(a); return;
//!     }
//! }
//! merged(4, x); merged(7, y);
//! // becomes
//! function merged_0(a) { return a + 1; }
//! function merged_1(a) { g(a); return; }
//! merged_0(x); merged_1(y);
//! ```
//!
//! The function body must contain only a switch whose value depends solely on the first
//! parameter. Case labels must be constant, with no default. Each case must end in `return` or
//! `throw` and have no other jump out of the switch.
//!
//! Every reference must be a call with a literal selector that matches a case. Cases must not
//! use the selector, `arguments`, or declarations from another case. Each new function gets
//! separate bindings for the remaining parameters. Cases with no callers are removed.

use swc_core::common::{DUMMY_SP, Mark, SyntaxContext};
use swc_core::ecma::ast::{
    BlockStmt, CallExpr, Callee, ClassDecl, Decl, Expr, FnDecl, Function, Id, Ident, Lit, Program,
    Stmt, SwitchStmt, VarDeclarator,
};
use swc_core::ecma::visit::{Visit, VisitMut, VisitMutWith, VisitWith};

use super::analysis::{Analysis, Bindings, names};
use super::state_machines::escapes;
use super::{HashMap, HashSet};
use crate::js::ast;

pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    let bindings = analysis.bindings(program);
    let mut merged = Merged {
        bindings,
        functions: HashMap::default(),
    };
    program.visit_with(&mut merged);
    let mut calls = Calls {
        functions: &merged.functions,
        picked: HashMap::default(),
    };
    program.visit_with(&mut calls);
    // Replacement function for each case selected by a call.
    let mut splits: HashMap<Id, Vec<Option<Ident>>> = HashMap::default();
    for (id, picked) in calls.picked {
        let Some(picked) = picked.filter(|picked| picked.calls == bindings.references(&id)) else {
            continue;
        };
        let context = SyntaxContext::empty().apply_mark(Mark::new());
        let names: Vec<Option<Ident>> = (0..merged.functions[&id].labels.len())
            .map(|index| {
                picked
                    .cases
                    .contains(&index)
                    .then(|| Ident::new(format!("{}_{index}", id.0).into(), DUMMY_SP, context))
            })
            .collect();
        splits.insert(id, names);
    }
    if splits.is_empty() {
        return false;
    }
    program.visit_mut_with(&mut Unmerge {
        functions: &merged.functions,
        splits: &splits,
    });
    true
}

/// Maps selector values to cases in a merged function.
struct Selection {
    selector: Id,
    discriminant: Expr,
    labels: Vec<f64>,
}

impl Selection {
    /// Returns the case selected by `selector`.
    fn case(&self, selector: f64) -> Option<usize> {
        let value = ast::fold_number(&self.discriminant, &|leaf| {
            (leaf.as_ident()?.to_id() == self.selector).then_some(selector)
        })?;
        self.labels.iter().position(|&label| label == value)
    }
}

/// Finds merged function declarations.
struct Merged<'bindings> {
    bindings: &'bindings Bindings,
    functions: HashMap<Id, Selection>,
}

impl Merged<'_> {
    fn selection(&self, function: &Function) -> Option<Selection> {
        let selector = names::parameter_ids(&function.params)?.first()?.clone();
        let [Stmt::Switch(switch)] = &function.body.as_ref()?.stmts[..] else {
            return None;
        };
        // The discriminant is computed from the selector alone.
        ast::fold_number(&switch.discriminant, &|leaf| {
            (leaf.as_ident()?.to_id() == selector).then_some(0.0)
        })?;
        let labels = switch
            .cases
            .iter()
            .map(|case| ast::fold_number(case.test.as_deref()?, &|_| None))
            .collect::<Option<Vec<_>>>()?;
        let separate = !function.is_async
            && !function.is_generator
            && names::mentions(&*switch.discriminant, std::slice::from_ref(&selector))
            && self.bindings.references(&selector) == 1
            && !names::uses_arguments(&switch.cases)
            && switch.cases.iter().all(|case| {
                matches!(case.cons.last(), Some(Stmt::Return(_) | Stmt::Throw(_)))
                    && !escapes(&case.cons)
            })
            && independent(switch);
        separate.then(|| Selection {
            selector,
            discriminant: (*switch.discriminant).clone(),
            labels,
        })
    }
}

impl Visit for Merged<'_> {
    fn visit_fn_decl(&mut self, declaration: &FnDecl) {
        if self.bindings.is_written_once(&declaration.ident.to_id())
            && let Some(selection) = self.selection(&declaration.function)
        {
            self.functions.insert(declaration.ident.to_id(), selection);
        }
        declaration.visit_children_with(self);
    }
}

/// Checks that no case refers to a binding declared in another case.
fn independent(switch: &SwitchStmt) -> bool {
    let declared: Vec<Vec<Id>> = switch
        .cases
        .iter()
        .map(|case| {
            let mut declarations = Declarations::default();
            case.cons.visit_with(&mut declarations);
            declarations.0
        })
        .collect();
    switch.cases.iter().enumerate().all(|(index, case)| {
        declared
            .iter()
            .enumerate()
            .all(|(other, ids)| other == index || !names::mentions(&case.cons, ids))
    })
}

#[derive(Default)]
struct Declarations(Vec<Id>);

impl Visit for Declarations {
    fn visit_var_declarator(&mut self, declarator: &VarDeclarator) {
        self.0
            .extend(swc_ecma_utils::find_pat_ids::<_, Id>(&declarator.name));
        declarator.visit_children_with(self);
    }

    fn visit_fn_decl(&mut self, declaration: &FnDecl) {
        self.0.push(declaration.ident.to_id());
        declaration.visit_children_with(self);
    }

    fn visit_class_decl(&mut self, declaration: &ClassDecl) {
        self.0.push(declaration.ident.to_id());
        declaration.visit_children_with(self);
    }
}

/// Finds the cases selected by calls to a merged function. Returns `None` if any reference is not a
/// direct call with a literal selector that matches a case.
#[derive(Default)]
struct Picked {
    calls: usize,
    cases: HashSet<usize>,
}

struct Calls<'functions> {
    functions: &'functions HashMap<Id, Selection>,
    picked: HashMap<Id, Option<Picked>>,
}

/// Extracts the function name and literal selector from `function(selector, ...)`.
fn selected_call(call: &CallExpr) -> Option<(Id, Option<f64>)> {
    let callee = call.callee.as_expr()?.as_ident()?.to_id();
    let spreads = call.args.iter().any(|argument| argument.spread.is_some());
    let selector = match call.args.first().map(|first| &*first.expr) {
        Some(Expr::Lit(Lit::Num(number))) if !spreads => Some(number.value),
        _ => None,
    };
    Some((callee, selector))
}

impl Visit for Calls<'_> {
    fn visit_call_expr(&mut self, call: &CallExpr) {
        if let Some((id, selector)) = selected_call(call)
            && let Some(selection) = self.functions.get(&id)
        {
            let case = selector.and_then(|value| selection.case(value));
            let picked = self
                .picked
                .entry(id)
                .or_insert_with(|| Some(Picked::default()));
            match (picked.as_mut(), case) {
                (Some(picked), Some(case)) => {
                    picked.calls += 1;
                    picked.cases.insert(case);
                }
                _ => *picked = None,
            }
        }
        call.visit_children_with(self);
    }
}

/// Creates replacement functions for the cases of `declaration` listed in `names`.
fn split(declaration: FnDecl, names: &[Option<Ident>]) -> Vec<Stmt> {
    let mut function = declaration.function;
    let mut body = function.body.take().expect("checked when collected");
    let Some(Stmt::Switch(switch)) = body.stmts.pop() else {
        unreachable!("checked when collected");
    };
    let _selector = function.params.remove(0);
    let mut functions = vec![];
    for (case, name) in switch.cases.into_iter().zip(names) {
        let Some(name) = name else { continue };
        // Give each split function separate parameter bindings.
        let context = SyntaxContext::empty().apply_mark(Mark::new());
        let renamed: HashMap<Id, Ident> = function
            .params
            .iter()
            .filter_map(|parameter| parameter.pat.as_ident())
            .map(|parameter| {
                let fresh = Ident::new(parameter.sym.clone(), parameter.span, context);
                (parameter.to_id(), fresh)
            })
            .collect();
        let mut rename = Rename(&renamed);
        let mut separate = function.clone();
        separate.params.visit_mut_with(&mut rename);
        let mut stmts = case.cons;
        stmts.visit_mut_with(&mut rename);
        separate.body = Some(BlockStmt {
            stmts,
            ..body.clone()
        });
        functions.push(Stmt::Decl(Decl::Fn(FnDecl {
            ident: name.clone(),
            declare: false,
            function: separate,
        })));
    }
    functions
}

struct Unmerge<'a> {
    functions: &'a HashMap<Id, Selection>,
    splits: &'a HashMap<Id, Vec<Option<Ident>>>,
}

impl VisitMut for Unmerge<'_> {
    fn visit_mut_stmts(&mut self, statements: &mut Vec<Stmt>) {
        statements.visit_mut_children_with(self);
        let mut replaced = Vec::with_capacity(statements.len());
        for statement in statements.drain(..) {
            match statement {
                Stmt::Decl(Decl::Fn(declaration))
                    if self.splits.contains_key(&declaration.ident.to_id()) =>
                {
                    let names = &self.splits[&declaration.ident.to_id()];
                    replaced.extend(split(declaration, names));
                }
                statement => replaced.push(statement),
            }
        }
        *statements = replaced;
    }

    fn visit_mut_call_expr(&mut self, call: &mut CallExpr) {
        call.visit_mut_children_with(self);
        if let Some((id, Some(selector))) = selected_call(call)
            && let Some(names) = self.splits.get(&id)
            && let Some(case) = self.functions[&id].case(selector)
            && let Some(Some(name)) = names.get(case)
        {
            call.callee = Callee::Expr(Box::new(Expr::Ident(name.clone())));
            call.args.remove(0);
        }
    }
}

struct Rename<'a>(&'a HashMap<Id, Ident>);

impl VisitMut for Rename<'_> {
    fn visit_mut_ident(&mut self, identifier: &mut Ident) {
        if let Some(fresh) = self.0.get(&identifier.to_id()) {
            *identifier = fresh.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn splits_cases_that_literal_selectors_pick() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
        let merged = "function m(s, a) {
                switch (s ^ 5) {
                    case 1: var x = a + 1; return x;
                    case 2: g(a); return;
                    case 3: dead(); return;
                }
            }";
        let output = transform(&format!("{merged} h(m(4, p), m(7, q), m(4, r));"));
        testing::assert_contains(
            &output,
            &[],
            &[
                "function m_0(a) { var x = a + 1; return x; }",
                "function m_1(a) { g(a); return; }",
                "h(m_0(p), m_1(q), m_0(r));",
            ],
        );
        testing::assert_lacks(&output, &["dead", "switch"]);
        for kept in [
            format!("{merged} h(m(4, p), m(9, q));"),
            format!("{merged} h(m(s, p));"),
            format!("{merged} h(m);"),
            "function m(s, a) { switch (s) { case 1: var x = 1; return; case 2: return x; } } m(1, 2);"
                .to_owned(),
            "function m(s, a) { switch (s) { case 1: g(); case 2: return; } } m(1, 2);".to_owned(),
            "function m(s, a) { switch (s) { case 1: return s; } } m(1, 2);".to_owned(),
            "function m(s, a) { switch (s) { case 1: return arguments; } } m(1, 2);".to_owned(),
            "function m(s, a) { switch (s) { case 1: return; default: return; } } m(1, 2);"
                .to_owned(),
        ] {
            let output = transform(&kept);
            assert!(output.contains("switch"), "{output}");
        }
    }
}
