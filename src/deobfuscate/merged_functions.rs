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

use oxc::allocator::{Box, CloneIn, GetAllocator, TakeIn, Vec as ArenaVec};
use oxc::ast::ast::{
    Argument, BindingIdentifier, BindingPattern, CallExpression, Expression, Function,
    FunctionType, IdentifierReference, Program, Statement,
};
use oxc::ast_visit::{Visit, VisitMut, walk, walk_mut};
use oxc::span::GetSpan;
use oxc::syntax::node::NodeId;
use oxc::syntax::reference::ReferenceFlags;
use oxc::syntax::scope::ScopeFlags;
use oxc::syntax::symbol::SymbolId;

use super::analysis::{Analysis, Id};
use super::ast::LabeledContinue;
use super::{HashMap, HashSet, ast};

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let candidates = ast::functions(program, analysis, &|function| {
        function.r#type == FunctionType::FunctionDeclaration
            && function.body.as_ref().is_some_and(|body| {
                matches!(body.statements.as_slice(), [Statement::SwitchStatement(_)])
            })
    });
    let mut functions = HashMap::default();
    for (id, function) in candidates {
        if let Some(selection) = selection(function, analysis) {
            functions.insert(id, selection);
        }
    }
    let mut calls = Calls {
        analysis,
        functions: &functions,
        picked: HashMap::default(),
    };
    calls.visit_program(program);
    let mut splits = HashMap::default();
    for (id, picked) in calls.picked {
        if picked.calls != analysis.bindings.references(&id) {
            continue;
        }
        let scope = analysis.scope(id);
        let base = analysis.name(id).to_owned();
        let span = analysis.span(id);
        let names = (0..functions[&id].labels.len()).map(|index| {
            let used = picked.cases.contains(&index);
            used.then(|| analysis.fresh_binding(&format!("{base}_{index}"), scope, span))
        });
        splits.insert(id, names.collect());
    }
    if splits.is_empty() {
        return false;
    }
    Unmerge {
        analysis,
        functions: &functions,
        splits: &splits,
    }
    .visit_program(program);
    true
}

/// Maps numeric selector values to cases in a merged function.
struct Selection<'a> {
    selector: Id,
    discriminant: &'a Expression<'a>,
    labels: Vec<f64>,
}

impl Selection<'_> {
    /// Evaluates the discriminant with the call's literal first argument as the selector, and
    /// finds the matching case label.
    fn called_case(&self, call: &CallExpression<'_>, analysis: &Analysis<'_>) -> Option<usize> {
        let value = ast::number(call.arguments.first()?.as_expression()?)?;
        let selected = ast::fold_number(self.discriminant, &|expression| {
            (analysis.expression_id(expression) == Some(self.selector)).then_some(value)
        })?;
        self.labels.iter().position(|&label| label == selected)
    }
}

/// Recognizes a switch controlled only by the first parameter. Cases must return or throw,
/// never use the selector or `arguments`, and never refer to declarations from another case.
fn selection<'a>(function: &'a Function<'a>, analysis: &Analysis<'a>) -> Option<Selection<'a>> {
    let selector = *ast::parameters(function)?.first()?;
    let [Statement::SwitchStatement(switch)] = function.body.as_ref()?.statements.as_slice() else {
        return None;
    };
    let depends_on_selector = |expression: &Expression<'_>| {
        (analysis.expression_id(expression) == Some(selector)).then_some(0.0)
    };
    if function.r#async
        || function.generator
        || analysis.bindings.references(&selector) != 1
        || ast::fold_number(&switch.discriminant, &depends_on_selector).is_none()
    {
        return None;
    }
    let labels: Vec<f64> = switch
        .cases
        .iter()
        .map(|case| ast::fold_number(case.test.as_ref()?, &|_| None))
        .collect::<Option<_>>()?;
    let mut declarations = vec![];
    for case in &switch.cases {
        // Dead branch removal drops a trailing `return;` after an `if` whose branches return.
        if !case
            .consequent
            .last()
            .is_some_and(|last| ast::abrupt(last, false))
            || ast::escapes(&case.consequent, LabeledContinue::Any)
        {
            return None;
        }
        let mut declared = Declared::default();
        for statement in &case.consequent {
            declared.visit_statement(statement)
        }
        if declared.arguments {
            return None;
        }
        declarations.push(declared.ids);
    }
    for (index, case) in switch.cases.iter().enumerate() {
        for (other, ids) in declarations.iter().enumerate() {
            if index != other && ast::mentions(&case.consequent, ids, analysis) {
                return None;
            }
        }
    }
    Some(Selection {
        selector,
        discriminant: &switch.discriminant,
        labels,
    })
}

/// Collects a case's bindings, outside nested functions, and whether it mentions `arguments`.
#[derive(Default)]
struct Declared {
    ids: Vec<Id>,
    arguments: bool,
}

impl<'a> Visit<'a> for Declared {
    fn visit_binding_identifier(&mut self, binding: &BindingIdentifier<'a>) {
        if let Some(symbol) = binding.symbol_id.get() {
            self.ids.push(Id::Local(symbol))
        }
    }

    fn visit_identifier_reference(&mut self, reference: &IdentifierReference<'a>) {
        self.arguments |= ast::is_arguments(reference);
    }

    fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
}

#[derive(Default)]
struct Picked {
    calls: usize,
    cases: HashSet<usize>,
}

/// Counts the calls of each merged function with a constant selector and the cases they pick.
struct Calls<'b, 'a> {
    analysis: &'b Analysis<'a>,
    functions: &'b HashMap<Id, Selection<'a>>,
    picked: HashMap<Id, Picked>,
}

impl<'a> Visit<'a> for Calls<'_, 'a> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some(id) = self.analysis.expression_id(&call.callee)
            && let Some(selection) = self.functions.get(&id)
            && let Some(case) = selection.called_case(call, self.analysis)
            && !call.optional
            && !call.arguments.iter().any(Argument::is_spread)
        {
            let picked = self.picked.entry(id).or_default();
            picked.calls += 1;
            picked.cases.insert(case);
        }
        walk::walk_call_expression(self, call)
    }
}

struct Unmerge<'b, 'a> {
    analysis: &'b mut Analysis<'a>,
    functions: &'b HashMap<Id, Selection<'a>>,
    splits: &'b HashMap<Id, Vec<Option<BindingIdentifier<'a>>>>,
}

impl<'a> Unmerge<'_, 'a> {
    /// Creates a separate declaration for each selected case, omitting cases with no callers.
    /// Each new function gets its own scope and parameter symbols; references are rebound to those
    /// symbols so later rewrites and hygiene cannot conflate parameters from different cases.
    fn split(
        &mut self,
        mut function: Function<'a>,
        names: &[Option<BindingIdentifier<'a>>],
    ) -> ArenaVec<'a, Statement<'a>> {
        let allocator = self.analysis.allocator();
        let mut split = ArenaVec::new_in(&allocator);
        let Some(body) = &mut function.body else {
            return split;
        };
        // The switch moves out, so each copy of the function clones only its own case.
        let statements = body.statements.take_in(&allocator);
        let Some(Statement::SwitchStatement(switch)) = statements.first() else {
            return split;
        };
        let merged_scope = function
            .scope_id
            .get()
            .expect("semantic analysis assigns function scopes");
        let parent = self.analysis.scoping.scope_parent_id(merged_scope);
        for (case, name) in switch.cases.iter().zip(names) {
            let Some(name) = name else { continue };
            let mut separate = function.clone_in_with_semantic_ids(allocator);
            separate.id = Some(name.clone_in_with_semantic_ids(allocator));
            separate.params.items.remove(0);
            let scope =
                self.analysis
                    .scoping
                    .add_scope(parent, NodeId::DUMMY, ScopeFlags::Function);
            separate.scope_id.set(Some(scope));
            let mut renamed = HashMap::default();
            for parameter in &mut separate.params.items {
                if let Some(binding) = parameter.pattern.get_binding_identifier() {
                    let fresh = self.analysis.binding(&binding.name, scope, binding.span);
                    renamed.insert(Id::Local(binding.symbol_id()), fresh.symbol_id());
                    let fresh = Box::new_in(fresh, &allocator);
                    parameter.pattern = BindingPattern::BindingIdentifier(fresh);
                }
            }
            let mut statements = case.consequent.clone_in_with_semantic_ids(allocator);
            let mut rename = Rename {
                analysis: self.analysis,
                renamed: &renamed,
            };
            rename.visit_statements(&mut statements);
            if let Some(body) = &mut separate.body {
                body.statements = statements;
            }
            split.push(Statement::FunctionDeclaration(Box::new_in(
                separate, &allocator,
            )));
        }
        split
    }
}

impl<'a> VisitMut<'a> for Unmerge<'_, 'a> {
    fn visit_statements(&mut self, statements: &mut ArenaVec<'a, Statement<'a>>) {
        walk_mut::walk_statements(self, statements);
        let splits = self.splits;
        let mut out = ArenaVec::new_in(&self.analysis.ast);
        for statement in statements.take_in(&self.analysis.ast) {
            let Statement::FunctionDeclaration(function) = statement else {
                out.push(statement);
                continue;
            };
            match ast::function_id(&function).and_then(|id| splits.get(&id)) {
                Some(names) => out.extend(self.split(function.unbox(), names)),
                None => out.push(Statement::FunctionDeclaration(function)),
            }
        }
        *statements = out;
    }

    fn visit_call_expression(&mut self, call: &mut CallExpression<'a>) {
        walk_mut::walk_call_expression(self, call);
        if let Some(id) = self.analysis.expression_id(&call.callee)
            && let Some(names) = self.splits.get(&id)
            && let Some(case) = self.functions[&id].called_case(call, self.analysis)
            && let Some(name) = &names[case]
        {
            let span = call.callee.span();
            let reference = self
                .analysis
                .reference(name.symbol_id(), span, ReferenceFlags::Read);
            call.callee = Expression::Identifier(Box::new_in(reference, &self.analysis.ast));
            call.arguments.remove(0);
        }
    }
}

/// Rebinds references to the parameters of a split function.
struct Rename<'b, 'a> {
    analysis: &'b mut Analysis<'a>,
    renamed: &'b HashMap<Id, SymbolId>,
}

impl<'a> VisitMut<'a> for Rename<'_, 'a> {
    fn visit_identifier_reference(&mut self, reference: &mut IdentifierReference<'a>) {
        if let Some(id) = self.analysis.id(reference)
            && let Some(&renamed) = self.renamed.get(&id)
        {
            // Resolving `id` required a reference ID.
            let flags = self
                .analysis
                .scoping
                .get_reference(reference.reference_id())
                .flags();
            *reference = self.analysis.reference(renamed, reference.span, flags);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn splits_cases_with_labeled_jumps_inside_the_handler() {
        let output = testing::rewrite(
            r#"function m(s,a) {
            switch(s^5) {
                case 1: handler: { if(a) break handler; work(a); } return;
                case 2: loop: while(a) { a--; if(a) continue loop; break loop; } return;
            }
        } m(4,x); m(7,y);"#,
            super::run,
        );
        testing::assert_contains(
            &output,
            &[
                "function m_0(a)",
                "function m_1(a)",
                "break handler;",
                "continue loop;",
                "break loop;",
                "m_0(x);",
                "m_1(y);",
            ],
        );
        testing::assert_lacks(&output, &["switch"]);
    }

    #[test]
    fn splits_cases_that_literal_selectors_pick() {
        let transform = |source: &str| testing::rewrite(source, super::run);
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

    #[test]
    fn splits_cases_ending_in_branches_that_return() {
        // Dead branch removal leaves no `return;` after the `if`.
        let transform = |source: &str| testing::rewrite(source, super::run);
        let output = transform(
            "function m(s, a) { switch (s) { case 1: if (a) { return 1; } else { return 2; } \
             case 2: throw a; } } h(m(1, p), m(2, q));",
        );
        testing::assert_contains(&output, &["function m_0(a) {", "h(m_0(p), m_1(q));"]);
        testing::assert_lacks(&output, &["switch"]);
        // A branch that breaks out of the switch falls out of the case.
        let output = transform(
            "function m(s, a) { switch (s) { case 1: if (a) { return 1; } else { break; } \
             case 2: return; } } h(m(1, p), m(2, q));",
        );
        testing::assert_contains(&output, &["switch"]);
    }
}
