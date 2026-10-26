//! Restores flattened switch cases to execution order and removes the dispatcher loop. Handles
//! a `for` dispatcher or its normalized assignments-plus-`while` form:
//!
//! ```js
//! for (order = "b|a".split("|"), cursor = 0; true;) { switch (order[cursor++]) { ... } break; }
//! order = "b|a".split("|"); cursor = 0; while (true) { switch (order[cursor++]) { ... } break; }
//! ```
//!
//! Removes order and cursor assignments only if they are used solely by the dispatcher or never
//! mentioned after the loop in the same statement list.

use swc_core::atoms::Atom;
use swc_core::common::{Span, SyntaxContext};
use swc_core::ecma::ast::{
    ArrowExpr, BlockStmt, BreakStmt, Class, ContinueStmt, Expr, ForStmt, Function, Id, LabeledStmt,
    Lit, MemberProp, Program, Stmt, SwitchCase, SwitchStmt, UpdateOp, VarDeclOrExpr,
};
use swc_core::ecma::visit::{Visit, VisitMut, VisitMutWith, VisitWith};

use super::analysis::{Analysis, Bindings, names};
use super::{HashMap, HashSet};
use crate::js::ast;

pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    let mut unflatten = UnflattenSwitches {
        bindings: analysis.bindings(program),
        changed: false,
    };
    program.visit_mut_with(&mut unflatten);
    unflatten.changed
}

struct UnflattenSwitches<'bindings> {
    bindings: &'bindings Bindings,
    changed: bool,
}

impl UnflattenSwitches<'_> {
    /// Checks whether dispatcher setup for `bindings` must be preserved because later
    /// statements may use it.
    fn keeps_setup(&self, bindings: &[Id; 2], after: Option<&[Stmt]>) -> bool {
        bindings.iter().any(|id| self.bindings.references(id) > 1)
            && after.is_none_or(|after| names::mentions(after, bindings))
    }

    /// Expands a `for` dispatcher in execution order. Preserves leading initializer
    /// expressions and, if [`Self::keeps_setup`], the order and cursor assignments.
    fn unflatten_for(&self, for_statement: &ForStmt, after: Option<&[Stmt]>) -> Option<Stmt> {
        if is_true(for_statement.test.as_deref())
            && for_statement.update.is_none()
            && let Some(VarDeclOrExpr::Expr(initializer)) = &for_statement.init
            && let Expr::Seq(initializer) = &**initializer
            && let [prefix @ .., array_assignment, index_assignment] = initializer.exprs.as_slice()
            && let Some(order) = split_order(array_assignment)
            && let Some(index) = zero_index(index_assignment)
            && let Some(dispatcher) = Dispatcher::of(&for_statement.body)
            && dispatcher.array == order.array
            && dispatcher.index == index
        {
            let prefix = if self.keeps_setup(&dispatcher.bindings(), after) {
                &initializer.exprs[..]
            } else {
                prefix
            };
            flattened(&dispatcher, &order, prefix, for_statement.span)
        } else {
            None
        }
    }
}

impl VisitMut for UnflattenSwitches<'_> {
    /// A `for` dispatcher used directly as another statement's body has no following statement
    /// list to check.
    fn visit_mut_stmt(&mut self, statement: &mut Stmt) {
        statement.visit_mut_children_with(self);

        if let Stmt::For(for_statement) = statement
            && let Some(inlined) = self.unflatten_for(for_statement, None)
        {
            *statement = inlined;
            self.changed = true;
        }
    }

    fn visit_mut_stmts(&mut self, statements: &mut Vec<Stmt>) {
        // Unflatten statements below, where subsequent statements are available for analysis.
        for statement in statements.iter_mut() {
            statement.visit_mut_children_with(self);
        }

        let mut position = 0;
        while position < statements.len() {
            if let Stmt::For(for_statement) = &statements[position]
                && let Some(inlined) =
                    self.unflatten_for(for_statement, Some(&statements[position + 1..]))
            {
                statements[position] = inlined;
                self.changed = true;
            } else if let Stmt::While(loop_) = &statements[position]
                && is_true(Some(&loop_.test))
                && let Some(dispatcher) = Dispatcher::of(&loop_.body)
                && let Some(setup) = Setup::find(&statements[..position], &dispatcher)
                && let Some(inlined) = flattened(&dispatcher, &setup.order, &[], loop_.span)
            {
                let bindings = dispatcher.bindings();
                statements[position] = inlined;
                self.changed = true;
                // The setup only fed the loop, unless something after it reads the order or the
                // cursor.
                if !self.keeps_setup(&bindings, Some(&statements[position + 1..])) {
                    for index in setup.statements {
                        statements.remove(index);
                    }
                    position -= setup.statements.len();
                }
            }
            position += 1;
        }
    }
}

/// Finds `order = "...".split(...)` and `cursor = 0` by scanning backward from a `while`
/// dispatcher. Stops at any other reference to either binding.
struct Setup {
    order: SplitOrder,
    /// Positions of the two setup statements, last first.
    statements: [usize; 2],
}

impl Setup {
    fn find(preceding: &[Stmt], dispatcher: &Dispatcher) -> Option<Self> {
        let bindings = dispatcher.bindings();
        let mut order = None;
        let mut cursor = None;
        let backwards = preceding.iter().enumerate().rev();
        for (position, statement) in backwards {
            if let Stmt::Expr(statement) = statement
                && order.is_none()
                && let Some(split) = split_order(&statement.expr)
                && split.array == dispatcher.array
            {
                order = Some((split, position));
            } else if let Stmt::Expr(statement) = statement
                && cursor.is_none()
                && zero_index(&statement.expr).is_some_and(|index| index == dispatcher.index)
            {
                cursor = Some(position);
            } else if names::mentions(statement, &bindings) {
                return None;
            }
            if let Some(cursor) = cursor
                && let Some((order, order_position)) = order.take()
            {
                return Some(Self {
                    order,
                    statements: [cursor.max(order_position), cursor.min(order_position)],
                });
            }
        }
        None
    }
}

fn is_true(test: Option<&Expr>) -> bool {
    matches!(test, Some(Expr::Lit(Lit::Bool(value))) if value.value)
}

/// `array = "b|a".split("|")`: the case labels in execution order and their separator.
struct SplitOrder {
    array: Id,
    order: String,
    separator: String,
}

fn split_order(expression: &Expr) -> Option<SplitOrder> {
    if let Some((array, value)) = ast::assignment(expression)
        && let Some((order, [separator])) = ast::method_call(value, "split")
        && separator.spread.is_none()
        && let Some(order) = ast::static_str(order)
        && let Some(separator) = ast::static_str(&separator.expr)
        && !separator.is_empty()
    {
        Some(SplitOrder {
            array,
            order: order.to_owned(),
            separator: separator.to_owned(),
        })
    } else {
        None
    }
}

/// `cursor = 0`: the cursor binding.
fn zero_index(expression: &Expr) -> Option<Id> {
    let (index, value) = ast::assignment(expression)?;
    matches!(value, Expr::Lit(Lit::Num(value)) if value.value == 0.0).then_some(index)
}

/// A loop body `{ switch (order[cursor++]) { ... } break; }`.
struct Dispatcher<'body> {
    switch: &'body SwitchStmt,
    /// The syntax context of the loop body.
    context: SyntaxContext,
    array: Id,
    index: Id,
}

impl<'body> Dispatcher<'body> {
    fn of(body: &'body Stmt) -> Option<Self> {
        if let Stmt::Block(body) = body
            && let [Stmt::Switch(switch), Stmt::Break(break_statement)] = body.stmts.as_slice()
            && break_statement.label.is_none()
            && let Expr::Member(discriminant) = &*switch.discriminant
            && let Some(array) = discriminant.obj.as_ident()
            && let MemberProp::Computed(property) = &discriminant.prop
            && let Expr::Update(increment) = &*property.expr
            && increment.op == UpdateOp::PlusPlus
            && !increment.prefix
            && let Some(index) = increment.arg.as_ident()
        {
            Some(Self {
                switch,
                context: body.ctxt,
                array: array.to_id(),
                index: index.to_id(),
            })
        } else {
            None
        }
    }

    fn bindings(&self) -> [Id; 2] {
        [self.array.clone(), self.index.clone()]
    }
}

/// Orders case bodies after the leading loop initializer expressions. Returns `None` for
/// unsupported cases and missing or unused labels.
fn flattened(
    dispatcher: &Dispatcher,
    order: &SplitOrder,
    prefix: &[Box<Expr>],
    span: Span,
) -> Option<Stmt> {
    let mut cases = case_bodies(&dispatcher.switch.cases, &dispatcher.bindings())?;
    let mut statements: Vec<Stmt> = prefix
        .iter()
        .map(|expression| ast::expression_statement(expression.clone()))
        .collect();
    for label in order.order.split(&order.separator) {
        statements.extend(cases.remove(label)?);
    }
    cases.is_empty().then(|| {
        Stmt::Block(BlockStmt {
            span,
            ctxt: dispatcher.context,
            stmts: statements,
        })
    })
}

/// Maps case labels to their bodies. Each body must continue the dispatcher or exit execution
/// so the bodies can be concatenated. Rejects other jumps to the switch or dispatcher loop,
/// since those targets will be removed. Also rejects bodies that read the order or cursor,
/// whose values depend on the loop.
fn case_bodies(cases: &[SwitchCase], bindings: &[Id; 2]) -> Option<HashMap<String, Vec<Stmt>>> {
    if cases
        .iter()
        .any(|case| names::mentions(&case.cons, bindings))
    {
        return None;
    }
    let mut bodies = HashMap::default();
    for case in cases {
        let label = case.test.as_deref().and_then(ast::static_str)?.to_owned();
        let mut statements = case.cons.clone();
        let continues_loop = matches!(
            statements.last(),
            Some(Stmt::Continue(continue_statement)) if continue_statement.label.is_none()
        );
        if continues_loop {
            statements.pop();
        } else if !matches!(statements.last(), Some(Stmt::Return(_) | Stmt::Throw(_))) {
            return None;
        }
        let mut jumps = Jumps::default();
        statements.visit_with(&mut jumps);
        if jumps.leaves {
            return None;
        }
        bodies.insert(label, statements);
    }
    Some(bodies)
}

/// Detects jumps from case statements to enclosing constructs: unlabeled `break` or
/// `continue` without an internal target, or `continue` to an external label. Labeled `break`
/// remains valid because its target still encloses the expanded cases.
#[derive(Default)]
struct Jumps {
    /// Loops around the node, within the case.
    loops: usize,
    /// Loops and `switch` statements around the node, within the case.
    breakable: usize,
    /// Labels declared around the node, within the case.
    labels: HashSet<Atom>,
    leaves: bool,
}

impl Visit for Jumps {
    fn visit_stmt(&mut self, statement: &Stmt) {
        let depth = usize::from(matches!(
            statement,
            Stmt::For(_) | Stmt::ForIn(_) | Stmt::ForOf(_) | Stmt::While(_) | Stmt::DoWhile(_)
        ));
        self.loops += depth;
        self.breakable += depth;
        statement.visit_children_with(self);
        self.loops -= depth;
        self.breakable -= depth;
    }

    fn visit_break_stmt(&mut self, jump: &BreakStmt) {
        self.leaves |= jump.label.is_none() && self.breakable == 0;
    }

    fn visit_continue_stmt(&mut self, jump: &ContinueStmt) {
        self.leaves |= match &jump.label {
            Some(label) => !self.labels.contains(&label.sym),
            None => self.loops == 0,
        };
    }

    fn visit_labeled_stmt(&mut self, labeled: &LabeledStmt) {
        let added = self.labels.insert(labeled.label.sym.clone());
        labeled.body.visit_with(self);
        if added {
            self.labels.remove(&labeled.label.sym);
        }
    }

    fn visit_switch_stmt(&mut self, switch: &SwitchStmt) {
        switch.discriminant.visit_with(self);
        self.breakable += 1;
        switch.cases.visit_with(self);
        self.breakable -= 1;
    }

    // Functions and classes have jump targets of their own.
    fn visit_function(&mut self, _: &Function) {}

    fn visit_arrow_expr(&mut self, _: &ArrowExpr) {}

    fn visit_class(&mut self, _: &Class) {}
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    fn fixture(separator: &str) -> String {
        format!(
            r#"(function (order, cursor) {{
            for (order = "second{separator}first".split(`{separator}`), cursor = 0; true;) {{
                switch (order[cursor++]) {{
                    case "first": console.log("first"); continue;
                    case "second": console.log("second"); continue;
                }}
                break;
            }}
        }})();"#
        )
    }

    #[test]
    fn unflattens_for_and_while_dispatchers_in_execution_order() {
        let while_loop = r#"(function (order, cursor) {
                order = "second|first".split("|");
                unrelated();
                cursor = 0;
                true;
                while (true) {
                    switch (order[cursor++]) {
                        case "first": console.log("first"); continue;
                        case "second": console.log("second"); continue;
                    }
                    break;
                }
            })();"#;
        let output = testing::transform(while_loop);
        assert!(!output.contains("split"), "{output}");
        assert!(output.contains("unrelated()"), "{output}");
        for source in [
            fixture("|"),
            fixture(";"),
            fixture("::"),
            while_loop.to_owned(),
        ] {
            let output = testing::transform(&source);
            assert!(!output.contains("switch"), "{output}");
            assert!(
                output.find("console.log(\"second\")").unwrap()
                    < output.find("console.log(\"first\")").unwrap(),
                "{output}"
            );
        }
    }

    #[test]
    fn keeps_setups_read_later_and_loops_it_cannot_unflatten() {
        // Jumps that stay inside a case do not prevent unflattening.
        let output = testing::transform(&format!(
            "{} function g() {{ return 1; }}",
            fixture("|")
                .replace(
                    "console.log(\"first\");",
                    "for (;;) { if (g()) break; else continue; } console.log(\"first\");",
                )
                .replace(
                    "break;\n            }",
                    "break;\n            }\n            console.log(order);"
                )
        ));
        assert!(!output.contains("switch"), "{output}");
        assert!(output.contains("split"), "{output}");
        for source in [
            fixture("|").replace("order[cursor++]", "different[cursor++]"),
            fixture("|").replace("order[cursor++]", "order[++cursor]"),
            fixture("|").replace("order[cursor++]", "order[other++]"),
            fixture("|").replace("true;", "true; effect()"),
            fixture("|").replace(".split(`|`)", ".split(`|`, 1)"),
        ] {
            let output = testing::transform(&source);
            assert!(output.contains("switch"), "{output}");
        }
    }
}
