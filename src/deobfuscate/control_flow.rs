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

use oxc::allocator::{CloneIn, GetAllocator, Vec};
use oxc::ast::ast::{
    Expression, ForStatement, Program, SimpleAssignmentTarget, Statement, SwitchStatement,
};
use oxc::ast_visit::{VisitMut, walk_mut};
use oxc::span::Span;
use oxc::syntax::operator::UpdateOperator;

use super::analysis::{Analysis, Id};
use super::ast::LabeledContinue;
use super::{HashMap, ast};

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let mut unflatten = Unflatten {
        analysis,
        changed: false,
    };
    unflatten.visit_program(program);
    unflatten.changed
}

/// `array = "b|a".split("|")`: the case labels in execution order and their separator.
struct Order<'a> {
    id: Id,
    order: &'a str,
    separator: &'a str,
}

fn order<'a>(expression: &Expression<'a>, analysis: &Analysis<'a>) -> Option<Order<'a>> {
    let (id, value) = analysis.assignment(expression)?;
    let (order, [separator]) = ast::method_call(value, "split")? else {
        return None;
    };
    let separator = ast::static_str(separator.as_expression()?)?;
    if separator.is_empty() {
        return None;
    }
    Some(Order {
        id,
        order: ast::static_str(order)?,
        separator,
    })
}

/// Matches `cursor = 0` and returns the cursor binding.
fn zero(expression: &Expression<'_>, analysis: &Analysis<'_>) -> Option<Id> {
    let Expression::AssignmentExpression(assignment) = expression.get_inner_expression() else {
        return None;
    };
    if ast::number(&assignment.right) != Some(0.0) {
        return None;
    }
    analysis.target_id(&assignment.left)
}

/// A loop body `{ switch (order[cursor++]) { ... } break; }` and its setup bindings.
struct Dispatcher<'b, 'a> {
    switch: &'b SwitchStatement<'a>,
    array: Id,
    index: Id,
}

impl Dispatcher<'_, '_> {
    fn setup(&self) -> [Id; 2] {
        [self.array, self.index]
    }
}

fn dispatcher<'b, 'a>(
    body: &'b Statement<'a>,
    analysis: &Analysis<'a>,
) -> Option<Dispatcher<'b, 'a>> {
    let Statement::BlockStatement(block) = body else {
        return None;
    };
    let [
        Statement::SwitchStatement(switch),
        Statement::BreakStatement(jump),
    ] = block.body.as_slice()
    else {
        return None;
    };
    if jump.label.is_some() {
        return None;
    }
    let Expression::ComputedMemberExpression(member) = switch.discriminant.get_inner_expression()
    else {
        return None;
    };
    let Expression::UpdateExpression(update) = member.expression.get_inner_expression() else {
        return None;
    };
    if update.operator != UpdateOperator::Increment || update.prefix {
        return None;
    }
    let SimpleAssignmentTarget::AssignmentTargetIdentifier(index) = &update.argument else {
        return None;
    };
    Some(Dispatcher {
        switch,
        array: analysis.expression_id(&member.object)?,
        index: analysis.id(index)?,
    })
}

/// Orders case bodies after any initializer prefix. Each case must continue the dispatcher or
/// return/throw, with no other jump to the removed loop or switch. Rejects bodies mentioning the
/// order or cursor, repeated or missing labels, and labels left unused by the order string.
fn flatten<'a>(
    dispatcher: &Dispatcher<'_, 'a>,
    order: &Order<'a>,
    prefix: &[Expression<'a>],
    span: Span,
    analysis: &Analysis<'a>,
) -> Option<Statement<'a>> {
    let allocator = analysis.allocator();
    let mut cases = HashMap::default();
    for case in &dispatcher.switch.cases {
        if ast::mentions(&case.consequent, &dispatcher.setup(), analysis) {
            return None;
        }
        let label = ast::static_str(case.test.as_ref()?)?;
        let mut body = case.consequent.clone_in_with_semantic_ids(allocator);
        match body.last() {
            Some(Statement::ContinueStatement(jump)) if jump.label.is_none() => {
                body.pop();
            }
            Some(last) if ast::abrupt(last, false) => {}
            _ => return None,
        }
        if ast::escapes(&body, LabeledContinue::Inner) || cases.insert(label, body).is_some() {
            return None;
        }
    }
    let mut flattened = Vec::new_in(analysis);
    for expression in prefix {
        let expression = expression.clone_in_with_semantic_ids(allocator);
        flattened.push(ast::expression_statement(expression, &analysis.ast))
    }
    for label in order.order.split(order.separator) {
        flattened.extend(cases.remove(label)?)
    }
    cases
        .is_empty()
        .then(|| Statement::new_block_statement(span, flattened, analysis))
}

struct Unflatten<'b, 'a> {
    analysis: &'b Analysis<'a>,
    changed: bool,
}

impl<'a> Unflatten<'_, 'a> {
    /// Keeps dispatcher setup when references after the loop may still need the order or cursor.
    fn keeps_setup(
        &self,
        dispatcher: &Dispatcher<'_, 'a>,
        after: Option<&[Statement<'a>]>,
    ) -> bool {
        let setup = dispatcher.setup();
        setup
            .iter()
            .any(|id| self.analysis.bindings.references(id) > 1)
            && after.is_none_or(|after| ast::mentions(after, &setup, self.analysis))
    }

    /// Expands a `for` dispatcher, preserving initializer prefixes and any setup still needed
    /// afterwards.
    fn for_loop(
        &self,
        for_loop: &ForStatement<'a>,
        after: Option<&[Statement<'a>]>,
    ) -> Option<Statement<'a>> {
        let test = for_loop.test.as_ref().and_then(ast::truthiness);
        if for_loop.update.is_some() || test != Some(true) {
            return None;
        }
        let Expression::SequenceExpression(init) = for_loop
            .init
            .as_ref()?
            .as_expression()?
            .get_inner_expression()
        else {
            return None;
        };
        let [prefix @ .., array, index] = init.expressions.as_slice() else {
            return None;
        };
        let order = order(array, self.analysis)?;
        let index = zero(index, self.analysis)?;
        let dispatcher = dispatcher(&for_loop.body, self.analysis)?;
        if dispatcher.array != order.id || dispatcher.index != index {
            return None;
        }
        let prefix = if self.keeps_setup(&dispatcher, after) {
            &init.expressions
        } else {
            prefix
        };
        flatten(&dispatcher, &order, prefix, for_loop.span, self.analysis)
    }

    /// Expands a `while (true)` dispatcher at `position`, removing its setup unless later
    /// statements still need it, and returns the expansion's new position.
    fn while_loop(
        &mut self,
        statements: &mut Vec<'a, Statement<'a>>,
        position: usize,
    ) -> Option<usize> {
        let analysis = self.analysis;
        let Statement::WhileStatement(while_loop) = &statements[position] else {
            return None;
        };
        if ast::truthiness(&while_loop.test) != Some(true) {
            return None;
        }
        let dispatcher = dispatcher(&while_loop.body, analysis)?;
        let setup = dispatcher.setup();
        let mut setup_order = None;
        let mut setup_index = None;
        for earlier in (0..position).rev() {
            let expression = match &statements[earlier] {
                Statement::ExpressionStatement(statement) => Some(&statement.expression),
                _ => None,
            };
            if let Some(expression) = expression
                && setup_order.is_none()
                && let Some(order) = order(expression, analysis)
                && order.id == dispatcher.array
            {
                setup_order = Some((earlier, order));
            } else if let Some(expression) = expression
                && setup_index.is_none()
                && zero(expression, analysis) == Some(dispatcher.index)
            {
                setup_index = Some(earlier)
            } else if ast::mentions(&statements[earlier..=earlier], &setup, analysis) {
                break;
            }
            if setup_order.is_some() && setup_index.is_some() {
                break;
            }
        }
        let ((order_position, order), index_position) = (setup_order?, setup_index?);
        let flattened = flatten(&dispatcher, &order, &[], while_loop.span, analysis)?;
        let keep = self.keeps_setup(&dispatcher, Some(&statements[position + 1..]));
        statements[position] = flattened;
        self.changed = true;
        if keep {
            return Some(position);
        }
        statements.remove(order_position.max(index_position));
        statements.remove(order_position.min(index_position));
        Some(position - 2)
    }
}

impl<'a> VisitMut<'a> for Unflatten<'_, 'a> {
    fn visit_statement(&mut self, statement: &mut Statement<'a>) {
        walk_mut::walk_statement(self, statement);
        if let Statement::ForStatement(for_loop) = statement
            && let Some(flattened) = self.for_loop(for_loop, None)
        {
            *statement = flattened;
            self.changed = true;
        }
    }

    fn visit_statements(&mut self, statements: &mut Vec<'a, Statement<'a>>) {
        for statement in statements.iter_mut() {
            walk_mut::walk_statement(self, statement)
        }
        let mut position = 0;
        while position < statements.len() {
            if let Statement::ForStatement(for_loop) = &statements[position] {
                let after = &statements[position + 1..];
                if let Some(flattened) = self.for_loop(for_loop, Some(after)) {
                    statements[position] = flattened;
                    self.changed = true;
                }
            } else if let Some(expanded) = self.while_loop(statements, position) {
                position = expanded;
            }
            position += 1;
        }
    }
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
