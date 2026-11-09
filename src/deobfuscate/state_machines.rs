//! Restores blocks that a state machine runs in a fixed order:
//!
//! ```js
//! state = 1;
//! while (state !== -1) switch (state) {
//!     case 0: b(); state = -1; break;
//!     case 1: a(); state = 0; break;
//! }
//! // becomes
//! state = 1;
//! { a(); b(); }
//! ```
//!
//! The statement before the loop must set a constant initial state. Case labels must be
//! constant, with no default. Follow cases from the initial state to the exit state; each
//! must end by assigning a constant next state, and no case may repeat.
//!
//! Leave the loop unchanged if anything else reads the state or if a jump exits a case before
//! its final `break`.

use oxc::allocator::{CloneIn, GetAllocator, Vec as ArenaVec};
use oxc::ast::ast::{Expression, Program, Statement};
use oxc::ast_visit::{VisitMut, walk_mut};
use oxc::span::GetSpan;
use oxc::syntax::operator::{AssignmentOperator, BinaryOperator};

use super::analysis::{Analysis, Id};
use super::{HashSet, ast};

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let mut unroll = Unroll {
        analysis,
        changed: false,
    };
    unroll.visit_program(program);
    unroll.changed
}

/// Returns the constant that `expression` assigns to `id`, possibly through a chain such as
/// `k = state = 2`.
fn initial_state(expression: &Expression<'_>, id: Id, analysis: &Analysis<'_>) -> Option<f64> {
    let Expression::AssignmentExpression(assignment) = expression.get_inner_expression() else {
        return None;
    };
    if assignment.operator != AssignmentOperator::Assign {
        return None;
    }
    if analysis.target_id(&assignment.left) == Some(id) {
        ast::number(&assignment.right)
    } else {
        initial_state(&assignment.right, id, analysis)
    }
}

struct Unroll<'b, 'a> {
    analysis: &'b Analysis<'a>,
    changed: bool,
}

impl<'a> Unroll<'_, 'a> {
    /// Returns the case bodies that `machine` runs after `initial` sets its state.
    fn unroll(
        &self,
        initial: &Statement<'a>,
        machine: &Statement<'a>,
    ) -> Option<ArenaVec<'a, Statement<'a>>> {
        let analysis = self.analysis;
        let Statement::WhileStatement(machine) = machine else {
            return None;
        };
        let Expression::BinaryExpression(test) = machine.test.get_inner_expression() else {
            return None;
        };
        if !matches!(
            test.operator,
            BinaryOperator::Inequality | BinaryOperator::StrictInequality
        ) {
            return None;
        }
        let (id, exit) = match analysis.expression_id(&test.left) {
            Some(id) => (id, ast::number(&test.right)?),
            None => (
                analysis.expression_id(&test.right)?,
                ast::number(&test.left)?,
            ),
        };
        let switch = match &machine.body {
            Statement::SwitchStatement(switch) => switch,
            Statement::BlockStatement(block) => match block.body.as_slice() {
                [Statement::SwitchStatement(switch)] => switch,
                _ => return None,
            },
            _ => return None,
        };
        if analysis.expression_id(&switch.discriminant) != Some(id)
            || analysis.bindings.references(&id) != 2
        {
            return None;
        }
        let Statement::ExpressionStatement(initial) = initial else {
            return None;
        };
        let mut state = initial_state(&initial.expression, id, analysis)?;
        let labels: Vec<f64> = switch
            .cases
            .iter()
            .map(|case| ast::number(case.test.as_ref()?))
            .collect::<Option<_>>()?;
        let mut seen = HashSet::default();
        let mut unrolled = ArenaVec::new_in(analysis);
        while state != exit {
            let index = labels.iter().position(|&label| label == state)?;
            if !seen.insert(index) {
                return None;
            }
            let [
                body @ ..,
                Statement::ExpressionStatement(transition),
                Statement::BreakStatement(jump),
            ] = switch.cases[index].consequent.as_slice()
            else {
                return None;
            };
            if jump.label.is_some() || ast::escapes(body, ast::LabeledContinue::Any) {
                return None;
            }
            let (target, next) = analysis.assignment(&transition.expression)?;
            if target != id {
                return None;
            }
            state = ast::number(next)?;
            let allocator = analysis.allocator();
            unrolled.extend(
                body.iter()
                    .map(|statement| statement.clone_in_with_semantic_ids(allocator)),
            );
        }
        Some(unrolled)
    }
}

impl<'a> VisitMut<'a> for Unroll<'_, 'a> {
    fn visit_statements(&mut self, statements: &mut ArenaVec<'a, Statement<'a>>) {
        walk_mut::walk_statements(self, statements);
        for index in 1..statements.len() {
            if let Some(unrolled) = self.unroll(&statements[index - 1], &statements[index]) {
                let span = statements[index].span();
                statements[index] = Statement::new_block_statement(span, unrolled, self.analysis);
                self.changed = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn unrolls_constant_transitions_from_the_initial_state() {
        let transform = |source: &str| testing::rewrite(source, super::run);
        let machine = |cases: &str, after: &str| {
            format!(
                "function f() {{ var s, k; k = s = 2; while (-1 !== s) switch (s) {{ {cases} }} {after} }}"
            )
        };
        let output = transform(&machine(
            "case 0: c(); s = -1; break;
             case 1: for (;;) { if (d()) break; continue; } s = 0; break;
             case 2: a(); s = 1; break;
             case 3: dead(); s = 0; break;",
            "",
        ));
        testing::assert_contains(&output, &["k = s = 2; { a(); for(;;)"]);
        testing::assert_lacks(&output, &["switch", "dead", "s = 1", "s = -1"]);
        for kept in [
            // Reject cycles, missing cases, early breaks, continues, and extra reads of the state.
            machine("case 2: a(); s = 2; break;", ""),
            machine("case 2: a(); s = 4; break;", ""),
            machine("case 2: if (a()) break; s = -1; break;", ""),
            machine("case 2: if (a()) continue; s = -1; break;", ""),
            machine("case 2: a(); s = -1; break;", "g(s);"),
            machine(
                "case 2: a(); s = b() ? 0 : -1; break; case 0: s = -1; break;",
                "",
            ),
            machine("case 2: a(); s = -1; break; default: b();", ""),
        ] {
            let output = transform(&kept);
            assert!(output.contains("switch"), "{output}");
        }
    }
}
