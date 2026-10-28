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

use swc_core::ecma::ast::{
    ArrowExpr, AssignOp, BinaryOp, BreakStmt, ContinueStmt, Expr, Function, Id, Program, Stmt,
    SwitchStmt, WhileStmt,
};
use swc_core::ecma::visit::{Visit, VisitMut, VisitMutWith, VisitWith};

use super::HashSet;
use super::analysis::{Analysis, Bindings};
use crate::js::ast;

pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    let mut unroll = Unroll {
        bindings: analysis.bindings(program),
        changed: false,
    };
    program.visit_mut_with(&mut unroll);
    unroll.changed
}

struct Unroll<'bindings> {
    bindings: &'bindings Bindings,
    changed: bool,
}

/// Returns the value assigned to `state` by `expression`, including chained assignments such as `x
/// = state = 1`.
fn assigned(expression: &Expr, state: &Id) -> Option<f64> {
    let assignment = expression
        .as_assign()
        .filter(|assignment| assignment.op == AssignOp::Assign)?;
    match assignment.left.as_ident() {
        Some(left) if left.to_id() == *state => ast::number(&assignment.right),
        _ => assigned(&assignment.right, state),
    }
}

impl Unroll<'_> {
    /// Returns the statements executed by `while (state !== exit) switch (state) { ... }`, in
    /// execution order, starting with the state set by `initial`.
    fn unrolled(&self, initial: &Stmt, machine: &Stmt) -> Option<Vec<Stmt>> {
        let Stmt::While(WhileStmt { test, body, .. }) = machine else {
            return None;
        };
        let test = test.unwrap_parens().as_bin()?;
        if !matches!(test.op, BinaryOp::NotEqEq | BinaryOp::NotEq) {
            return None;
        }
        let (state, exit) = match (test.left.as_ident(), test.right.as_ident()) {
            (Some(state), None) => (state.to_id(), ast::number(&test.right)?),
            (None, Some(state)) => (state.to_id(), ast::number(&test.left)?),
            _ => return None,
        };
        let switch = match body.as_ref() {
            Stmt::Switch(switch) => switch,
            Stmt::Block(block) => match &block.stmts[..] {
                [Stmt::Switch(switch)] => switch,
                _ => return None,
            },
            _ => return None,
        };
        // Only the loop test and the switch read the state.
        if switch.discriminant.unwrap_parens().as_ident()?.to_id() != state
            || self.bindings.references(&state) != 2
        {
            return None;
        }
        let mut current = assigned(&initial.as_expr()?.expr, &state)?;
        let labels = switch
            .cases
            .iter()
            .map(|case| ast::number(case.test.as_deref()?))
            .collect::<Option<Vec<f64>>>()?;
        let mut statements = vec![];
        let mut seen = HashSet::default();
        while current != exit {
            let index = labels.iter().position(|&label| label == current)?;
            if !seen.insert(index) {
                return None;
            }
            let [
                body @ ..,
                Stmt::Expr(transition),
                Stmt::Break(BreakStmt { label: None, .. }),
            ] = &switch.cases[index].cons[..]
            else {
                return None;
            };
            let (target, next) = ast::assignment(&transition.expr)?;
            if target != state || escapes(body) {
                return None;
            }
            current = ast::number(next)?;
            statements.extend(body.iter().cloned());
        }
        Some(statements)
    }
}

impl VisitMut for Unroll<'_> {
    fn visit_mut_stmts(&mut self, statements: &mut Vec<Stmt>) {
        statements.visit_mut_children_with(self);
        for index in 1..statements.len() {
            if let Some(unrolled) = self.unrolled(&statements[index - 1], &statements[index]) {
                statements[index] = ast::block(unrolled);
                self.changed = true;
            }
        }
    }
}

/// Checks for a `break` or `continue` targeting an enclosing loop or switch.
pub(super) fn escapes(body: &[Stmt]) -> bool {
    let mut jumps = Jumps::default();
    body.visit_with(&mut jumps);
    jumps.escapes
}

/// Finds unlabeled jumps not caught by a nested loop or switch.
#[derive(Default)]
struct Jumps {
    loops: usize,
    switches: usize,
    escapes: bool,
}

impl Visit for Jumps {
    fn visit_stmt(&mut self, statement: &Stmt) {
        let depth = usize::from(matches!(
            statement,
            Stmt::For(_) | Stmt::ForIn(_) | Stmt::ForOf(_) | Stmt::While(_) | Stmt::DoWhile(_)
        ));
        self.loops += depth;
        statement.visit_children_with(self);
        self.loops -= depth;
    }

    fn visit_break_stmt(&mut self, jump: &BreakStmt) {
        self.escapes |= jump.label.is_none() && self.loops == 0 && self.switches == 0;
    }

    fn visit_continue_stmt(&mut self, jump: &ContinueStmt) {
        self.escapes |= jump.label.is_none() && self.loops == 0;
    }

    fn visit_switch_stmt(&mut self, switch: &SwitchStmt) {
        self.switches += 1;
        switch.visit_children_with(self);
        self.switches -= 1;
    }

    // Jumps cannot leave a function.
    fn visit_function(&mut self, _: &Function) {}

    fn visit_arrow_expr(&mut self, _: &ArrowExpr) {}
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn unrolls_constant_transitions_from_the_initial_state() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
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
        testing::assert_contains(&output, &[], &["k = s = 2; { a(); for(;;)"]);
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
