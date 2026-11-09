//! Initializes the VM's enclosing scope once before handler execution.

use std::mem;

use oxc::ast::ast::{
    AssignmentExpression, BindingPattern, Expression, SimpleAssignmentTarget, Statement,
    UpdateExpression, VariableDeclarator,
};
use oxc::ast_visit::{Visit, walk};

use super::run::{CallScope, Frame, Run, Stop};
use crate::js::ast::{Binding, Script};
use crate::vm::HashMap;
use crate::vm::session::Session;
use crate::vm::value::{Env, Scope, Value};

/// Runs the enclosing scope's `prelude`, then the VM's setup `statements`. Returns setup
/// bindings and errors associated with bindings that interrupted statements may have written.
///
/// Setup can read prelude values, but handlers cannot assume they remain unchanged. Prelude
/// bindings and failures are therefore excluded from the session. Functions created during
/// setup use session bindings afterward.
#[must_use]
pub(crate) fn setup<'a>(
    session: &Session<'a>,
    prelude: &[&'a Statement<'a>],
    statements: &'a [Statement<'a>],
) -> (
    HashMap<Binding<'a>, Value<'a>>,
    HashMap<Binding<'a>, String>,
) {
    let mut run = Run::new(session, &[], Vec::new(), None);
    let around = Env::scope(HashMap::default(), None);
    run.run_setup(around.clone(), prelude.iter().copied());
    run.unavailable.to_mut().clear();
    let own = Env::scope(HashMap::default(), Some(around.clone()));
    run.run_setup(own.clone(), statements);
    around.borrow_mut().variables.clear();
    let bindings = mem::take(&mut own.borrow_mut().variables);
    (bindings, run.unavailable.into_owned())
}

impl<'ast> Run<'ast, '_> {
    /// Runs setup `statements` in `scope`, which functions declared beside the class share until
    /// setup ends. Records the bindings interrupted statements may have written.
    fn run_setup(
        &mut self,
        scope: Scope<'ast>,
        statements: impl IntoIterator<Item = &'ast Statement<'ast>>,
    ) {
        self.frames.push(Frame {
            this: Value::Undefined,
            scope: CallScope::Own(scope.clone()),
        });
        self.setup = Some(scope);
        for statement in statements {
            let mut written = Written {
                script: self.session.script,
                bindings: Vec::new(),
            };
            written.visit_statement(statement);
            match self.statement(statement) {
                Ok(_) => {
                    for binding in written.bindings {
                        self.unavailable.to_mut().remove(&binding);
                    }
                }
                Err(stop) => {
                    let reason = match *stop {
                        Stop::Throw(value) => format!("it throws {}", value.expr()),
                        Stop::Unsupported(reason) => reason,
                    };
                    for binding in written.bindings {
                        // Global-object members are not tracked, so writes to them do not
                        // invalidate a tracked binding.
                        if let Ok(Value::Namespace(_)) = self.lookup(binding) {
                            continue;
                        }
                        self.frame_mut()
                            .own_scope()
                            .borrow_mut()
                            .variables
                            .remove(&binding);
                        self.unavailable.to_mut().insert(binding, reason.clone());
                    }
                }
            }
        }
    }
}

/// Bindings a statement may declare, assign, or mutate through property writes.
struct Written<'a> {
    script: Script<'a>,
    bindings: Vec<Binding<'a>>,
}

impl<'a> Visit<'a> for Written<'a> {
    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        if let BindingPattern::BindingIdentifier(name) = &declarator.id {
            self.bindings.push(Binding::Symbol(name.symbol_id()));
        }
        walk::walk_variable_declarator(self, declarator);
    }

    fn visit_assignment_expression(&mut self, assignment: &AssignmentExpression<'a>) {
        if let Some(target) = assignment.left.as_simple_assignment_target() {
            self.target(target);
        }
        walk::walk_assignment_expression(self, assignment);
    }

    fn visit_update_expression(&mut self, update: &UpdateExpression<'a>) {
        self.target(&update.argument);
        walk::walk_update_expression(self, update);
    }
}

impl<'a> Written<'a> {
    /// Records an assigned name, or the root of an assigned member.
    fn target(&mut self, target: &SimpleAssignmentTarget<'a>) {
        match target {
            SimpleAssignmentTarget::AssignmentTargetIdentifier(name) => {
                self.bindings.push(self.script.binding(name));
            }
            target => {
                if let Some(member) = target.as_member_expression() {
                    self.root(member.object());
                }
            }
        }
    }

    /// Records the binding at the root of a member-expression chain.
    fn root(&mut self, mut expression: &Expression<'a>) {
        loop {
            match expression {
                Expression::Identifier(name) => {
                    return self.bindings.push(self.script.binding(name));
                }
                Expression::ParenthesizedExpression(paren) => expression = &paren.expression,
                other => match other.as_member_expression() {
                    Some(member) => expression = member.object(),
                    None => return,
                },
            }
        }
    }
}
