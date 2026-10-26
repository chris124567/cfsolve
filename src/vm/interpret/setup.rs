//! Initializes the VM's enclosing scope once before handler execution.

use std::mem;

use swc_core::atoms::Atom;
use swc_core::ecma::ast::{Expr, Pat, SimpleAssignTarget, Stmt, UpdateExpr, VarDeclarator};
use swc_core::ecma::visit::{Visit, VisitWith};

use super::run::{Frame, Run, Stop};
use crate::vm::HashMap;
use crate::vm::session::Session;
use crate::vm::value::{Env, Scope, Value};

/// Runs the enclosing scope's `prelude`, then the VM's setup `statements`. Returns setup
/// bindings and errors associated with names that interrupted statements may have written.
///
/// Setup can read prelude values, but handlers cannot assume they remain unchanged. Prelude
/// bindings and failures are therefore excluded from the session. Functions created during
/// setup use session bindings afterward.
#[must_use]
pub(crate) fn setup<'a>(
    session: &Session<'a>,
    prelude: &'a [Stmt],
    statements: &'a [Stmt],
) -> (HashMap<Atom, Value<'a>>, HashMap<Atom, String>) {
    let mut run = Run::new(session, &[], Vec::new(), None);
    let around = Env::scope(HashMap::default(), None);
    run.run_setup(around.clone(), prelude);
    run.unavailable.to_mut().clear();
    let own = Env::scope(HashMap::default(), Some(around.clone()));
    run.run_setup(own.clone(), statements);
    around.borrow_mut().variables.clear();
    let bindings = mem::take(&mut own.borrow_mut().variables);
    (bindings, run.unavailable.into_owned())
}

impl<'ast> Run<'ast, '_> {
    /// Runs setup `statements` in `scope`, which functions declared beside the class share until
    /// setup ends. Records the names interrupted statements may have written.
    fn run_setup(&mut self, scope: Scope<'ast>, statements: &'ast [Stmt]) {
        self.frames.push(Frame {
            this: Value::Undefined,
            scope: scope.clone(),
        });
        self.setup = Some(scope);
        for statement in statements {
            let mut written = Written::default();
            statement.visit_with(&mut written);
            match self.statement(statement) {
                Ok(_) => {
                    for name in written.0 {
                        self.unavailable.to_mut().remove(&name);
                    }
                }
                Err(stop) => {
                    let reason = match *stop {
                        Stop::Throw(value) => format!("it throws {}", value.expr()),
                        Stop::Unsupported(reason) => reason,
                    };
                    for name in written.0 {
                        // Global-object members are not tracked, so writes to them do not
                        // invalidate a tracked binding.
                        if let Ok(Value::Namespace(_)) = self.lookup(&name) {
                            continue;
                        }
                        self.frame().scope.borrow_mut().variables.remove(&name);
                        self.unavailable.to_mut().insert(name, reason.clone());
                    }
                }
            }
        }
    }
}

/// Names a statement may declare, assign, or mutate through property writes.
#[derive(Default)]
struct Written(Vec<Atom>);

impl Visit for Written {
    fn visit_var_declarator(&mut self, declarator: &VarDeclarator) {
        if let Pat::Ident(name) = &declarator.name {
            self.0.push(name.id.sym.clone());
        }
        declarator.visit_children_with(self);
    }

    fn visit_simple_assign_target(&mut self, target: &SimpleAssignTarget) {
        match target {
            SimpleAssignTarget::Ident(name) => self.0.push(name.id.sym.clone()),
            SimpleAssignTarget::Member(member) => self.root(&member.obj),
            _ => {}
        }
        target.visit_children_with(self);
    }

    fn visit_update_expr(&mut self, update: &UpdateExpr) {
        self.root(&update.arg);
        update.visit_children_with(self);
    }
}

impl Written {
    /// Returns the root name of a member-expression chain.
    fn root(&mut self, mut expr: &Expr) {
        loop {
            match expr {
                Expr::Ident(name) => return self.0.push(name.sym.clone()),
                Expr::Member(member) => expr = &member.obj,
                Expr::Paren(paren) => expr = &paren.expr,
                _ => return,
            }
        }
    }
}
