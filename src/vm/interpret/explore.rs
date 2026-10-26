//! Explores feasible paths through an instruction handler.

use std::mem;

use super::run::Run;
use crate::vm::HashMap;
use crate::vm::extract::{Handler, Operand};
use crate::vm::output::Path;
use crate::vm::session::Session;
use crate::vm::value::{Callable, Value};

/// Maximum symbolic branches explored per handler.
pub(crate) const MAXIMUM_PATHS: usize = 64;

/// One instruction's handler, ready to run.
pub(crate) struct Invocation<'session, 'ast> {
    pub session: &'session Session<'ast>,
    pub program: &'session [u8],
    /// The position after the opcode byte, where the operands start.
    pub pc: u32,
    /// The dispatch key the opcode byte leaves.
    pub key: u8,
    pub handler: &'session Handler<'ast>,
    /// The instance fields the constructor derives from the program.
    pub fields: &'session HashMap<String, Value<'ast>>,
    /// Registers whose values are known, such as a candidate string.
    pub known: &'session [(u8, Value<'ast>)],
}

#[derive(Default)]
pub(crate) struct Ways<'ast> {
    pub taken: Vec<Way<'ast>>,
    /// Exceptions from paths that rejected the instruction's operands.
    pub faults: Vec<String>,
}

pub(crate) struct Way<'ast> {
    pub path: Path,
    /// Final values of the instance fields this path read or wrote.
    pub fields: HashMap<String, Value<'ast>>,
}

/// Runs the handler for each feasible combination of symbolic branches, depth-first with true
/// before false. Returns `None` if there are more than [`MAXIMUM_PATHS`].
#[must_use]
pub(crate) fn explore<'ast>(invocation: &Invocation<'_, 'ast>) -> Option<Ways<'ast>> {
    let mut ways = Ways::default();
    let this = if invocation.handler.bound {
        Value::Machine
    } else {
        Value::Undefined
    };
    let arguments: Vec<Value<'_>> = invocation
        .handler
        .arguments
        .iter()
        .map(|operand| match *operand {
            Operand::Machine => Value::Machine,
            Operand::Number(number) => Value::Number(number),
        })
        .collect();
    let handler = Callable::Script {
        name: None,
        function: invocation.handler.function,
        scope: None,
    };
    let mut decisions = Vec::new();
    for _ in 0..MAXIMUM_PATHS {
        let mut run = Run::handler(invocation, decisions);
        let outcome = run.invoke(&handler, this.clone(), arguments.clone());
        decisions = mem::take(&mut run.branches.decisions);
        decisions.truncate(run.branches.decided);
        let scopes = run.scopes();
        let fields = mem::take(&mut run.fields);
        let way = run.finish(outcome);
        // Clear captured scopes to break cycles between functions and the scopes holding them.
        for scope in scopes {
            scope.borrow_mut().variables.clear();
        }
        match way {
            Ok(path) => ways.taken.push(Way { path, fields }),
            Err(fault) => ways.faults.push(fault),
        }
        // Retry the last branch taken as `true` that has not yet been tried as `false`.
        while decisions.last() == Some(&false) {
            decisions.pop();
        }
        match decisions.last_mut() {
            Some(last) => *last = false,
            None => return Some(ways),
        }
    }
    None
}
