//! Explores feasible paths through an instruction handler.

use std::mem;

use swc_core::ecma::ast::Function;

use super::copies::Copies;
use super::run::{Run, Stop};
use crate::vm::dispatch::Decoded;
use crate::vm::output::Path;
use crate::vm::session::Session;
use crate::vm::value::{Callable, Value};
use crate::vm::{HashMap, convert};

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
    pub handler: &'ast Function,
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
    let handler = Callable::Script {
        name: None,
        function: invocation.handler,
        scope: None,
    };
    let mut decisions = Vec::new();
    for _ in 0..MAXIMUM_PATHS {
        let mut run = Run::handler(invocation, decisions);
        let outcome = run.invoke(&handler, Value::Undefined, vec![Value::Machine]);
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

/// Runs `decoder` after setting the program counter and dispatch key registers. Returns the decoded
/// opcode and updated key, or the reason execution stopped.
pub(crate) fn decode<'ast>(
    session: &Session<'ast>,
    program: &[u8],
    decoder: &'ast Function,
    arguments: Vec<Value<'ast>>,
    pc: u32,
    key: u8,
) -> Result<Decoded, String> {
    let mut run = Run::new(session, program, Vec::new(), Some(Copies::default()));
    run.start_at(pc, key);
    let decoder = Callable::Script {
        name: None,
        function: decoder,
        scope: None,
    };
    let outcome = run.invoke(&decoder, Value::Undefined, arguments);
    let next = run.register_value(session.layout.key);
    for scope in run.scopes() {
        scope.borrow_mut().variables.clear();
    }
    let opcode = outcome.map_err(|stop| match *stop {
        Stop::Throw(value) => format!("throws {}", value.expr()),
        Stop::Unsupported(reason) => reason,
    })?;
    let byte = |value: &Value<'_>| value.number().and_then(convert::byte);
    match (byte(&opcode), byte(&next)) {
        (Some(opcode), Some(key)) => Ok(Decoded { opcode, key }),
        _ => Err(format!(
            "decoding leaves opcode {} and key {}",
            opcode.expr(),
            next.expr()
        )),
    }
}
