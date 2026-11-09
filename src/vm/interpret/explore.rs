//! Explores feasible paths through an instruction handler.

use std::{mem, ptr};

use oxc::ast::ast::Function;

use super::copies::Copies;
use super::intrinsic;
use super::plan::Routine;
use super::run::{Decrypted, Run, Snapshot, Stop};
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
    pub handler: &'ast Function<'ast>,
    /// The instance fields the constructor derives from the program.
    pub fields: &'session HashMap<String, Value<'ast>>,
    /// Strings decrypted from the program so far.
    pub decrypted: &'session Decrypted<'ast>,
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
///
/// Paths that differ only after the top-level statement where the handler's first branch was
/// seen resume from a [`Snapshot`] taken before it rather than rerunning the whole handler.
/// Each path still sees exactly the state a rerun would.
#[must_use]
pub(crate) fn explore<'ast>(invocation: &Invocation<'_, 'ast>) -> Option<Ways<'ast>> {
    let session = invocation.session;
    let handler = invocation.handler;
    let address = intrinsic::address(handler);
    // `Run::script` runs these natively or caches them, rather than through a slot plan.
    let special = session.intrinsics.contains_key(&address)
        || session
            .record_decoder
            .is_some_and(|decoder| ptr::eq(decoder, handler));
    let plan = if special {
        None
    } else {
        Routine::function(handler)
            .and_then(|routine| session.compiled.slots(session.script, routine))
    };
    // A run that thaws a shared session object leaves no results; explore again with the
    // object copied.
    'explore: loop {
        let branching = session
            .branching
            .borrow()
            .get(&address)
            .copied()
            .unwrap_or_default();
        // Snapshots usually repay their copying only for handlers whose instructions have
        // averaged at least 1.5 runs.
        let split = branching
            .statement
            .filter(|&statement| statement > 0 && 2 * branching.runs >= 3 * branching.instructions);
        let mut ways = Ways::default();
        let mut decisions = Vec::new();
        let mut snapshot: Option<Snapshot<'ast>> = None;
        for _ in 0..MAXIMUM_PATHS {
            let resumed = snapshot
                .as_ref()
                .filter(|snapshot| snapshot.resumes(&decisions));
            let (mut run, outcome, copied) = match (plan.as_deref(), resumed) {
                (Some(plan), Some(snapshot)) => {
                    let (mut run, mut locals, copied) =
                        Run::resume(invocation, snapshot, decisions);
                    // Snapshot locals are dropped rather than returned to the spare buffers.
                    let outcome = run.handler_statements(
                        plan,
                        snapshot.statement,
                        &mut locals,
                        &mut |_, _, _| {},
                    );
                    (run, outcome, copied)
                }
                (Some(plan), None) => {
                    let mut run = Run::handler(invocation, decisions);
                    let mut taken = None;
                    // The last top-level statement started before any decision was consumed.
                    let mut undecided = None;
                    let outcome = run.call_handler(
                        plan,
                        Value::Undefined,
                        vec![Value::Machine],
                        &mut |run, statement, locals| {
                            if run.branches.decided == 0 {
                                undecided = Some(statement);
                            }
                            if split == Some(statement) {
                                taken = run.snapshot(statement, locals);
                            }
                        },
                    );
                    if branching.statement.is_none()
                        && !run.thawed
                        && run.branches.decided > 0
                        && let Some(statement) = undecided
                    {
                        let mut learned = session.branching.borrow_mut();
                        learned
                            .entry(address)
                            .or_default()
                            .statement
                            .get_or_insert(statement);
                    }
                    snapshot = taken;
                    (run, outcome, Vec::new())
                }
                (None, _) => {
                    let mut run = Run::handler(invocation, decisions);
                    let handler = Callable::Script {
                        name: None,
                        function: handler,
                        scope: None,
                    };
                    let outcome = run.invoke(&handler, Value::Undefined, vec![Value::Machine]);
                    (run, outcome, Vec::new())
                }
            };
            decisions = mem::take(&mut run.branches.decisions);
            decisions.truncate(run.branches.decided);
            let thawed = run.thawed;
            let scopes = run.scopes();
            let fields = mem::take(&mut run.fields);
            let way = run.finish(outcome);
            // Clear captured scopes to break cycles between functions and the scopes holding
            // them.
            for scope in scopes.into_iter().chain(copied) {
                scope.borrow_mut().variables.clear();
            }
            if thawed {
                continue 'explore;
            }
            match way {
                Ok(path) => ways.taken.push(Way { path, fields }),
                Err(fault) => ways.faults.push(fault),
            }
            // Retry the last branch taken as `true` that has not yet been tried as `false`.
            while decisions.last() == Some(&false) {
                decisions.pop();
            }
            let Some(last) = decisions.last_mut() else {
                let mut learned = session.branching.borrow_mut();
                let learned = learned.entry(address).or_default();
                learned.instructions += 1;
                learned.runs += ways.taken.len() + ways.faults.len();
                return Some(ways);
            };
            *last = false;
        }
        break None;
    }
}

/// What exploration has learned about a handler's paths.
#[derive(Clone, Copy, Default)]
pub(crate) struct Branching {
    /// The top-level statement where its first decision was seen.
    statement: Option<usize>,
    /// Instructions explored.
    instructions: usize,
    /// Runs the explored instructions took.
    runs: usize,
}

/// Runs `decoder` after setting the program counter and dispatch key registers. Returns the decoded
/// opcode and updated key, or the reason execution stopped.
pub(crate) fn decode<'ast>(
    session: &Session<'ast>,
    program: &[u8],
    decoder: Routine<'ast>,
    arguments: Vec<Value<'ast>>,
    pc: u32,
    key: u8,
) -> Result<Decoded, String> {
    // A run that thaws a shared session object decodes again with the object copied.
    let (outcome, next) = loop {
        let mut run = Run::new(session, program, Vec::new(), Some(Copies::default()));
        run.sharing = true;
        run.start_at(pc, key);
        let outcome = run.routine(decoder, None, Value::Undefined, arguments.clone());
        let next = run.register_value(session.layout.key);
        for scope in run.scopes() {
            scope.borrow_mut().variables.clear();
        }
        if !run.thawed {
            break (outcome, next);
        }
    };
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
