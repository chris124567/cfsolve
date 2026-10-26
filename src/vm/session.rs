//! VM state initialized from the script before any program runs: setup bindings, register
//! layout, instance fields, and opcode handlers. [`Session::constructed`] adds the constructor
//! fields that depend on a program.
//!
//! Handler runs copy mutable values (see [`super::interpret`]); only deterministic decoded
//! strings ([`Session::decoded`]) and lazily compiled plans are cached across runs.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use anyhow::{Context, Result, bail, ensure};
use swc_core::atoms::Atom;
use swc_core::ecma::ast::{
    AssignTarget, BinaryOp, BlockStmt, Class, Expr, Function, MemberProp, SimpleAssignTarget, Stmt,
};

use super::extract::{self, Handler, StateFields};
use super::interpret::{self, Plans, Run, Spare};
use super::output::{Constant, Position, Term};
use super::value::Value;
use super::{HashMap, convert};
use crate::js::ast;

pub(crate) struct Session<'ast> {
    /// Functions declared beside the class: handlers and their helpers.
    pub functions: HashMap<Atom, &'ast Function>,
    /// Function values created lazily and shared across runs. Functions declared beside the
    /// class capture no state that a run can change.
    pub function_values: RefCell<HashMap<Atom, Value<'ast>>>,
    /// Lazily prepared handlers and helpers, including unsupported functions.
    pub compiled: Plans<'ast>,
    pub spare: RefCell<Spare<'ast>>,
    pub bindings: HashMap<Atom, Value<'ast>>,
    /// Names interrupted setup statements may have written, with their errors. Reading them
    /// stops interpretation.
    pub unavailable: HashMap<Atom, String>,
    pub layout: Layout,
    /// Handler state: registers, register mask, state-register indices, and decoded-string
    /// cache.
    pub state: HashMap<String, Value<'ast>>,
    /// The symbol the instance keeps its program under, if any.
    pub program_key: Option<Rc<()>>,
    /// Decoded strings cached by handler and slot across runs. An entry is valid only for its
    /// bytecode position and dispatch key; reusing it avoids decoding again during branch
    /// exploration and comparison retries.
    pub decoded: RefCell<HashMap<(usize, u32), Vec<Value<'ast>>>>,
    /// Other fields the constructor initializes, including the string-hash cache that hashed
    /// comparisons use.
    pub fields: HashMap<String, Value<'ast>>,
    constructor: &'ast BlockStmt,
    pub handlers: HashMap<u8, Handler<'ast>>,
    /// Where the program runner starts a program.
    pub entry: Position,
}

/// Instance state register indices, with zero as the per-run register mask.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Layout {
    pub pc: u8,
    pub key: u8,
    pub program: u8,
    pub cells: u8,
}

impl<'ast> Session<'ast> {
    /// Evaluates the enclosing `prelude`, the setup in `body` that defines the VM `class`, and
    /// the constructor.
    pub(super) fn try_new(
        body: &'ast BlockStmt,
        class: &'ast Class,
        prelude: &'ast [Stmt],
    ) -> Result<Self> {
        let run = extract::method(class, "run").context("the VM class has no run method")?;
        let constructor = extract::constructor(class)?;
        let functions = extract::functions(&body.stmts);
        let handlers = extract::handlers(&functions, run)?;
        let names = extract::state_fields(run)?;
        let mut session = Self {
            functions,
            handlers,
            entry: extract::entry(body)?,
            ..Self::unevaluated(constructor)
        };
        (session.bindings, session.unavailable) = interpret::setup(&session, prelude, &body.stmts);
        let (fields, symbols) = construct(&mut Run::method(&session), constructor);
        (session.state, session.layout) = state(&names, &fields)?;
        session.program_key = match &symbols[..] {
            [] => None,
            [symbol] => Some(symbol.clone()),
            symbols => bail!("the VM constructor keys {} fields by symbol", symbols.len()),
        };
        session.fields = concrete(fields);
        Ok(session)
    }

    fn unevaluated(constructor: &'ast BlockStmt) -> Self {
        Self {
            functions: HashMap::default(),
            function_values: RefCell::default(),
            compiled: Default::default(),
            spare: RefCell::default(),
            bindings: HashMap::default(),
            unavailable: HashMap::default(),
            layout: Layout::default(),
            state: HashMap::default(),
            program_key: None,
            decoded: RefCell::default(),
            fields: HashMap::default(),
            constructor,
            handlers: HashMap::default(),
            entry: Position::new(0, 0),
        }
    }

    /// Evaluates the constructor fields for `program`, including program-dependent data such as
    /// its string table.
    pub(super) fn constructed(&self, program: &[u8]) -> HashMap<String, Value<'ast>> {
        let (fields, _) = construct(&mut Run::constructor(self, program), self.constructor);
        concrete(fields)
    }
}

#[cfg(test)]
impl Session<'_> {
    /// Creates an empty session for interpreter tests.
    pub(crate) fn empty() -> Self {
        Self::unevaluated(Box::leak(Box::default()))
    }
}

/// Evaluates the constructor's field assignments through `run`. Returns the named fields and
/// the symbols used as other keys.
fn construct<'a>(
    run: &mut Run<'a, '_>,
    constructor: &'a BlockStmt,
) -> (HashMap<String, Value<'a>>, Vec<Rc<()>>) {
    let mut fields = HashMap::default();
    let mut symbols = Vec::new();
    for statement in &constructor.stmts {
        if let Stmt::Expr(statement) = statement
            && let Expr::Assign(assign) = &*statement.expr
            && let AssignTarget::Simple(SimpleAssignTarget::Member(target)) = &assign.left
            && matches!(&*target.obj, Expr::This(_))
        {
            if let Some(field) = ast::member_str(&target.prop).map(str::to_owned) {
                if let Ok(value) = run.expression(&assign.right) {
                    fields.insert(field, value);
                }
            } else if let MemberProp::Computed(key) = &target.prop
                && let Ok(Value::Symbol(symbol)) = run.expression(&key.expr)
            {
                symbols.push(symbol);
            }
        }
    }
    (fields, symbols)
}

/// Keeps the fields whose values depend only on the script.
fn concrete<'a>(mut fields: HashMap<String, Value<'a>>) -> HashMap<String, Value<'a>> {
    fields.retain(|_, value| !value.is_symbolic());
    fields
}

/// Recovers state-field values and register layout. The constructor computes indices as
/// `this.<mask> ^ <register>` with a random mask per run. Uses zero for the mask during
/// analysis.
fn state<'a>(
    names: &StateFields,
    fields: &HashMap<String, Value<'a>>,
) -> Result<(HashMap<String, Value<'a>>, Layout)> {
    let mut state = HashMap::default();
    let mut masks = BTreeSet::new();
    let mut register = |name: &str| -> Result<u8> {
        let value = fields
            .get(name)
            .with_context(|| format!("the VM constructor sets no this.{name}"))?;
        let (mask, register) = masked(value)
            .with_context(|| format!("the VM constructor's this.{name} is not a register"))?;
        masks.extend(mask);
        state.insert(name.to_owned(), Value::Number(f64::from(register)));
        Ok(register)
    };
    let layout = Layout {
        pc: register(&names.pc)?,
        key: register(&names.key)?,
        program: register(&names.program)?,
        cells: register(&names.cells)?,
    };
    ensure!(
        masks.len() <= 1,
        "the VM's registers use {} masks",
        masks.len()
    );
    state.insert(names.registers.clone(), Value::Registers);
    state.extend(masks.pop_first().map(|mask| (mask, Value::Number(0.0))));
    // The decoded-string cache is the one field the constructor starts as an empty array.
    let mut caches = fields.iter().filter(
        |(_, value)| matches!(value, Value::Array(elements) if elements.borrow().is_empty()),
    );
    if let (Some((cache, _)), None) = (caches.next(), caches.next()) {
        state.insert(cache.clone(), Value::Cache);
    }
    Ok((state, layout))
}

/// Extracts the register and optional mask field from `this.<mask> ^ <register>` or a bare
/// `<register>`.
fn masked(value: &Value<'_>) -> Option<(Option<String>, u8)> {
    let term = match value {
        Value::Number(register) => return Some((None, convert::byte(*register)?)),
        Value::Symbolic(term) => &**term,
        _ => return None,
    };
    let Term::Binary(BinaryOp::BitXor, left, right) = term else {
        return None;
    };
    match (&**left, &**right) {
        (Term::Field(mask), Term::Const(Constant::Number(register)))
        | (Term::Const(Constant::Number(register)), Term::Field(mask)) => {
            Some((Some(mask.clone()), convert::byte(*register)?))
        }
        _ => None,
    }
}
