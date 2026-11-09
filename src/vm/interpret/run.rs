//! Mutable state of one handler, setup, or constructor run: symbolic branches, effects, and the
//! journal that undoes speculative attempts.

use std::borrow::Cow;
use std::cell::RefCell;
use std::hash::Hash;
use std::mem;
use std::rc::Rc;

use oxc::syntax::operator::{BinaryOperator, UnaryOperator};

use super::builtin;
use super::copies::{self, Copies, Fork};
use super::explore::Invocation;
use super::frozen::{self, Frozen};
use crate::js::ast::{Binding, Script};
use crate::vm::output::{Constant, Effect, Exit, Path, Position, Term};
use crate::vm::session::Session;
use crate::vm::value::{Callable, Env, Scope, Value};
use crate::vm::{HashMap, convert, disassemble};

/// Why evaluation stopped before completing normally.
pub(crate) enum Stop<'ast> {
    /// A JavaScript exception: a `throw`, or an error such as reading a property of `undefined`.
    Throw(Value<'ast>),
    /// Code this interpreter does not follow, and why.
    Unsupported(String),
}

impl<'ast> Stop<'ast> {
    pub(super) fn throw(value: Value<'ast>) -> Box<Self> {
        Box::new(Self::Throw(value))
    }

    pub(super) fn unsupported(reason: &str) -> Box<Self> {
        Box::new(Self::Unsupported(reason.to_owned()))
    }
}

/// Boxes error details to keep successful results small enough to return in registers.
pub(super) type Evaluation<'ast, T> = Result<T, Box<Stop<'ast>>>;

/// How a statement completed: normally, or with a control-flow jump.
pub(super) enum Flow<'ast> {
    Normal,
    Return(Value<'ast>),
    Break(Option<&'ast str>),
    Continue(Option<&'ast str>),
}

pub(crate) struct Run<'ast, 'session> {
    pub(super) session: &'session Session<'ast>,
    pub(super) program: &'session [u8],
    /// Instance fields derived from program bytes by the constructor, once known.
    constructed: Option<&'session HashMap<String, Value<'ast>>>,
    /// Strings decrypted from the program's records, once a program is loaded.
    pub(super) decrypted: Option<&'session Decrypted<'ast>>,
    pub(super) registers: HashMap<u8, Value<'ast>>,
    /// Tags written before their register values; see [`crate::vm::registers`].
    pub(super) tags: HashMap<u8, Value<'ast>>,
    /// Instance fields this run has read or written.
    pub(super) fields: HashMap<String, Value<'ast>>,
    /// Session bindings this run has read or written.
    pub(super) globals: HashMap<Binding<'ast>, Value<'ast>>,
    /// Bindings unavailable after interrupted setup, with their errors. Setup copies the
    /// session's map when it changes it.
    pub(super) unavailable: Cow<'session, HashMap<Binding<'ast>, String>>,
    /// Copies isolate session objects; absent while building the session.
    copies: Option<Copies<'ast>>,
    pub(super) frames: Vec<Frame<'ast>>,
    /// Scope of setup and of functions declared beside the class. After setup, those functions
    /// resolve through session bindings.
    pub(super) setup: Option<Scope<'ast>>,
    /// Scopes captured by functions created in this run.
    closed: Vec<Scope<'ast>>,
    pub(super) effects: Vec<Effect>,
    temps: usize,
    pub(super) branches: Branches,
    /// Register-dependent expressions known to equal constants on the current branch path.
    facts: Vec<(Term, Value<'ast>)>,
    journal: Journal<'ast>,
    pub(super) spare: Spare<'ast>,
    /// Whether the run shares [`Frozen`] session objects instead of copying them.
    pub(super) sharing: bool,
    /// Whether the run wrote to a shared object, thawing it. Its results are discarded.
    pub(super) thawed: bool,
}

/// Strings decrypted from a program's string records, by record contents (see
/// [`RecordKey`]).
pub(crate) type Decrypted<'ast> = RefCell<HashMap<RecordKey, Value<'ast>>>;

/// The contents of a string record after the program: numbers and arrays of numbers, as bits.
pub(crate) type RecordKey = Vec<RecordPart>;

#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) enum RecordPart {
    Number(u64),
    Numbers(Vec<u64>),
}

/// Cleared buffers from completed calls. Handler runs take them from the session and
/// return them when they finish.
#[derive(Default)]
pub(crate) struct Spare<'ast> {
    pub(super) locals: Vec<Vec<Option<Value<'ast>>>>,
    pub(super) arguments: Vec<Vec<Value<'ast>>>,
}

#[derive(Default)]
pub(super) struct Branches {
    /// Branch directions in encounter order: choices from [`explore`](fn@super::explore), then
    /// true for newly reached branches.
    pub(super) decisions: Vec<bool>,
    /// How many of `decisions` are consumed.
    pub(super) decided: usize,
    /// Encountered branch conditions and the direction taken for each.
    conditions: Vec<(Term, bool)>,
}

impl Branches {
    /// Chooses the direction for `condition`, reusing earlier choices for the same condition or
    /// its negation. Otherwise consumes the next decision.
    fn decide(&mut self, condition: &Term) -> bool {
        let polarity = Polarity::of(condition);
        let earlier = self.conditions.iter().find_map(|(earlier, decision)| {
            let earlier = Polarity::of(earlier);
            (earlier.base == polarity.base)
                .then_some(*decision != (polarity.negated != earlier.negated))
        });
        if let Some(decision) = earlier {
            return decision;
        }
        if self.decided == self.decisions.len() {
            self.decisions.push(true);
        }
        let decision = self.decisions[self.decided];
        self.decided += 1;
        self.conditions.push((condition.clone(), decision));
        decision
    }
}

/// Splits a condition into its base expression and polarity. Treats `!c` as negated `c`, and
/// inequalities as negated equalities.
struct Polarity<'term> {
    base: Base<'term>,
    negated: bool,
}

#[derive(PartialEq)]
enum Base<'term> {
    Binary(BinaryOperator, &'term Term, &'term Term),
    Other(&'term Term),
}

impl<'term> Polarity<'term> {
    fn of(mut term: &'term Term) -> Self {
        let mut negated = false;
        while let Term::Unary(UnaryOperator::LogicalNot, inner) = term {
            term = inner;
            negated = !negated;
        }
        let base = match term {
            Term::Binary(operator, left, right) => {
                let (operator, inequality) = match operator {
                    BinaryOperator::StrictInequality => (BinaryOperator::StrictEquality, true),
                    BinaryOperator::Inequality => (BinaryOperator::Equality, true),
                    operator => (*operator, false),
                };
                negated ^= inequality;
                Base::Binary(operator, left, right)
            }
            term => Base::Other(term),
        };
        Self { base, negated }
    }
}

/// Values overwritten in `registers`, `fields` and `globals` while an attempt is open (see
/// [`Run::checkpoint`]).
#[derive(Default)]
struct Journal<'ast> {
    undo: Vec<Undo<'ast>>,
    /// Number of active speculative attempts.
    attempts: usize,
}

impl<'ast> Journal<'ast> {
    fn recording(&self) -> bool {
        self.attempts > 0
    }

    fn record(&mut self, undo: Undo<'ast>) {
        if self.recording() {
            self.undo.push(undo);
        }
    }
}

/// Lengths and counters to restore when an attempt is abandoned.
pub(super) struct Checkpoint {
    undo: usize,
    frames: usize,
    effects: usize,
    temps: usize,
    decisions: usize,
    decided: usize,
    conditions: usize,
    facts: usize,
}

/// The value held at a map key before a write.
enum Undo<'ast> {
    Register(u8, Option<Value<'ast>>),
    Field(String, Option<Value<'ast>>),
    Global(Binding<'ast>, Option<Value<'ast>>),
}

/// Active call receiver and local scope.
pub(super) struct Frame<'ast> {
    pub(super) this: Value<'ast>,
    pub(super) scope: CallScope<'ast>,
}

/// A call's own scope. Most slot-plan calls never store a variable in it, so it is created
/// on first use. Until then, the call sees exactly the variables of the scope it would enclose.
pub(super) enum CallScope<'ast> {
    Own(Scope<'ast>),
    /// Not yet created; it would enclose this scope.
    Deferred(Option<Scope<'ast>>),
}

impl<'ast> CallScope<'ast> {
    fn fork(&self, fork: &mut Fork<'_, 'ast>) -> Self {
        match self {
            Self::Own(scope) => Self::Own(fork.scope(scope)),
            Self::Deferred(outer) => Self::Deferred(outer.as_ref().map(|outer| fork.scope(outer))),
        }
    }
}

impl<'ast> Frame<'ast> {
    pub(super) fn new(this: Value<'ast>) -> Self {
        Self {
            this,
            scope: CallScope::Deferred(None),
        }
    }

    /// The call's own scope, creating it if needed.
    pub(super) fn own_scope(&mut self) -> &Scope<'ast> {
        if let CallScope::Deferred(outer) = &mut self.scope {
            self.scope = CallScope::Own(Env::scope(HashMap::default(), outer.take()));
        }
        let CallScope::Own(scope) = &self.scope else {
            unreachable!("the scope was just created");
        };
        scope
    }

    /// The scope enclosing the call's own variables, if the call has any.
    fn visible(&self) -> Option<&Scope<'ast>> {
        match &self.scope {
            CallScope::Own(scope) => Some(scope),
            CallScope::Deferred(outer) => outer.as_ref(),
        }
    }

    pub(super) fn find(&self, binding: Binding<'ast>) -> Option<Value<'ast>> {
        Env::find(self.visible()?, binding)
    }

    /// Assigns `binding` in the nearest scope containing it, as [`Env::assign`] does.
    pub(super) fn assign(&self, binding: Binding<'ast>, value: Value<'ast>) -> Option<Value<'ast>> {
        match self.visible() {
            Some(scope) => Env::assign(scope, binding, value),
            None => Some(value),
        }
    }

    /// Whether the call itself declares `binding`.
    pub(super) fn declares(&self, binding: Binding<'ast>) -> bool {
        matches!(&self.scope, CallScope::Own(scope)
            if scope.borrow().variables.contains_key(&binding))
    }
}

impl<'ast, 'session> Run<'ast, 'session> {
    pub(super) fn new(
        session: &'session Session<'ast>,
        program: &'session [u8],
        decisions: Vec<bool>,
        copies: Option<Copies<'ast>>,
    ) -> Self {
        Self {
            session,
            program,
            constructed: None,
            decrypted: None,
            registers: HashMap::default(),
            tags: HashMap::default(),
            fields: HashMap::default(),
            globals: HashMap::default(),
            unavailable: Cow::Borrowed(&session.unavailable),
            copies,
            frames: Vec::new(),
            setup: None,
            closed: Vec::new(),
            effects: Vec::new(),
            temps: 0,
            branches: Branches {
                decisions,
                ..Branches::default()
            },
            facts: Vec::new(),
            journal: Journal::default(),
            spare: Spare::default(),
            sharing: false,
            thawed: false,
        }
    }

    /// A handler run that follows `decisions`, then takes any further symbolic branch as true.
    pub(super) fn handler(invocation: &Invocation<'session, 'ast>, decisions: Vec<bool>) -> Self {
        let mut run = Self::invoked(invocation, decisions, Some(Copies::default()));
        for (register, value) in &invocation.session.initial {
            let value = run.isolate(value);
            run.registers.insert(*register, value);
        }
        run.start_at(invocation.pc, invocation.key);
        run.registers.extend(invocation.known.iter().cloned());
        run
    }

    /// A run of `invocation`'s handler with no registers set, sharing frozen session objects.
    fn invoked(
        invocation: &Invocation<'session, 'ast>,
        decisions: Vec<bool>,
        copies: Option<Copies<'ast>>,
    ) -> Self {
        let mut run = Self::new(invocation.session, invocation.program, decisions, copies);
        run.constructed = Some(invocation.fields);
        run.decrypted = Some(invocation.decrypted);
        run.spare = invocation.session.spare.take();
        run.sharing = true;
        run
    }

    /// Sets the program counter to `pc` and the dispatch key to `key`.
    pub(super) fn start_at(&mut self, pc: u32, key: u8) {
        let layout = self.session.layout;
        self.registers.extend([
            (layout.pc, Value::Number(f64::from(pc))),
            (layout.key, Value::Number(f64::from(key))),
            (layout.program, Value::Program),
            (layout.cells, Value::Cells),
        ]);
    }

    /// A run inside a method of the instance, while the session is built.
    pub(in crate::vm) fn method(session: &'session Session<'ast>) -> Self {
        let mut run = Self::new(session, &[], Vec::new(), None);
        run.frames.push(Frame::new(Value::Machine));
        run
    }

    /// A run of the constructor over `program`, after the session is built.
    pub(in crate::vm) fn constructor(
        session: &'session Session<'ast>,
        program: &'session [u8],
    ) -> Self {
        let mut run = Self::new(session, program, Vec::new(), Some(Copies::default()));
        run.frames.push(Frame::new(Value::Machine));
        run
    }

    /// The script whose code the run interprets.
    pub(in crate::vm) fn source(&self) -> Script<'ast> {
        self.session.script
    }

    /// The path this run took, or why the handler rejected its operands.
    pub(super) fn finish(mut self, outcome: Evaluation<'ast, Value<'ast>>) -> Result<Path, String> {
        self.session.spare.replace(mem::take(&mut self.spare));
        let exit = match outcome {
            Ok(_) => match self.position()? {
                None => Exit::Return,
                Some(Position { pc, key }) => Exit::Next { pc, key },
            },
            Err(stop) => match *stop {
                Stop::Throw(value) if value.is_symbolic() => {
                    self.effects.push(Effect::Throw(value.expr()));
                    Exit::Throw
                }
                Stop::Throw(value) => return Err(value.expr().to_string()),
                Stop::Unsupported(reason) => match self.position()? {
                    Some(Position { pc, key }) => Exit::Unfollowed { pc, key, reason },
                    None => return Err(format!("{reason}, with no position to continue from")),
                },
            },
        };
        // A catch handler can be pushed onto a constructor-created register stack.
        // Native array operations mutate that stack without producing an effect; retain
        // its frame so disassembly can also visit the exception continuation.
        for (register, _) in &self.session.initial {
            if let Some(value @ Value::Array(elements)) = self.registers.get(register)
                && elements.borrow().iter().any(|element| {
                    matches!(element.expr(), Term::Array(ref frame)
                        if disassemble::catch_frame(frame).is_some())
                })
            {
                self.effects.push(Effect::Set(*register, value.expr()));
            }
        }
        // The listing retains every path, so release unused vector capacity.
        let mut conditions = self.branches.conditions;
        conditions.shrink_to_fit();
        self.effects.shrink_to_fit();
        Ok(Path {
            conditions,
            effects: self.effects,
            exit,
        })
    }

    /// Returns the continuation position. Returns `None` if a `return` leaves the program
    /// counter as NaN.
    fn position(&self) -> Result<Option<Position>, String> {
        let layout = self.session.layout;
        let pc = self
            .registers
            .get(&layout.pc)
            .expect("a handler's run starts with the program counter set");
        let key = self
            .registers
            .get(&layout.key)
            .expect("a handler's run starts with the dispatch key set");
        match (pc.number(), key.number()) {
            (Some(pc), _) if pc.is_nan() => Ok(None),
            (Some(pc), Some(key)) => match (convert::position(pc), convert::byte(key)) {
                (Some(pc), Some(key)) => Ok(Some(Position::new(pc, key))),
                _ => Err(format!("the handler leaves pc {pc} and key {key}")),
            },
            _ => Err(format!(
                "the handler leaves pc {} and key {}",
                pc.expr(),
                key.expr()
            )),
        }
    }

    pub(super) fn decide(&mut self, condition: &Value<'ast>) -> bool {
        if let Some(truth) = condition.truthy() {
            return truth;
        }
        let term = match condition {
            Value::Symbolic(term) => Cow::Borrowed(&**term),
            condition => Cow::Owned(condition.expr()),
        };
        let decision = self.branches.decide(&term);
        self.learn(&term, decision);
        decision
    }

    /// Records that an expression equals a constant after a true strict equality test or a false
    /// strict inequality test.
    fn learn(&mut self, mut condition: &Term, mut holds: bool) {
        while let Term::Unary(UnaryOperator::LogicalNot, inner) = condition {
            condition = inner;
            holds = !holds;
        }
        let Term::Binary(operator, left, right) = condition else {
            return;
        };
        let equal = match operator {
            BinaryOperator::StrictEquality => holds,
            BinaryOperator::StrictInequality => !holds,
            _ => return,
        };
        if equal
            && let (Term::Const(constant), term) | (term, Term::Const(constant)) =
                (&**left, &**right)
            && !matches!(term, Term::Const(_))
            && let Some(value) = constant_value(constant)
        {
            self.facts.push((term.clone(), value));
        }
    }

    /// Returns the known constant for `value` on the current branch path, or `value` if none is
    /// known.
    pub(super) fn refined(&self, value: &Value<'ast>) -> Value<'ast> {
        if let Value::Symbolic(term) = value
            && let Some((_, known)) = self.facts.iter().find(|(fact, _)| fact == &**term)
        {
            return known.clone();
        }
        value.clone()
    }

    pub(super) fn temp(&mut self, expr: Term) -> Value<'ast> {
        let temp = self.temps;
        self.temps += 1;
        self.effects.push(Effect::Let(temp, expr));
        Value::symbolic(Term::Temp(temp))
    }

    pub(super) fn frame(&self) -> &Frame<'ast> {
        self.frames.last().expect("code runs inside a frame")
    }

    pub(super) fn frame_mut(&mut self) -> &mut Frame<'ast> {
        self.frames.last_mut().expect("code runs inside a frame")
    }

    /// Declares `binding` in the active call's scope.
    pub(super) fn declare(&mut self, binding: Binding<'ast>, value: Value<'ast>) {
        self.frame_mut()
            .own_scope()
            .borrow_mut()
            .variables
            .insert(binding, value);
    }

    /// Reads `binding` from the scopes, then from session bindings and functions declared
    /// beside the class. A binding none of them hold, such as a parameter of a function
    /// enclosing the VM, reads as the global of its name, as an unresolved reference does.
    pub(super) fn lookup(&mut self, binding: Binding<'ast>) -> Evaluation<'ast, Value<'ast>> {
        if let Some(value) = self.frame().find(binding) {
            return Ok(value);
        }
        if let Some(value) = self.globals.get(&binding) {
            return Ok(value.clone());
        }
        let name = self.session.script.name(binding);
        if let Some(reason) = self.unavailable.get(&binding) {
            return Err(Stop::unsupported(&format!(
                "{name}, whose setup stopped: {reason}"
            )));
        }
        if let Some(value) = self.session.bindings.get(&binding) {
            let value = self.isolate(value);
            self.set_global(binding, value.clone());
            return Ok(value);
        }
        if let Binding::Symbol(symbol) = binding
            && let Some(&function) = self.session.functions.get(&symbol)
        {
            let mut values = self.session.function_values.borrow_mut();
            let value = values.entry(symbol).or_insert_with(|| {
                Value::function(Callable::Script {
                    name: Some(name),
                    function,
                    scope: None,
                })
            });
            return Ok(value.clone());
        }
        Ok(match name {
            "undefined" => Value::Undefined,
            "NaN" => Value::Number(f64::NAN),
            "Infinity" => Value::Number(f64::INFINITY),
            "globalThis" | "self" | "window" => Value::Namespace(Rc::default()),
            name => builtin::member("", name),
        })
    }

    /// Assigns `binding` in the nearest scope holding it, or else the session binding. Otherwise
    /// declares it in the active call's scope.
    pub(super) fn assign(&mut self, binding: Binding<'ast>, value: Value<'ast>) {
        let Some(value) = self.frame().assign(binding, value) else {
            return;
        };
        if self.globals.contains_key(&binding) || self.session.bindings.contains_key(&binding) {
            self.set_global(binding, value);
            return;
        }
        self.declare(binding, value);
    }

    /// Returns an instance field from the current run or the constructor's initial value.
    pub(super) fn field(&mut self, name: &str) -> Value<'ast> {
        if let Some(value) = self.fields.get(name) {
            return value.clone();
        }
        let constructed = self.constructed.and_then(|fields| fields.get(name));
        match constructed.or_else(|| self.session.fields.get(name)) {
            Some(value) => {
                let value = self.isolate(value);
                self.set_field(name.to_owned(), value.clone());
                value
            }
            None => Value::symbolic(Term::Field(name.into())),
        }
    }

    pub(super) fn set_register(&mut self, register: u8, value: Value<'ast>) {
        let old = self.registers.insert(register, value);
        self.journal.record(Undo::Register(register, old));
    }

    pub(super) fn set_field(&mut self, name: String, value: Value<'ast>) {
        if self.journal.recording() {
            let old = self.fields.insert(name.clone(), value);
            self.journal.record(Undo::Field(name, old));
        } else {
            self.fields.insert(name, value);
        }
    }

    fn set_global(&mut self, binding: Binding<'ast>, value: Value<'ast>) {
        let old = self.globals.insert(binding, value);
        self.journal.record(Undo::Global(binding, old));
    }

    /// Starts a speculative attempt. [`Run::restore`] rolls it back; [`Run::release`] commits
    /// it.
    pub(super) fn checkpoint(&mut self) -> Checkpoint {
        self.journal.attempts += 1;
        Checkpoint {
            undo: self.journal.undo.len(),
            frames: self.frames.len(),
            effects: self.effects.len(),
            temps: self.temps,
            decisions: self.branches.decisions.len(),
            decided: self.branches.decided,
            conditions: self.branches.conditions.len(),
            facts: self.facts.len(),
        }
    }

    /// Restores `checkpoint` without undoing object mutations. Such mutations can only come
    /// from calls recorded separately by the caller.
    pub(super) fn restore(&mut self, checkpoint: Checkpoint) {
        let undone = self.journal.undo.drain(checkpoint.undo..).rev();
        for undo in undone {
            match undo {
                Undo::Register(key, old) => restore(&mut self.registers, key, old),
                Undo::Field(key, old) => restore(&mut self.fields, key, old),
                Undo::Global(key, old) => restore(&mut self.globals, key, old),
            }
        }
        self.frames.truncate(checkpoint.frames);
        self.effects.truncate(checkpoint.effects);
        self.temps = checkpoint.temps;
        let branches = &mut self.branches;
        branches.decisions.truncate(checkpoint.decisions);
        branches.decided = checkpoint.decided;
        branches.conditions.truncate(checkpoint.conditions);
        self.facts.truncate(checkpoint.facts);
        self.release(checkpoint);
    }

    /// Commits changes made since `checkpoint`.
    pub(super) fn release(&mut self, checkpoint: Checkpoint) {
        let journal = &mut self.journal;
        journal.attempts -= 1;
        // An attempt around this one may still need to undo it.
        if !journal.recording() {
            debug_assert!(
                checkpoint.undo <= journal.undo.len(),
                "an attempt's journal only grows until it is restored or released"
            );
            journal.undo.clear();
        }
    }

    /// Returns the scope that a newly created function would capture.
    pub(super) fn closure_scope(&mut self) -> Scope<'ast> {
        let scope = self.frame_mut().own_scope().clone();
        if !self
            .closed
            .last()
            .is_some_and(|last| Rc::ptr_eq(last, &scope))
        {
            self.closed.push(scope.clone());
        }
        scope
    }

    /// Returns the captured scopes this run created or copied. Parent scopes are tracked too,
    /// except the session's empty scope, because calls nest inside their function's captured
    /// scope.
    pub(super) fn scopes(&mut self) -> Vec<Scope<'ast>> {
        let mut scopes = mem::take(&mut self.closed);
        if let Some(copies) = &self.copies {
            scopes.extend(copies.scopes.values().flatten().cloned());
        }
        scopes
    }

    /// Copies a session value for use by this run, preserving run-local sharing.
    pub(super) fn isolate(&mut self, value: &Value<'ast>) -> Value<'ast> {
        let frozen = self.frozen();
        let Some(copies) = &mut self.copies else {
            return value.clone();
        };
        copies::copy(value, copies, frozen)
    }

    /// The session objects this run shares, if it shares them.
    fn frozen(&self) -> Option<&'session Frozen> {
        self.sharing.then_some(&self.session.frozen)
    }

    /// Checks that the run may write to `object`. A write to a shared session object thaws its
    /// group and stops the run, whose caller reruns the instruction with the group copied.
    pub(super) fn writable(&mut self, object: &Value<'ast>) -> Evaluation<'ast, ()> {
        if let Some(frozen) = self.frozen()
            && let Some(address) = frozen::address(object)
            && frozen.contains(address)
        {
            frozen.thaw(address);
            self.thawed = true;
            return Err(Stop::unsupported("a write to a shared session object"));
        }
        Ok(())
    }

    /// Takes a snapshot of a handler run before top-level statement `statement`, with the
    /// handler's `locals`. Returns `None` if the run is inside a speculative attempt or setup
    /// changed which names are unavailable, which a snapshot does not restore.
    pub(super) fn snapshot(
        &self,
        statement: usize,
        locals: &[Option<Value<'ast>>],
    ) -> Option<Snapshot<'ast>> {
        if self.journal.recording()
            || matches!(self.unavailable, Cow::Owned(_))
            || self.frames.len() != 1
            || self.setup.is_some()
            || self.constructed.is_none()
        {
            return None;
        }
        let mut fork = Fork::new(self.frozen());
        let frame = self.frame();
        Some(Snapshot {
            statement,
            decided: self.branches.decisions[..self.branches.decided].to_vec(),
            registers: fork.map(&self.registers),
            tags: fork.map(&self.tags),
            fields: fork.map(&self.fields),
            globals: fork.map(&self.globals),
            copies: self.copies.as_ref().map(|copies| fork.copies(copies)),
            closed: self.closed.iter().map(|scope| fork.scope(scope)).collect(),
            effects: self.effects.clone(),
            temps: self.temps,
            conditions: self.branches.conditions.clone(),
            facts: self
                .facts
                .iter()
                .map(|(term, value)| (term.clone(), fork.value(value)))
                .collect(),
            this: fork.value(&frame.this),
            scope: frame.scope.fork(&mut fork),
            locals: locals
                .iter()
                .map(|local| local.as_ref().map(|value| fork.value(value)))
                .collect(),
            copied: fork.copied,
        })
    }

    /// A handler run resumed from `snapshot`, following `decisions`, whose first decisions are
    /// the snapshot's. Returns the run, the handler's locals, and the scopes copied for it,
    /// which the caller clears when the run ends.
    pub(super) fn resume(
        invocation: &Invocation<'session, 'ast>,
        snapshot: &Snapshot<'ast>,
        decisions: Vec<bool>,
    ) -> (Self, Vec<Option<Value<'ast>>>, Vec<Scope<'ast>>) {
        let mut fork = Fork::new(Some(&invocation.session.frozen));
        let copies = snapshot.copies.as_ref().map(|copies| fork.copies(copies));
        let mut run = Self::invoked(invocation, decisions, copies);
        run.registers = fork.map(&snapshot.registers);
        run.tags = fork.map(&snapshot.tags);
        run.fields = fork.map(&snapshot.fields);
        run.globals = fork.map(&snapshot.globals);
        run.closed = snapshot
            .closed
            .iter()
            .map(|scope| fork.scope(scope))
            .collect();
        run.effects = snapshot.effects.clone();
        run.temps = snapshot.temps;
        run.branches.decided = snapshot.decided.len();
        run.branches.conditions = snapshot.conditions.clone();
        run.facts = snapshot
            .facts
            .iter()
            .map(|(term, value)| (term.clone(), fork.value(value)))
            .collect();
        run.frames.push(Frame {
            this: fork.value(&snapshot.this),
            scope: snapshot.scope.fork(&mut fork),
        });
        let locals = snapshot
            .locals
            .iter()
            .map(|local| local.as_ref().map(|value| fork.value(value)))
            .collect();
        (run, locals, fork.copied)
    }
}

/// A handler run's state before one of the top-level statements of its body. Paths that share
/// the decisions made before that statement resume here instead of rerunning the statements
/// before it.
pub(super) struct Snapshot<'ast> {
    /// The top-level statement to resume at.
    pub(super) statement: usize,
    /// The decisions consumed before the statement.
    decided: Vec<bool>,
    registers: HashMap<u8, Value<'ast>>,
    tags: HashMap<u8, Value<'ast>>,
    fields: HashMap<String, Value<'ast>>,
    globals: HashMap<Binding<'ast>, Value<'ast>>,
    copies: Option<Copies<'ast>>,
    closed: Vec<Scope<'ast>>,
    effects: Vec<Effect>,
    temps: usize,
    conditions: Vec<(Term, bool)>,
    facts: Vec<(Term, Value<'ast>)>,
    this: Value<'ast>,
    scope: CallScope<'ast>,
    locals: Vec<Option<Value<'ast>>>,
    /// Every scope the snapshot holds, cleared when it is dropped to break cycles.
    copied: Vec<Scope<'ast>>,
}

impl Drop for Snapshot<'_> {
    fn drop(&mut self) {
        for scope in &self.copied {
            scope.borrow_mut().variables.clear();
        }
    }
}

impl<'ast> Snapshot<'ast> {
    /// Whether a run following `decisions` makes the same decisions before the statement.
    pub(super) fn resumes(&self, decisions: &[bool]) -> bool {
        decisions.starts_with(&self.decided)
    }
}

/// Converts a constant to a value. Excludes NaN because it is not equal to any value.
fn constant_value<'a>(constant: &Constant) -> Option<Value<'a>> {
    Some(match constant {
        Constant::Undefined => Value::Undefined,
        Constant::Null => Value::Null,
        Constant::Bool(value) => Value::Bool(*value),
        Constant::Number(number) if number.is_nan() => return None,
        Constant::Number(number) => Value::Number(*number),
        Constant::String(text) => Value::string(text),
    })
}

/// Restores `old` at `key` in `map`, removing the key if it was previously absent.
fn restore<K: Eq + Hash, V>(map: &mut HashMap<K, V>, key: K, old: Option<V>) {
    match old {
        Some(old) => map.insert(key, old),
        None => map.remove(&key),
    };
}
