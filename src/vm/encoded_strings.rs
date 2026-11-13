//! Folds strings the program decodes with its own decoder functions.
//!
//! Some builds keep a probe's API names and markup as base64 text and decode each one at run
//! time with a decoder the probe builds for itself: a factory, called with `globalThis`, keeps
//! the global object, `String` and a cache in cells and returns the decoder; the probe stores
//! the decoder in a cell and calls it with each encoded constant. The decoder `atob`s its
//! argument, XORs each character with a key stream from a seed, and joins the characters with
//! `String.fromCharCode`.
//!
//! Rather than recognizing that algorithm, this module runs the factory and the decoder on their
//! listing paths with JavaScript's semantics for the few values and operations they use, and
//! gives up on anything else. Each call of a decoder cell with a constant argument then becomes
//! a load of the string the call returns, as [`super::packed_names`] does for names.
//!
//! The listing does not show two things the evaluation relies on: `String.fromCharCode` is
//! applied to the character buffer through a script helper the listing shows as a global whose
//! first argument is an opaque function, and the register machine's return pops a numeric
//! return address.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::ops::{ControlFlow, Deref};
use std::rc::Rc;

use oxc::syntax::operator::{BinaryOperator, LogicalOperator, UnaryOperator};

use super::output::{Constant, Effect, Exit, Listing, Path, Term};
use super::{HashMap, dataflow, disassemble};
use crate::js;

/// Instructions one evaluation may run before giving up. Decoding a constant takes a few dozen
/// per character.
const STEP_LIMIT: usize = 1_000_000;

/// The callee the machine calls to pop the return address when a function returns.
const POP: &str = "Array.prototype.pop";

pub(super) fn fold(listing: &mut Listing) {
    let Some(program) = Program::new(listing) else {
        return;
    };
    // Dataflow finds what functions store in cells, and reads cells to find the decoders other
    // functions call and the text they decoded, so repeat until the stored values stop changing.
    let mut entries = program.entries();
    for _ in 0..4 {
        let stored = program.stored(&entries);
        if stored == *program.scopes.stored.borrow() {
            break;
        }
        *program.scopes.stored.borrow_mut() = stored;
        entries = program.entries();
    }
    // Each decoded effect's instruction, path, index and text.
    let mut decoded = Vec::new();
    let mut encoded = BTreeSet::new();
    for (&pc, instruction) in &program.listing.instructions {
        let Some(known) = entries.get(&pc) else {
            continue;
        };
        let function = program.scopes.owner(pc);
        for (way, path) in instruction.paths.iter().enumerate() {
            let mut temporaries = BTreeMap::new();
            // Temporaries holding decoded text, whose copies become loads of the text too.
            let mut texts = BTreeMap::new();
            for (at, effect) in path.effects.iter().enumerate() {
                let (Effect::Let(_, term) | Effect::Set(_, term)) = effect else {
                    continue;
                };
                let fact = |term| program.fact(term, known, &temporaries, function);
                let value = fact(term);
                let text = if let Term::Call {
                    callee, arguments, ..
                } = term
                    && let Some(Fact::Decoder(_)) = fact(callee)
                    && let Some(Fact::Text(text)) = &value
                    && let [argument] = arguments.as_slice()
                    && let Some(Fact::Text(argument)) = fact(argument)
                {
                    encoded.insert(argument.to_string());
                    Some(text.clone())
                } else if let (Term::Cell(_), Some(Fact::Text(text))) = (term, &value) {
                    Some(text.clone())
                } else if let (Effect::Set(..), Term::Temp(temporary)) = (effect, term) {
                    texts.get(temporary).cloned()
                } else {
                    None
                };
                if let Some(text) = &text {
                    decoded.push((pc, way, at, text.to_string()));
                }
                if let Effect::Let(temporary, _) = effect {
                    dataflow::assign(&mut texts, *temporary, text);
                    dataflow::assign(&mut temporaries, *temporary, value);
                }
            }
        }
    }
    listing.encoded.extend(encoded);
    for (pc, way, at, text) in decoded {
        let instruction = listing
            .instructions
            .get_mut(&pc)
            .expect("decoded from the listing");
        if let Effect::Let(_, term) | Effect::Set(_, term) = &mut instruction.paths[way].effects[at]
        {
            *term = Term::Const(Constant::String(text));
        }
    }
}

/// Facts about the whole program that evaluation and dataflow need.
struct Program<'listing> {
    listing: &'listing Listing,
    /// Registers every assignment in the program sets to the same constant, such as the method
    /// names the program loads once at its start.
    fixed: BTreeMap<u8, Constant>,
    /// The facts of the [`Self::fixed`] registers, indexed by register, which hold at every
    /// instruction dataflow reaches, so [`Facts`] leave them out. NaN is left out here instead:
    /// it never equals itself, so dataflow forgets it where paths meet.
    invariant: Vec<Option<Fact<'listing>>>,
    /// Facts known on entry to every function and handler: the fixed registers left out of
    /// [`Self::invariant`].
    start: Facts<'listing>,
    /// The register holding the global object, which the program never assigns.
    global: u8,
    /// The register a called function reads its first argument from.
    argument: u8,
    /// The register a returning function leaves its result in.
    result: u8,
    scopes: Scopes<'listing>,
    /// Whether each function, run as a decoder factory, makes a decoder.
    factories: RefCell<HashMap<u32, bool>>,
    /// What each factory's decoders return, by factory.
    decoded: RefCell<HashMap<u32, Decoded>>,
}

impl<'listing> Program<'listing> {
    fn new(listing: &'listing Listing) -> Option<Self> {
        let mut assigned = BTreeMap::new();
        let mut global_reads = BTreeSet::new();
        let mut results = BTreeSet::new();
        for instruction in listing.instructions.values() {
            for path in &instruction.paths {
                // A return pops the return address and leaves the result in one register,
                // which builds set before or after the pop.
                if path.exit == Exit::Return && path.effects.iter().any(is_pop) {
                    let set = path.effects.iter().filter_map(|effect| match effect {
                        Effect::Set(register, _) => Some(*register),
                        _ => None,
                    });
                    results.extend(only(set));
                }
                for effect in &path.effects {
                    if let Effect::Set(register, value) = effect {
                        let constant = match value {
                            Term::Const(constant @ (Constant::String(_) | Constant::Number(_))) => {
                                Some(constant)
                            }
                            _ => None,
                        };
                        merge(&mut assigned, *register, constant);
                    }
                    effect.visit_terms(&mut |term| {
                        if let Term::Get(object, key) = term
                            && let Term::Reg(register) = **object
                            && key.string() == Some("globalThis")
                        {
                            global_reads.insert(register);
                        }
                    });
                }
            }
        }
        let fixed = assigned
            .iter()
            .filter_map(|(&register, constant)| Some((register, (*constant)?.clone())))
            .collect();
        let mut invariant = vec![None; usize::from(u8::MAX) + 1];
        let mut start = Facts::new();
        for (&register, constant) in &assigned {
            let Some(fact) = (*constant).and_then(Fact::of) else {
                continue;
            };
            #[expect(clippy::eq_op, reason = "NaN is the fact unequal to itself")]
            if fact == fact {
                invariant[usize::from(register)] = Some(fact);
            } else {
                start.insert(register, fact);
            }
        }
        let unassigned = |register: &u8| !assigned.contains_key(register);
        let global = only(global_reads.into_iter().filter(unassigned))?;
        // Every path of each function's entry copies its argument from a register the program
        // never assigns, as when the copy checks its type.
        let arguments = listing.functions.iter().filter_map(|function| {
            let instruction = listing.instructions.get(&function.pc)?;
            let copied = instruction
                .paths
                .iter()
                .map(|path| match path.effects.first()? {
                    Effect::Set(_, Term::Reg(register))
                        if unassigned(register) && *register != global =>
                    {
                        Some(*register)
                    }
                    _ => None,
                });
            only(copied.collect::<Option<BTreeSet<_>>>()?)
        });
        let argument = only(arguments.collect::<BTreeSet<_>>())?;
        Some(Self {
            listing,
            fixed,
            invariant,
            start,
            global,
            argument,
            result: only(results)?,
            scopes: Scopes::new(listing),
            factories: RefCell::default(),
            decoded: RefCell::default(),
        })
    }

    /// Facts on entry to each instruction the program's functions and handlers reach, which
    /// start with only the fixed registers known. Handlers only fill in instructions nothing
    /// else reaches, so a catch path cannot erase what the normal path knows.
    fn entries(&self) -> BTreeMap<u32, Facts<'listing>> {
        let functions = self.listing.functions.iter().map(|function| function.pc);
        let hidden = self.listing.hidden.iter().map(|hidden| hidden.target.pc);
        let mut entries = self.forward(disassemble::exception_entries(self.listing));
        entries.extend(self.forward(functions.chain(hidden)));
        entries
    }

    fn forward(&self, entries: impl IntoIterator<Item = u32>) -> BTreeMap<u32, Facts<'listing>> {
        let entries = entries.into_iter().map(|pc| (pc, self.start.clone()));
        let ControlFlow::Continue(incoming) =
            dataflow::forward(self.listing, entries, |pc, path, known| {
                let function = self.scopes.owner(pc);
                ControlFlow::<Infallible, bool>::Continue(self.transfer(path, known, function))
            });
        incoming
    }

    /// Applies `path` of an instruction in `function` to `known` and returns whether the path
    /// can run. Terms read registers as they were when the instruction started.
    fn transfer(
        &self,
        path: &'listing Path,
        known: &mut Facts<'listing>,
        function: Option<u32>,
    ) -> bool {
        let mut temporaries = BTreeMap::new();
        let mut writes = Vec::new();
        for effect in &path.effects {
            match effect {
                Effect::Let(temporary, term) => {
                    let fact = self.fact(term, known, &temporaries, function);
                    dataflow::assign(&mut temporaries, *temporary, fact);
                }
                // Writes to invariant registers store the constant they already hold.
                Effect::Set(register, _) if self.invariant[usize::from(*register)].is_some() => {}
                Effect::Set(register, term) => {
                    writes.push((*register, self.fact(term, known, &temporaries, function)));
                }
                _ => {}
            }
        }
        let feasible = path.conditions.iter().all(|(condition, expected)| {
            truth(self.fact(condition, known, &temporaries, function))
                .is_none_or(|actual| actual == *expected)
        });
        for (register, fact) in writes {
            dataflow::assign(known, register, fact);
        }
        feasible
    }

    /// What each function stores in each cell it assigns: a decoder, or text assigned before the
    /// function creates any function that reads the cell. `None` when it stores anything else
    /// there.
    fn stored(
        &self,
        entries: &BTreeMap<u32, Facts<'listing>>,
    ) -> BTreeMap<(u32, u32), Option<Fact<'listing>>> {
        let mut stored = BTreeMap::new();
        // Where each function last assigns each cell.
        let mut last_set = BTreeMap::new();
        for (&pc, instruction) in &self.listing.instructions {
            let Some(function) = self.scopes.owner(pc) else {
                continue;
            };
            let known = entries.get(&pc);
            for path in &instruction.paths {
                let mut temporaries = BTreeMap::new();
                for effect in &path.effects {
                    let fact = |term| self.fact(term, known?, &temporaries, Some(function));
                    match effect {
                        Effect::SetCell(cell, term) => {
                            last_set.insert((function, *cell), pc);
                            let value = fact(term)
                                .filter(|fact| matches!(fact, Fact::Decoder(_) | Fact::Text(_)));
                            merge(&mut stored, (function, *cell), value);
                        }
                        Effect::Let(temporary, term) => {
                            let value = fact(term);
                            dataflow::assign(&mut temporaries, *temporary, value);
                        }
                        _ => {}
                    }
                }
            }
        }
        for (&(function, cell), value) in &mut stored {
            if matches!(value, Some(Fact::Text(_)))
                && self
                    .scopes
                    .read_early(function, cell, last_set[&(function, cell)])
            {
                *value = None;
            }
        }
        stored
    }

    /// What `term` is known to be in `function`.
    fn fact(
        &self,
        term: &'listing Term,
        known: &Facts<'listing>,
        temporaries: &BTreeMap<usize, Fact<'listing>>,
        function: Option<u32>,
    ) -> Option<Fact<'listing>> {
        let fact = |term| self.fact(term, known, temporaries, function);
        Some(match term {
            Term::Const(constant) => Fact::of(constant)?,
            Term::Reg(register) => known
                .get(register)
                .or(self.invariant[usize::from(*register)].as_ref())?
                .clone(),
            Term::Temp(temporary) => temporaries.get(temporary)?.clone(),
            Term::Cell(cell) => {
                let (scope, stored) = self.scopes.cell(function?, *cell)?;
                // Only functions the assigning function creates afterwards read text surely
                // assigned.
                if matches!(stored, Fact::Text(_)) && Some(scope) == function {
                    return None;
                }
                stored
            }
            Term::Get(object, key)
                if **object == Term::Reg(self.global) && key.string() == Some("globalThis") =>
            {
                Fact::Global
            }
            Term::Closure { pc, .. } => Fact::Closure(*pc),
            Term::Call {
                callee,
                this: None,
                arguments,
            } => match (fact(callee)?, arguments.as_slice()) {
                (Fact::Closure(pc), [argument])
                    if fact(argument)? == Fact::Global && self.is_factory(pc) =>
                {
                    Fact::Decoder(pc)
                }
                (Fact::Decoder(pc), [argument]) => match fact(argument)? {
                    Fact::Text(text) => Fact::Text(Text::Shared(self.decode(pc, &text)?)),
                    _ => return None,
                },
                _ => return None,
            },
            Term::Unary(UnaryOperator::Typeof, argument) => {
                Fact::Text(Text::Listing(fact(argument)?.type_name()))
            }
            Term::Unary(UnaryOperator::LogicalNot, argument) => Fact::Bool(!truth(fact(argument))?),
            Term::Binary(
                operator @ (BinaryOperator::StrictEquality | BinaryOperator::StrictInequality),
                left,
                right,
            ) => {
                let equal = fact(left)?.strictly_equals(&fact(right)?)?;
                Fact::Bool(equal == (*operator == BinaryOperator::StrictEquality))
            }
            _ => return None,
        })
    }

    /// Runs factory `pc` given the global object, returning the decoder it makes.
    fn decoder(&self, pc: u32) -> Option<Rc<Closure>> {
        let factory = Closure {
            pc,
            cells: Cells::new(),
        };
        match self.call(&factory, Value::Global)? {
            Value::Closure(decoder) => Some(decoder),
            _ => None,
        }
    }

    fn is_factory(&self, pc: u32) -> bool {
        *(self.factories.borrow_mut())
            .entry(pc)
            .or_insert_with(|| self.decoder(pc).is_some())
    }

    /// What a decoder from factory `pc` returns for `text`, if a string. Each text gets a fresh
    /// decoder, so its cache cannot answer for an earlier call.
    fn decode(&self, pc: u32, text: &str) -> Option<Rc<str>> {
        if let Some(result) = (self.decoded.borrow().get(&pc)).and_then(|texts| texts.get(text)) {
            return result.clone();
        }
        let result = (|| {
            let argument = Value::String(text.encode_utf16().collect());
            match self.call(&*self.decoder(pc)?, argument)? {
                Value::String(units) => Some(String::from_utf16(&units).ok()?.into()),
                _ => None,
            }
        })();
        let mut decoded = self.decoded.borrow_mut();
        let texts = decoded.entry(pc).or_default();
        texts.insert(text.to_owned(), result.clone());
        result
    }

    /// Runs `closure` with `argument` until it returns, or gives up.
    fn call(&self, closure: &Closure, argument: Value) -> Option<Value> {
        let mut frame = Frame {
            registers: (self.fixed.iter())
                .map(|(&register, constant)| (register, Value::of(constant)))
                .collect(),
            cells: closure.cells.clone(),
        };
        frame.registers.insert(self.argument, argument);
        let mut pc = closure.pc;
        for _ in 0..STEP_LIMIT {
            let instruction = self.listing.instructions.get(&pc)?;
            let paths = instruction.paths.iter();
            let path = only(paths.filter(|path| frame.takes(path) == Some(true)))?;
            let mut temporaries = BTreeMap::new();
            // Terms read registers as they were when the instruction started, so writes wait
            // until its effects finish.
            let mut writes = Vec::new();
            for effect in &path.effects {
                let evaluation = Evaluation {
                    registers: &frame.registers,
                    temporaries: &temporaries,
                    cells: &frame.cells,
                    pure: false,
                };
                match effect {
                    Effect::Let(temporary, term) => {
                        let value = evaluation.value(term)?;
                        temporaries.insert(*temporary, value);
                    }
                    Effect::Set(register, term) => {
                        writes.push((*register, evaluation.value(term)?));
                    }
                    Effect::SetProperty { object, key, value } => {
                        let object = evaluation.value(object)?;
                        let key = evaluation.value(key)?;
                        set_property(&object, &key, evaluation.value(value)?)?;
                    }
                    Effect::NewCell(cell) => {
                        let value = Rc::new(RefCell::new(Value::Undefined));
                        frame.cells.insert(*cell, value);
                    }
                    Effect::SetCell(cell, term) => {
                        let value = evaluation.value(term)?;
                        *frame.cells.get(cell)?.borrow_mut() = value;
                    }
                    Effect::Throw(_) => return None,
                }
            }
            frame.registers.extend(writes);
            match path.exit {
                Exit::Next { pc: next, .. } => pc = next,
                Exit::Return => return frame.registers.get(&self.result).cloned(),
                Exit::Throw | Exit::Unfollowed { .. } => return None,
            }
        }
        None
    }
}

/// The single item of `items`, if there is exactly one.
fn only<T>(items: impl IntoIterator<Item = T>) -> Option<T> {
    let mut items = items.into_iter();
    let first = items.next()?;
    items.next().is_none().then_some(first)
}

/// Records `value` for `key`, or `None` once two records disagree.
fn merge<K: Ord, V: PartialEq>(map: &mut BTreeMap<K, Option<V>>, key: K, value: Option<V>) {
    map.entry(key)
        .and_modify(|known| {
            if *known != value {
                *known = None;
            }
        })
        .or_insert(value);
}

fn is_pop(effect: &Effect) -> bool {
    matches!(effect, Effect::Let(_, Term::Call { callee, .. })
        if matches!(&**callee, Term::Global(name) if name == POP))
}

fn mentions_temporary(term: &Term) -> bool {
    let mut found = false;
    term.visit(&mut |term| found |= matches!(term, Term::Temp(_)));
    found
}

/// What dataflow knows about a register, temporary or cell.
#[derive(Clone, Debug, PartialEq)]
enum Fact<'listing> {
    Undefined,
    Bool(bool),
    Number(f64),
    Text(Text<'listing>),
    Global,
    /// A program function by entry.
    Closure(u32),
    /// The decoder that the factory with this entry makes.
    Decoder(u32),
}

type Facts<'listing> = BTreeMap<u8, Fact<'listing>>;

/// What a decoder returns for each text, if a string.
type Decoded = HashMap<String, Option<Rc<str>>>;

/// A string fact, which dataflow copies to every instruction it reaches: a listing constant, or
/// text that evaluation made.
#[derive(Clone, Debug)]
enum Text<'listing> {
    Listing(&'listing str),
    Shared(Rc<str>),
}

impl Deref for Text<'_> {
    type Target = str;

    fn deref(&self) -> &str {
        match self {
            Self::Listing(text) => text,
            Self::Shared(text) => text,
        }
    }
}

impl PartialEq for Text<'_> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl<'listing> Fact<'listing> {
    fn of(constant: &'listing Constant) -> Option<Self> {
        Some(match constant {
            Constant::Undefined => Self::Undefined,
            Constant::Bool(value) => Self::Bool(*value),
            Constant::Number(value) => Self::Number(*value),
            Constant::String(text) => Self::Text(Text::Listing(text)),
            Constant::Null => return None,
        })
    }

    fn type_name(&self) -> &'static str {
        match self {
            Self::Undefined => "undefined",
            Self::Bool(_) => "boolean",
            Self::Number(_) => "number",
            Self::Text(_) => "string",
            Self::Global => "object",
            Self::Closure(_) | Self::Decoder(_) => "function",
        }
    }

    /// `===` where it is decided: primitives by value, the global object by identity. Two
    /// functions are unknown, as one factory makes a new decoder on each call.
    fn strictly_equals(&self, other: &Self) -> Option<bool> {
        match (self, other) {
            (Self::Closure(_) | Self::Decoder(_), Self::Closure(_) | Self::Decoder(_)) => None,
            (Self::Number(left), Self::Number(right)) => Some(left == right),
            _ => Some(self == other),
        }
    }
}

/// A condition's outcome when its fact is a known boolean.
fn truth(fact: Option<Fact<'_>>) -> Option<bool> {
    match fact {
        Some(Fact::Bool(value)) => Some(value),
        _ => None,
    }
}

/// Which function each instruction belongs to, which function creates each function, and what
/// functions keep in cells.
struct Scopes<'listing> {
    owners: BTreeMap<u32, Option<u32>>,
    parents: BTreeMap<u32, Option<u32>>,
    declared: BTreeSet<(u32, u32)>,
    /// What a function stores in a cell (see [`Program::stored`]).
    stored: RefCell<BTreeMap<(u32, u32), Option<Fact<'listing>>>>,
    /// Where each function is created, when one instruction creates it.
    created: BTreeMap<u32, Option<u32>>,
    /// The cells each function reads.
    reads: BTreeMap<u32, BTreeSet<u32>>,
}

impl<'listing> Scopes<'listing> {
    fn new(listing: &Listing) -> Self {
        let mut hidden: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for branch in &listing.hidden {
            hidden
                .entry(branch.compare)
                .or_default()
                .push(branch.target.pc);
        }
        // Walk each function's code without entering the functions it creates.
        let mut owners = BTreeMap::new();
        for function in &listing.functions {
            let mut pending = vec![function.pc];
            let mut seen = BTreeSet::new();
            while let Some(pc) = pending.pop() {
                if !seen.insert(pc) {
                    continue;
                }
                let Some(instruction) = listing.instructions.get(&pc) else {
                    continue;
                };
                merge(&mut owners, pc, Some(function.pc));
                pending.extend(instruction.exits());
                pending.extend(hidden.get(&pc).into_iter().flatten());
                for effect in instruction.effects() {
                    effect.visit_terms(&mut |term| {
                        if let Term::Array(frame) = term
                            && let Some(handler) = disassemble::catch_frame(frame)
                        {
                            pending.push(handler.pc);
                        }
                    });
                }
            }
        }
        let mut parents = BTreeMap::new();
        let mut declared = BTreeSet::new();
        let mut created = BTreeMap::new();
        let mut reads: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
        for (&pc, instruction) in &listing.instructions {
            let owner = owners.get(&pc).copied().flatten();
            for effect in instruction.effects() {
                effect.visit_terms(&mut |term| match term {
                    Term::Cell(cell) => {
                        if let Some(owner) = owner {
                            reads.entry(owner).or_default().insert(*cell);
                        }
                    }
                    Term::Closure { pc: function, .. } => {
                        merge(&mut created, *function, Some(pc));
                        merge(&mut parents, *function, owner);
                    }
                    _ => {}
                });
                if let (Some(owner), Effect::NewCell(cell)) = (owner, effect) {
                    declared.insert((owner, *cell));
                }
            }
        }
        Self {
            owners,
            parents,
            declared,
            stored: RefCell::default(),
            created,
            reads,
        }
    }

    fn owner(&self, pc: u32) -> Option<u32> {
        self.owners.get(&pc).copied().flatten()
    }

    /// Whether a function that reads `function`'s `cell` may run before `assigned`: one that
    /// `function` creates there or earlier, or one created within it.
    fn read_early(&self, function: u32, cell: u32, assigned: u32) -> bool {
        self.reads.iter().any(|(&reader, cells)| {
            if reader == function || !cells.contains(&cell) {
                return false;
            }
            // The reader's enclosing functions, up to the one declaring the cell.
            let mut scope = reader;
            for _ in 0..=self.parents.len() {
                if self.declared.contains(&(scope, cell)) {
                    return false;
                }
                let Some(parent) = self.parents.get(&scope).copied().flatten() else {
                    // Readers whose scope is unknown may read it.
                    return true;
                };
                if parent == function {
                    let created = self.created.get(&scope).copied().flatten();
                    return created.is_none_or(|at| at <= assigned);
                }
                scope = parent;
            }
            true
        })
    }

    /// What `cell` holds in `function`, and the nearest enclosing function, which declares
    /// the cell and stores it.
    fn cell(&self, function: u32, cell: u32) -> Option<(u32, Fact<'listing>)> {
        let mut scope = function;
        for _ in 0..=self.parents.len() {
            if self.declared.contains(&(scope, cell)) {
                let stored = self.stored.borrow().get(&(scope, cell))?.clone()?;
                return Some((scope, stored));
            }
            scope = self.parents.get(&scope).copied().flatten()?;
        }
        None
    }
}

/// A value during evaluation.
#[derive(Clone, Debug)]
enum Value {
    Undefined,
    Null,
    Bool(bool),
    Number(f64),
    String(Rc<[u16]>),
    Global,
    /// The `String` constructor.
    StringConstructor,
    Builtin(Builtin),
    Array(Rc<RefCell<Vec<Value>>>),
    Object(Rc<RefCell<Object>>),
    Closure(Rc<Closure>),
    /// A function the listing does not show.
    Opaque,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Builtin {
    Atob,
    FromCharCode,
    CharCodeAt,
    Push,
}

#[derive(Debug, Default)]
struct Object {
    properties: BTreeMap<Rc<[u16]>, Value>,
    /// Whether the object's prototype was set to `null`, so that missing properties are
    /// `undefined` rather than inherited.
    bare: bool,
}

#[derive(Debug)]
struct Closure {
    pc: u32,
    cells: Cells,
}

type Cells = BTreeMap<u32, Rc<RefCell<Value>>>;

struct Frame {
    registers: BTreeMap<u8, Value>,
    cells: Cells,
}

impl Frame {
    /// Whether the frame takes `path`, or `None` if a condition cannot be decided. Conditions
    /// may read the path's own call results, which are computed without side effects.
    fn takes(&self, path: &Path) -> Option<bool> {
        let mut temporaries = BTreeMap::new();
        if (path.conditions.iter()).any(|(condition, _)| mentions_temporary(condition)) {
            for effect in &path.effects {
                if let Effect::Let(temporary, term) = effect {
                    let value = self.pure(&temporaries).value(term);
                    dataflow::assign(&mut temporaries, *temporary, value);
                }
            }
        }
        let evaluation = self.pure(&temporaries);
        for (condition, expected) in &path.conditions {
            if evaluation.value(condition)?.truthy() != *expected {
                return Some(false);
            }
        }
        Some(true)
    }

    /// Evaluates without side effects against the frame's current state.
    fn pure<'a>(&'a self, temporaries: &'a BTreeMap<usize, Value>) -> Evaluation<'a> {
        Evaluation {
            registers: &self.registers,
            temporaries,
            cells: &self.cells,
            pure: true,
        }
    }
}

impl Value {
    fn of(constant: &Constant) -> Self {
        match constant {
            Constant::Undefined => Self::Undefined,
            Constant::Null => Self::Null,
            Constant::Bool(value) => Self::Bool(*value),
            Constant::Number(value) => Self::Number(*value),
            Constant::String(text) => Self::String(text.encode_utf16().collect()),
        }
    }

    fn number(&self) -> Option<f64> {
        match self {
            Self::Number(value) => Some(*value),
            _ => None,
        }
    }

    fn type_name(&self) -> &'static str {
        match self {
            Self::Undefined => "undefined",
            Self::Bool(_) => "boolean",
            Self::Number(_) => "number",
            Self::String(_) => "string",
            Self::Null | Self::Global | Self::Array(_) | Self::Object(_) => "object",
            Self::StringConstructor | Self::Builtin(_) | Self::Closure(_) | Self::Opaque => {
                "function"
            }
        }
    }

    /// `ToBoolean`.
    fn truthy(&self) -> bool {
        match self {
            Self::Undefined | Self::Null => false,
            Self::Bool(value) => *value,
            Self::Number(value) => *value != 0.0 && !value.is_nan(),
            Self::String(units) => !units.is_empty(),
            _ => true,
        }
    }

    /// `===`, for the values evaluation can compare.
    fn strictly_equals(&self, other: &Self) -> Option<bool> {
        Some(match (self, other) {
            (Self::Undefined, Self::Undefined)
            | (Self::Null, Self::Null)
            | (Self::Global, Self::Global)
            | (Self::StringConstructor, Self::StringConstructor) => true,
            (Self::Bool(left), Self::Bool(right)) => left == right,
            (Self::Number(left), Self::Number(right)) => left == right,
            (Self::String(left), Self::String(right)) => left == right,
            (Self::Builtin(left), Self::Builtin(right)) => left == right,
            (Self::Array(left), Self::Array(right)) => Rc::ptr_eq(left, right),
            (Self::Object(left), Self::Object(right)) => Rc::ptr_eq(left, right),
            (Self::Closure(left), Self::Closure(right)) => Rc::ptr_eq(left, right),
            (Self::Opaque, _) | (_, Self::Opaque) => return None,
            _ => false,
        })
    }
}

/// Evaluates terms against registers as an instruction started.
struct Evaluation<'a> {
    registers: &'a BTreeMap<u8, Value>,
    temporaries: &'a BTreeMap<usize, Value>,
    cells: &'a Cells,
    /// Gives up on calls that change state, for deciding conditions.
    pure: bool,
}

impl Evaluation<'_> {
    fn value(&self, term: &Term) -> Option<Value> {
        Some(match term {
            Term::Const(constant) => Value::of(constant),
            Term::Reg(register) => self.registers.get(register)?.clone(),
            Term::Temp(temporary) => self.temporaries.get(temporary)?.clone(),
            Term::Cell(cell) => self.cells.get(cell)?.borrow().clone(),
            Term::Array(elements) => Value::Array(Rc::new(RefCell::new(self.values(elements)?))),
            // Object literals other than `{}` never occur in the code this runs.
            Term::Object(properties) if properties.is_empty() => {
                Value::Object(Rc::new(RefCell::new(Object::default())))
            }
            Term::Get(object, key) => get(&self.value(object)?, &self.value(key)?)?,
            Term::Call {
                callee,
                this,
                arguments,
            } => {
                let (function, receiver) = match (&**callee, this) {
                    (Term::Global(name), None) => {
                        return self.call_global(name, &self.values(arguments)?);
                    }
                    (Term::Get(object, key), None) => {
                        let object = self.value(object)?;
                        (get(&object, &self.value(key)?)?, object)
                    }
                    (callee, None) => (self.value(callee)?, Value::Undefined),
                    (callee, Some(this)) => (self.value(callee)?, self.value(this)?),
                };
                self.call(&function, &receiver, &self.values(arguments)?)?
            }
            Term::Closure { pc, .. } => Value::Closure(Rc::new(Closure {
                pc: *pc,
                cells: self.cells.clone(),
            })),
            Term::Unary(operator, argument) => {
                let argument = self.value(argument)?;
                match operator {
                    UnaryOperator::Typeof => {
                        Value::String(argument.type_name().encode_utf16().collect())
                    }
                    UnaryOperator::LogicalNot => Value::Bool(!argument.truthy()),
                    UnaryOperator::UnaryNegation => Value::Number(-argument.number()?),
                    _ => return None,
                }
            }
            Term::Binary(operator, left, right) => {
                binary(*operator, &self.value(left)?, &self.value(right)?)?
            }
            Term::Logical(operator, left, right) => {
                let left = self.value(left)?;
                let decided = match operator {
                    LogicalOperator::And => !left.truthy(),
                    LogicalOperator::Or => left.truthy(),
                    LogicalOperator::Coalesce => !matches!(left, Value::Undefined | Value::Null),
                };
                if decided { left } else { self.value(right)? }
            }
            Term::Opaque(what) if what == "function" => Value::Opaque,
            _ => return None,
        })
    }

    fn values(&self, terms: &[Term]) -> Option<Vec<Value>> {
        terms.iter().map(|term| self.value(term)).collect()
    }

    /// Calls the machine's stack pop or the script helper that applies a function.
    fn call_global(&self, name: &str, arguments: &[Value]) -> Option<Value> {
        if name == POP {
            // The return address, which the return path checks is a number.
            return arguments.is_empty().then_some(Value::Number(0.0));
        }
        match arguments {
            [
                Value::Opaque,
                Value::Builtin(Builtin::FromCharCode),
                _,
                Value::Array(units),
            ] => from_char_code(&units.borrow()),
            _ => None,
        }
    }

    fn call(&self, function: &Value, receiver: &Value, arguments: &[Value]) -> Option<Value> {
        let Value::Builtin(builtin) = function else {
            return None;
        };
        match (builtin, receiver, arguments) {
            (Builtin::Atob, _, [Value::String(text), ..]) => atob(text),
            (Builtin::CharCodeAt, Value::String(text), arguments) => {
                let position = match arguments.first() {
                    None | Some(Value::Undefined) => 0.0,
                    Some(position) => position.number()?,
                };
                let position = if position.is_nan() {
                    0.0
                } else {
                    position.trunc()
                };
                let unit = (position >= 0.0)
                    .then(|| text.get(position as usize))
                    .flatten();
                Some(Value::Number(
                    unit.map_or(f64::NAN, |&unit| f64::from(unit)),
                ))
            }
            (Builtin::Push, Value::Array(elements), arguments) if !self.pure => {
                let mut elements = elements.borrow_mut();
                elements.extend_from_slice(arguments);
                Some(Value::Number(elements.len() as f64))
            }
            (Builtin::FromCharCode, _, arguments) => from_char_code(arguments),
            _ => None,
        }
    }
}

/// `object[key]` for the objects evaluation models.
fn get(object: &Value, key: &Value) -> Option<Value> {
    let key = match key {
        Value::String(units) => units,
        Value::Number(index) => {
            let Value::Array(elements) = object else {
                return None;
            };
            if index.fract() != 0.0 || *index < 0.0 {
                return None;
            }
            let element = elements.borrow().get(*index as usize).cloned();
            return Some(element.unwrap_or(Value::Undefined));
        }
        _ => return None,
    };
    let name = String::from_utf16(key).ok()?;
    Some(match (object, name.as_str()) {
        (Value::Global, "atob") => Value::Builtin(Builtin::Atob),
        (Value::Global, "String") => Value::StringConstructor,
        (Value::Global, "globalThis") => Value::Global,
        (Value::StringConstructor, "fromCharCode") => Value::Builtin(Builtin::FromCharCode),
        (Value::String(units), "length") => Value::Number(units.len() as f64),
        (Value::String(_), "charCodeAt") => Value::Builtin(Builtin::CharCodeAt),
        (Value::Array(elements), "length") => Value::Number(elements.borrow().len() as f64),
        (Value::Array(_), "push") => Value::Builtin(Builtin::Push),
        (Value::Object(object), _) => {
            let object = object.borrow();
            match object.properties.get(key) {
                Some(value) => value.clone(),
                // Without a prototype nothing is inherited.
                None if object.bare => Value::Undefined,
                None => return None,
            }
        }
        _ => return None,
    })
}

fn set_property(object: &Value, key: &Value, value: Value) -> Option<()> {
    let (Value::Object(object), Value::String(key)) = (object, key) else {
        return None;
    };
    let mut object = object.borrow_mut();
    if key.iter().copied().eq("__proto__".encode_utf16()) {
        // Only a `null` prototype is modeled.
        if !matches!(value, Value::Null) || !object.properties.is_empty() {
            return None;
        }
        object.bare = true;
    } else if object.bare {
        object.properties.insert(key.clone(), value);
    } else {
        // Properties of an object with a prototype could be setters.
        return None;
    }
    Some(())
}

fn binary(operator: BinaryOperator, left: &Value, right: &Value) -> Option<Value> {
    use BinaryOperator as Op;
    Some(match operator {
        Op::StrictEquality => Value::Bool(left.strictly_equals(right)?),
        Op::StrictInequality => Value::Bool(!left.strictly_equals(right)?),
        Op::Addition => match (left, right) {
            (Value::Number(left), Value::Number(right)) => Value::Number(left + right),
            (Value::String(left), Value::String(right)) => {
                Value::String([&left[..], &right[..]].concat().into())
            }
            _ => return None,
        },
        _ => {
            let (left, right) = (left.number()?, right.number()?);
            match operator {
                Op::Subtraction => Value::Number(left - right),
                Op::Multiplication => Value::Number(left * right),
                Op::BitwiseXOR => Value::Number(js::bit_xor(left, right)),
                Op::BitwiseOR => Value::Number(js::bit_or(left, right)),
                Op::BitwiseAnd => Value::Number(js::bit_and(left, right)),
                Op::ShiftLeft => Value::Number(js::shl(left, right)),
                Op::ShiftRight => Value::Number(js::shr(left, right)),
                Op::ShiftRightZeroFill => Value::Number(js::ushr(left, right)),
                Op::LessThan => Value::Bool(left < right),
                Op::GreaterThan => Value::Bool(left > right),
                Op::LessEqualThan => Value::Bool(left <= right),
                Op::GreaterEqualThan => Value::Bool(left >= right),
                _ => return None,
            }
        }
    })
}

/// `String.fromCharCode` of numbers, which it takes modulo 2^16.
fn from_char_code(arguments: &[Value]) -> Option<Value> {
    let units = arguments
        .iter()
        .map(|argument| Some(js::uint32(argument.number()?) as u16))
        .collect::<Option<_>>()?;
    Some(Value::String(units))
}

/// `atob`: the forgiving base64 decode, giving one code unit per byte.
fn atob(text: &[u16]) -> Option<Value> {
    let mut data: Vec<u8> = text
        .iter()
        .filter(|&&unit| !matches!(unit, 0x09 | 0x0a | 0x0c | 0x0d | 0x20))
        .map(|&unit| u8::try_from(unit).ok())
        .collect::<Option<_>>()?;
    if data.len().is_multiple_of(4) {
        for _ in 0..2 {
            if data.last() == Some(&b'=') {
                data.pop();
            }
        }
    }
    if data.len() % 4 == 1 {
        return None;
    }
    let mut bits = 0u32;
    let mut count = 0;
    let mut units = Vec::with_capacity(data.len() * 3 / 4);
    for byte in data {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        bits = bits << 6 | u32::from(digit);
        count += 6;
        if count >= 8 {
            count -= 8;
            units.push(((bits >> count) & 0xff) as u16);
        }
    }
    Some(Value::String(units.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::output::{Instruction, Position};

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn decoded(value: Option<Value>) -> Option<String> {
        match value? {
            Value::String(units) => String::from_utf16(&units).ok(),
            _ => None,
        }
    }

    #[test]
    fn atob_follows_the_forgiving_base64_decode() {
        assert_eq!(decoded(atob(&units("ZiV4M2onbg=="))).unwrap(), "f%x3j'n");
        assert_eq!(decoded(atob(&units("ZiV4M2onbg"))).unwrap(), "f%x3j'n");
        assert_eq!(decoded(atob(&units(" Zm9v\n"))).unwrap(), "foo");
        assert!(atob(&units("Zm9vY")).is_none(), "a length of 1 modulo 4");
        assert!(atob(&units("Zm=9v")).is_none(), "padding inside");
        assert!(atob(&units("Zm9v-")).is_none());
    }

    fn string(text: &str) -> Term {
        Term::Const(Constant::String(text.into()))
    }

    fn number(value: f64) -> Term {
        Term::Const(Constant::Number(value))
    }

    fn reg(register: u8) -> Term {
        Term::Reg(register)
    }

    fn get(object: Term, key: Term) -> Term {
        Term::Get(Box::new(object), Box::new(key))
    }

    fn binary(operator: BinaryOperator, left: Term, right: Term) -> Term {
        Term::Binary(operator, Box::new(left), Box::new(right))
    }

    fn call(callee: Term, arguments: Vec<Term>) -> Term {
        Term::Call {
            callee: Box::new(callee),
            this: None,
            arguments,
        }
    }

    fn closure(pc: u32) -> Term {
        Term::Closure {
            pc,
            key: 0,
            parameters: Vec::new(),
            arity: 1,
        }
    }

    fn path(conditions: Vec<(Term, bool)>, effects: Vec<Effect>, exit: Exit) -> Path {
        Path {
            conditions,
            effects,
            exit,
        }
    }

    /// Writes straight-line `code` at `start`, each instruction leading to the next and the
    /// last as given.
    fn code(listing: &mut Listing, start: u32, code: Vec<Vec<Path>>) {
        for (pc, paths) in (start..).zip(code) {
            listing.instructions.insert(
                pc,
                Instruction {
                    pc,
                    key: 0,
                    opcode: 0,
                    paths,
                },
            );
        }
    }

    fn next(pc: u32) -> Exit {
        Exit::Next { pc, key: 0 }
    }

    fn step(pc: u32, effects: Vec<Effect>) -> Vec<Path> {
        vec![path(Vec::new(), effects, next(pc + 1))]
    }

    fn returning(register: u8) -> Vec<Path> {
        let pop = Effect::Let(0, call(Term::Global(POP.into()), Vec::new()));
        vec![path(
            Vec::new(),
            vec![Effect::Set(73, reg(register)), pop],
            Exit::Return,
        )]
    }

    /// A program like the builds that encode strings: a factory at 100 keeps `globalThis` and
    /// `String` in cells and returns a decoder at 200, which XORs `atob(text)` with alternating
    /// key bytes and joins the characters through the apply helper. The function at 300 stores
    /// a decoder in cell 5, and the function at 400, which it creates, calls it.
    fn program() -> Listing {
        use BinaryOperator as Op;
        let mut listing = Listing {
            functions: [0, 100, 200, 300, 400]
                .map(|pc| Position::new(pc, 0))
                .to_vec(),
            ..Listing::default()
        };
        // Program start: the method and property names the program uses throughout.
        code(
            &mut listing,
            0,
            vec![
                step(0, vec![Effect::Set(6, string("charCodeAt"))]),
                step(1, vec![Effect::Set(7, string("String"))]),
                step(2, vec![Effect::Set(9, string("length"))]),
                vec![path(
                    Vec::new(),
                    vec![Effect::Set(1, closure(300))],
                    Exit::Return,
                )],
            ],
        );
        code(
            &mut listing,
            100,
            vec![
                step(100, vec![Effect::Set(15, reg(98))]),
                step(101, vec![Effect::NewCell(29), Effect::SetCell(29, reg(15))]),
                step(
                    102,
                    vec![Effect::NewCell(31), Effect::Set(12, get(reg(15), reg(7)))],
                ),
                step(103, vec![Effect::SetCell(31, reg(12))]),
                step(104, vec![Effect::Set(12, closure(200))]),
                returning(12),
            ],
        );
        let xor = |key: f64| {
            vec![
                Effect::Let(0, call(get(reg(38), reg(6)), vec![reg(35)])),
                Effect::Set(21, binary(Op::BitwiseXOR, Term::Temp(0), number(key))),
            ]
        };
        code(
            &mut listing,
            200,
            vec![
                step(200, vec![Effect::Set(18, reg(98))]),
                step(201, vec![Effect::Set(12, Term::Cell(29))]),
                step(
                    202,
                    vec![
                        Effect::Let(0, call(get(reg(12), string("atob")), vec![reg(18)])),
                        Effect::Set(38, Term::Temp(0)),
                    ],
                ),
                step(
                    203,
                    vec![
                        Effect::Set(35, number(0.0)),
                        Effect::Set(19, Term::Array(Vec::new())),
                    ],
                ),
                // 204: loop while characters remain.
                vec![
                    path(
                        vec![(binary(Op::LessThan, reg(35), get(reg(38), reg(9))), true)],
                        Vec::new(),
                        next(205),
                    ),
                    path(
                        vec![(binary(Op::LessThan, reg(35), get(reg(38), reg(9))), false)],
                        Vec::new(),
                        next(210),
                    ),
                ],
                step(205, xor(11.0)),
                step(
                    206,
                    vec![
                        Effect::Let(0, call(get(reg(19), string("push")), vec![reg(21)])),
                        Effect::Set(35, binary(Op::Addition, reg(35), number(1.0))),
                    ],
                ),
                // 207: an odd count ends the text.
                vec![
                    path(
                        vec![(binary(Op::LessThan, reg(35), get(reg(38), reg(9))), true)],
                        Vec::new(),
                        next(208),
                    ),
                    path(
                        vec![(binary(Op::LessThan, reg(35), get(reg(38), reg(9))), false)],
                        Vec::new(),
                        next(210),
                    ),
                ],
                step(208, xor(64.0)),
                vec![path(
                    Vec::new(),
                    vec![
                        Effect::Let(0, call(get(reg(19), string("push")), vec![reg(21)])),
                        Effect::Set(35, binary(Op::Addition, reg(35), number(1.0))),
                    ],
                    next(204),
                )],
                step(
                    210,
                    vec![Effect::Set(12, Term::Cell(31)), Effect::Set(16, string(""))],
                ),
                step(
                    211,
                    vec![Effect::Set(21, get(reg(12), string("fromCharCode")))],
                ),
                step(
                    212,
                    vec![
                        Effect::Let(
                            0,
                            call(
                                Term::Global("RZ".into()),
                                vec![Term::Opaque("function".into()), reg(21), reg(12), reg(19)],
                            ),
                        ),
                        Effect::Set(16, binary(Op::Addition, reg(16), Term::Temp(0))),
                    ],
                ),
                returning(16),
            ],
        );
        code(
            &mut listing,
            300,
            vec![
                step(300, vec![Effect::NewCell(5), Effect::Set(18, closure(100))]),
                step(
                    301,
                    vec![Effect::Set(12, get(reg(13), string("globalThis")))],
                ),
                step(
                    302,
                    vec![
                        Effect::Let(0, call(reg(18), vec![reg(12)])),
                        Effect::Set(25, Term::Temp(0)),
                    ],
                ),
                step(303, vec![Effect::SetCell(5, reg(25))]),
                step(304, vec![Effect::Set(12, closure(400))]),
                returning(12),
            ],
        );
        code(
            &mut listing,
            400,
            vec![
                step(
                    400,
                    vec![
                        Effect::Set(18, reg(98)),
                        Effect::Set(18, string("byF/IQ==")),
                    ],
                ),
                step(
                    401,
                    vec![
                        Effect::Let(0, call(Term::Cell(5), vec![reg(18)])),
                        Effect::Set(15, Term::Temp(0)),
                    ],
                ),
                step(402, vec![Effect::Set(16, get(reg(12), reg(15)))]),
                returning(16),
            ],
        );
        listing
    }

    #[test]
    fn decoder_calls_become_loads_of_what_they_return() {
        let mut listing = program();
        fold(&mut listing);
        assert_eq!(
            listing.instructions[&401].paths[0].effects,
            [
                Effect::Let(0, string("data")),
                Effect::Set(15, string("data"))
            ],
        );
        assert_eq!(
            listing.instructions[&400].paths[0].effects[1],
            Effect::Set(18, string("byF/IQ==")),
            "the encoded text stays where the program loads it"
        );
        assert_eq!(listing.encoded, BTreeSet::from(["byF/IQ==".to_owned()]));
    }

    /// A cell assigned text reads as that text in the functions its function creates, but not
    /// in the function itself, nor anywhere once a function that reads it is created earlier.
    #[test]
    fn text_cells_read_as_their_text_in_created_functions() {
        let fold_with = |early_reader_reads: bool| {
            let mut listing = program();
            let functions = [500, 600, 700].map(|pc| Position::new(pc, 0));
            listing.functions.extend(functions);
            code(
                &mut listing,
                500,
                vec![
                    // A function created before the assignment.
                    step(500, vec![Effect::NewCell(7), Effect::Set(15, closure(700))]),
                    step(501, vec![Effect::SetCell(7, string("entryType"))]),
                    step(502, vec![Effect::Set(12, Term::Cell(7))]),
                    step(503, vec![Effect::Set(14, closure(600))]),
                    returning(14),
                ],
            );
            code(
                &mut listing,
                600,
                vec![
                    step(600, vec![Effect::Set(12, Term::Cell(7))]),
                    returning(12),
                ],
            );
            let early = if early_reader_reads {
                Term::Cell(7)
            } else {
                reg(98)
            };
            code(
                &mut listing,
                700,
                vec![step(700, vec![Effect::Set(16, early)]), returning(16)],
            );
            fold(&mut listing);
            listing
        };
        let listing = fold_with(false);
        assert_eq!(
            listing.instructions[&600].paths[0].effects,
            [Effect::Set(12, string("entryType"))]
        );
        assert_eq!(
            listing.instructions[&502].paths[0].effects,
            [Effect::Set(12, Term::Cell(7))],
            "the assigning function's own read is left"
        );
        assert!(!listing.encoded.contains("entryType"));
        let listing = fold_with(true);
        assert_eq!(
            listing.instructions[&600].paths[0].effects,
            [Effect::Set(12, Term::Cell(7))],
            "a function created before the assignment reads the cell"
        );
    }

    /// Some builds set the result after popping the return address.
    #[test]
    fn results_set_after_the_pop_are_found() {
        let mut listing = program();
        for instruction in listing.instructions.values_mut() {
            for path in &mut instruction.paths {
                if path.exit == Exit::Return && path.effects.len() == 2 {
                    path.effects.reverse();
                }
            }
        }
        fold(&mut listing);
        assert_eq!(
            listing.instructions[&401].paths[0].effects,
            [
                Effect::Let(0, string("data")),
                Effect::Set(15, string("data"))
            ],
        );
    }

    #[test]
    fn a_cell_another_function_declares_is_not_the_decoder() {
        let mut listing = program();
        // The calling function declares its own cell 5, which holds no decoder.
        let start = &mut listing.instructions.get_mut(&400).unwrap().paths[0].effects;
        start.insert(0, Effect::NewCell(5));
        fold(&mut listing);
        assert_eq!(
            listing.instructions[&401].paths[0].effects[1],
            Effect::Set(15, Term::Temp(0))
        );
    }

    #[test]
    fn unmodeled_operations_leave_the_call() {
        let mut listing = program();
        // The decoder reads a property of the global object evaluation does not model.
        listing.instructions.get_mut(&201).unwrap().paths[0].effects =
            vec![Effect::Set(12, get(Term::Cell(29), string("crypto")))];
        fold(&mut listing);
        assert_eq!(
            listing.instructions[&401].paths[0].effects[1],
            Effect::Set(15, Term::Temp(0))
        );
    }
}
