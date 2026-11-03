//! Disassembles instructions reachable from program entries.
//!
//! A worklist visits each [`Position`] once. When it empties, retries unresolved hidden
//! branches with newly discovered strings; see [`Machine::disassemble_from`]. Stops once every
//! [`Probe`] has been tried with every candidate.
//!
//! Comparison handlers account for most of the work. A [`Shortcut`] skips strings whose hash
//! cannot match. Before finishing, retries unresolved probes without shortcuts, so unsupported
//! handler shapes affect speed without changing results.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::Infallible;
use std::ops::ControlFlow;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, ScopedJoinHandle};

use anyhow::{Result, bail};
use indexmap::IndexSet;
use rustc_hash::{FxBuildHasher, FxHashSet};
use swc_core::ecma::ast::BinaryOp;

use super::interpret::Way;
use super::machine::{Definition, Loaded, Machine};
use super::output::{
    Constant, Effect, Exit, Failure, Hidden, Instruction, Listing, Path, Position, Term,
};
use super::value::Value;
use super::{HashMap, convert, dataflow, packed_names};
use crate::candidates;

impl Machine<'_> {
    /// Follows entry paths, created functions, and installed exception handlers.
    pub fn disassemble(&self, program: &[u8]) -> Result<Listing> {
        self.disassemble_from(program, &[self.entry()], &[])
    }

    /// Disassembles from `entries`, also trying candidate `strings`.
    ///
    /// Some handlers hash a register string and use the hash to unmask a branch target. These
    /// branches are retried with the program's state-name constants and `strings` until no new
    /// code is found.
    pub fn disassemble_from(
        &self,
        program: &[u8],
        entries: &[Position],
        strings: &[&str],
    ) -> Result<Listing> {
        let mut walk = Walk::default();
        walk.listing.functions.push(self.entry());
        // API names are tried as given, whatever their characters.
        walk.candidates
            .extend(strings.iter().map(|&text| text.to_owned()));
        for &entry in entries {
            walk.enqueue(entry)?;
        }
        let loaded = self.load(program);
        thread::scope(|scope| -> Result<()> {
            let decoders = Decoders::start(scope, self.definition, program);
            loop {
                decoders.walk(&mut walk, self, &loaded)?;
                if !(walk.retry(self, &loaded)? || walk.drop_shortcuts()) {
                    return Ok(());
                }
            }
        })?;
        let mut listing = walk.listing;
        // Discovery order must not affect the output.
        listing.functions[1..].sort_unstable();
        listing.hidden.sort_by(|first, second| {
            (first.compare, &first.string).cmp(&(second.compare, &second.string))
        });
        listing.failures.sort_unstable_by_key(|failure| failure.pc);
        fuse_method_calls(&mut listing);
        packed_names::fold(&mut listing);
        Ok(listing)
    }
}

/// Threads that decode positions alongside the walk, each with a machine of its own: the
/// interpreter's values are not shareable, but a decoded [`Instruction`] is plain data.
///
/// Decoding a position reads only the program and the machine, never the walk, so positions can
/// be decoded in any order and on any thread. Whoever decodes an instruction queues the positions
/// it leads to ([`successors`]), which the walk will reach once it adds the instruction, so the
/// decoding runs ahead of the walk across every branch at once. The walk still adds instructions
/// in the order it reaches them, which makes the listing the one a single thread would produce.
struct Decoders<'scope> {
    queue: Arc<Queue>,
    decoded: Receiver<(Position, Decoded)>,
    /// Kept so the channel stays open while no worker has started.
    _sender: Sender<(Position, Decoded)>,
    _workers: Vec<ScopedJoinHandle<'scope, ()>>,
}

/// What decoding one position gave, or why a worker could not start.
enum Decoded {
    Instruction(Result<Instruction, Failure>),
    Unavailable(anyhow::Error),
}

#[derive(Default)]
struct Queue {
    waiting: Mutex<Waiting>,
    ready: Condvar,
}

#[derive(Default)]
struct Waiting {
    /// Positions the walk has reached, decoded first.
    reached: VecDeque<Position>,
    /// Positions decoded instructions lead to, which the walk will reach.
    ahead: VecDeque<Position>,
    /// Positions taken for decoding.
    taken: FxHashSet<Position>,
    closed: bool,
}

impl Waiting {
    fn next(&mut self) -> Option<Position> {
        while let Some(position) = self.reached.pop_front().or_else(|| self.ahead.pop_front()) {
            if self.taken.insert(position) {
                return Some(position);
            }
        }
        None
    }
}

impl Queue {
    /// Queues positions the walk reached, unless they are already taken.
    fn reach(&self, positions: impl IntoIterator<Item = Position>) {
        let mut waiting = self.waiting.lock().expect("decode queue lock");
        let before = waiting.reached.len();
        for position in positions {
            if !waiting.taken.contains(&position) {
                waiting.reached.push_back(position);
            }
        }
        Self::wake(&self.ready, waiting.reached.len() - before);
    }

    /// Queues the positions `instruction` leads to.
    fn look_ahead(&self, instruction: &Instruction) {
        let mut waiting = self.waiting.lock().expect("decode queue lock");
        let before = waiting.ahead.len();
        for path in &instruction.paths {
            for position in successors(instruction.pc, path, |_| {}) {
                if !waiting.taken.contains(&position) {
                    waiting.ahead.push_back(position);
                }
            }
        }
        Self::wake(&self.ready, waiting.ahead.len() - before);
    }

    fn wake(ready: &Condvar, added: usize) {
        match added {
            0 => {}
            1 => ready.notify_one(),
            _ => ready.notify_all(),
        }
    }

    /// Takes a position to decode without waiting, marking it taken; `false` if it is taken.
    fn take_this(&self, position: Position) -> bool {
        self.waiting
            .lock()
            .expect("decode queue lock")
            .taken
            .insert(position)
    }

    /// The next position to decode, without waiting.
    fn take(&self) -> Option<Position> {
        self.waiting.lock().expect("decode queue lock").next()
    }

    /// The next position to decode, waiting for one; `None` once the queue closes.
    fn wait(&self) -> Option<Position> {
        let mut waiting = self.waiting.lock().expect("decode queue lock");
        loop {
            if waiting.closed {
                return None;
            }
            if let Some(next) = waiting.next() {
                return Some(next);
            }
            waiting = self.ready.wait(waiting).expect("decode queue lock");
        }
    }

    fn close(&self) {
        self.waiting.lock().expect("decode queue lock").closed = true;
        self.ready.notify_all();
    }
}

/// Decoding threads beside the walk's own: enough to keep a few cores busy, while leaving room
/// for other work on the machine.
fn decoding_threads() -> usize {
    thread::available_parallelism().map_or(1, |cores| cores.get().min(8)) - 1
}

impl<'scope> Decoders<'scope> {
    fn start<'env>(
        scope: &'scope thread::Scope<'scope, 'env>,
        definition: &'env Definition,
        program: &'env [u8],
    ) -> Self {
        let queue = Arc::new(Queue::default());
        let (sender, decoded) = mpsc::channel();
        let workers = (0..decoding_threads())
            .map(|_| {
                let (queue, sender) = (queue.clone(), sender.clone());
                scope.spawn(move || {
                    let machine = match Machine::try_new(definition) {
                        Ok(machine) => machine,
                        Err(error) => {
                            let _ = sender.send((Position::new(0, 0), Decoded::Unavailable(error)));
                            return;
                        }
                    };
                    let loaded = machine.load(program);
                    while let Some(position) = queue.wait() {
                        let instruction = machine.decode(&loaded, position.pc, position.key, &[]);
                        if let Ok(instruction) = &instruction {
                            queue.look_ahead(instruction);
                        }
                        if sender
                            .send((position, Decoded::Instruction(instruction)))
                            .is_err()
                        {
                            return;
                        }
                    }
                })
            })
            .collect();
        Self {
            queue,
            decoded,
            _sender: sender,
            _workers: workers,
        }
    }

    /// Empties the walk's queue: adds each queued position's instruction in queue order,
    /// decoding positions itself while the one it needs is not ready, and queueing what each
    /// reaches.
    fn walk<'a>(
        &self,
        walk: &mut Walk,
        machine: &Machine<'a>,
        loaded: &Loaded<'_, 'a>,
    ) -> Result<()> {
        // The walk's positions in the order it reached them, and the instructions decoded
        // before the walk needed them.
        let mut order: VecDeque<Position> = VecDeque::new();
        let mut decoded: HashMap<Position, Result<Instruction, Failure>> = HashMap::default();
        let reach = |walk: &mut Walk, order: &mut VecDeque<Position>| {
            let reached: Vec<Position> = walk.queue.drain(..).collect();
            self.queue.reach(reached.iter().copied());
            order.extend(reached);
        };
        reach(walk, &mut order);
        while let Some(position) = order.pop_front() {
            let instruction = loop {
                if let Some(instruction) = decoded.remove(&position) {
                    break instruction;
                }
                // Decode what is needed now if nobody has taken it, else whatever is queued,
                // and otherwise wait for the workers.
                let (at, result) = if self.queue.take_this(position) {
                    (
                        position,
                        Decoded::Instruction(self.decode(machine, loaded, position)),
                    )
                } else if let Ok(answer) = self.decoded.try_recv() {
                    answer
                } else if let Some(other) = self.queue.take() {
                    (
                        other,
                        Decoded::Instruction(self.decode(machine, loaded, other)),
                    )
                } else {
                    self.decoded.recv().expect("the walk keeps a sender")
                };
                match result {
                    Decoded::Instruction(instruction) => {
                        decoded.insert(at, instruction);
                    }
                    Decoded::Unavailable(error) => {
                        return Err(error.context("starting a decoding thread"));
                    }
                }
            };
            match instruction {
                Ok(instruction) => walk.add(machine, loaded, instruction)?,
                Err(failure) => walk.listing.failures.push(failure),
            }
            // A hidden branch is revealed by a probe and a candidate string; its code often
            // leads to the next one. Retrying as soon as either turns up, rather than once the
            // queue drains, lets the code behind it be decoded alongside the rest.
            if walk.found != walk.retried {
                walk.retry(machine, loaded)?;
            }
            reach(walk, &mut order);
        }
        Ok(())
    }

    /// Decodes `position` on the walk's own thread, looking ahead as the workers do.
    fn decode<'a>(
        &self,
        machine: &Machine<'a>,
        loaded: &Loaded<'_, 'a>,
        position: Position,
    ) -> Result<Instruction, Failure> {
        let instruction = machine.decode(loaded, position.pc, position.key, &[]);
        if let Ok(instruction) = &instruction {
            self.queue.look_ahead(instruction);
        }
        instruction
    }
}

impl Drop for Decoders<'_> {
    fn drop(&mut self) {
        self.queue.close();
    }
}

/// The positions `path` of the instruction at `from` leads to: where it continues, the functions
/// it creates and the exception handlers it installs. Calls `each` with every term of its
/// effects.
fn successors(from: u32, path: &Path, mut each: impl FnMut(&Term)) -> Vec<Position> {
    let continues = match &path.exit {
        // Handlers update a local program counter and store it when they finish. If a handler
        // stops early, the stored counter remains just past the opcode, pointing into its
        // operands.
        Exit::Unfollowed { pc, .. } if *pc == from + 1 => None,
        exit => exit.continues_at(),
    };
    let mut next: Vec<Position> = continues.into_iter().collect();
    for effect in &path.effects {
        effect.visit_terms(&mut |term| {
            match term {
                Term::Closure { pc, key, .. } => next.push(Position::new(*pc, *key)),
                Term::Array(frame) => next.extend(catch_frame(frame)),
                _ => {}
            }
            each(term);
        });
    }
    next
}

#[derive(Default)]
struct Walk {
    listing: Listing,
    /// Reached program counters with their dispatch keys and the first instruction to reach each
    /// one, if any.
    visited: HashMap<u32, (u8, Option<u32>)>,
    /// The instruction whose successors are being queued.
    from: Option<u32>,
    queue: VecDeque<Position>,
    /// Candidate state names in the order found. Observed state comparisons always use
    /// complete string constants.
    candidates: IndexSet<String, FxBuildHasher>,
    /// Unresolved hidden branches, by compare pc and register.
    probes: BTreeMap<(u32, u8), Probe>,
    /// Candidate hashes indexed by the instance field that caches them (see [`Shortcut`]).
    hashes: HashMap<String, HashMap<String, f64>>,
    /// Probes and candidates found so far, and how many of them the last retry saw.
    found: u64,
    retried: u64,
}

/// A compare that may hide a branch, retried with candidate strings.
struct Probe {
    key: u8,
    /// Where the compare goes when the string does not match.
    fallthrough: Option<Position>,
    /// How many of [`Walk::candidates`] it has been tried with.
    tried: usize,
    shortcut: Option<Shortcut>,
}

impl Walk {
    fn enqueue(&mut self, position: Position) -> Result<()> {
        let Position { pc, key } = position;
        match self.visited.get(&pc) {
            None => {
                self.visited.insert(pc, (key, self.from));
                self.queue.push_back(position);
                Ok(())
            }
            Some(&(earlier, _)) if earlier == key => Ok(()),
            Some(&(earlier, first)) => {
                let origin =
                    |from: Option<u32>| from.map_or("an entry".to_owned(), |pc| format!("pc {pc}"));
                bail!(
                    "pc {pc} is reached under keys {earlier} from {} and {key} from {}",
                    origin(first),
                    origin(self.from)
                )
            }
        }
    }

    fn add<'a>(
        &mut self,
        machine: &Machine<'a>,
        loaded: &Loaded<'_, 'a>,
        instruction: Instruction,
    ) -> Result<()> {
        self.from = Some(instruction.pc);
        for path in &instruction.paths {
            self.follow(path)?;
        }
        // A comparison with register-dependent control flow that the interpreter cannot resolve
        // may hide a branch.
        let mut registers = BTreeSet::new();
        let unfollowed = instruction
            .paths
            .iter()
            .filter(|path| matches!(path.exit, Exit::Unfollowed { .. }))
            .flat_map(|path| &path.conditions);
        for (condition, _) in unfollowed {
            condition.visit(&mut |term| {
                if let Term::Reg(register) = term {
                    registers.insert(*register);
                }
            });
        }
        let fallthrough = instruction
            .paths
            .iter()
            .find_map(|path| path.exit.continues_at());
        let (pc, key) = (instruction.pc, instruction.key);
        for register in registers {
            let probe = Probe {
                key,
                fallthrough,
                tried: 0,
                shortcut: Shortcut::learn(machine, loaded, pc, key, register),
            };
            self.probes.insert((pc, register), probe);
            self.found += 1;
        }
        self.listing.instructions.insert(pc, instruction);
        Ok(())
    }

    fn follow(&mut self, path: &Path) -> Result<()> {
        let from = self.from.expect("an instruction is being added");
        let (functions, candidates, found) = (
            &mut self.listing.functions,
            &mut self.candidates,
            &mut self.found,
        );
        let next = successors(from, path, |term| match term {
            Term::Closure { pc, key, .. } => {
                let entry = Position::new(*pc, *key);
                if !functions.contains(&entry) {
                    functions.push(entry);
                }
            }
            Term::Const(Constant::String(text))
                if is_state_name(text) && candidates.insert(text.clone()) =>
            {
                *found += 1;
            }
            _ => {}
        });
        for position in next {
            self.enqueue(position)?;
        }
        Ok(())
    }

    /// Retries unresolved probes with new candidates and queues revealed targets. Returns
    /// whether any target was found.
    fn retry<'a>(&mut self, machine: &Machine<'a>, loaded: &Loaded<'_, 'a>) -> Result<bool> {
        self.retried = self.found;
        let mut hits = Vec::new();
        for (&(compare, register), probe) in &mut self.probes {
            let mut shortcut = probe.shortcut.as_ref().map(|shortcut| {
                (
                    shortcut,
                    self.hashes.entry(shortcut.field.clone()).or_default(),
                )
            });
            for candidate in self.candidates.iter().skip(probe.tried) {
                if let Some((shortcut, hashes)) = &shortcut
                    && hashes
                        .get(candidate)
                        .is_some_and(|&hash| hash != shortcut.expected)
                {
                    continue;
                }
                let known = [(register, Value::string(candidate))];
                let Ok((_, ways)) = machine.ways(loaded, compare, probe.key, &known) else {
                    continue;
                };
                if let Some((shortcut, hashes)) = &mut shortcut
                    && let Some(hash) = shortcut.hash(&ways)
                {
                    hashes.insert(candidate.clone(), hash);
                }
                let before = hits.len();
                for way in &ways {
                    let Exit::Next { pc, key } = way.path.exit else {
                        continue;
                    };
                    let target = Position::new(pc, key);
                    if Some(target) != probe.fallthrough {
                        let string = candidate.clone();
                        hits.push(Hidden {
                            compare,
                            string,
                            target,
                        });
                    }
                }
                // A hashed compare matches one string.
                if hits.len() > before {
                    break;
                }
            }
            probe.tried = self.candidates.len();
        }
        let revealed = !hits.is_empty();
        for hit in hits {
            // Once a compare has revealed its target, no other string can.
            let compare = hit.compare;
            self.probes.retain(|&(pc, _), _| pc != compare);
            self.from = Some(compare);
            self.enqueue(hit.target)?;
            self.listing.hidden.push(hit);
        }
        Ok(revealed)
    }

    /// Removes shortcuts from unresolved probes so the next retry tests every candidate string.
    /// Returns whether a shortcut was removed.
    fn drop_shortcuts(&mut self) -> bool {
        let mut dropped = false;
        for probe in self.probes.values_mut() {
            if probe.shortcut.take().is_some() {
                probe.tried = 0;
                dropped = true;
            }
        }
        dropped
    }
}

/// The hash a comparison handler expects. Supported handlers cache the last string and its hash
/// in two instance fields, then compare the hash against a program value.
struct Shortcut {
    /// The field caching the hash.
    field: String,
    expected: f64,
}

/// Sample strings that differ from every candidate.
const SAMPLES: [&str; 2] = ["\u{1}", "\u{2}"];

impl Shortcut {
    /// Runs the comparison handler at `pc` with two sample strings in `register`. Identifies
    /// the string cache as the field containing the sample, and the hash as the numeric field
    /// that changes between samples. A third run presets the string cache and leaves the hash
    /// unknown to reveal the expected hash in branch conditions.
    fn learn<'a>(
        machine: &Machine<'a>,
        loaded: &Loaded<'_, 'a>,
        pc: u32,
        key: u8,
        register: u8,
    ) -> Option<Self> {
        let run = |loaded: &Loaded<'_, 'a>, sample: &str| {
            let known = [(register, Value::string(sample))];
            machine
                .ways(loaded, pc, key, &known)
                .ok()
                .map(|(_, ways)| ways)
        };
        let fields = |sample| {
            let [way] = <[Way<'a>; 1]>::try_from(run(loaded, sample)?).ok()?;
            Some(way.fields)
        };
        let (first, second) = (fields(SAMPLES[0])?, fields(SAMPLES[1])?);
        let cache = first.iter().find_map(|(name, value)| match value {
            Value::String(text) if *text == SAMPLES[0].into() => Some(name),
            _ => None,
        })?;
        let hashes = first
            .iter()
            .filter(|&(name, value)| match (value, second.get(name)) {
                (Value::Number(a), Some(Value::Number(b))) => a != b,
                _ => false,
            });
        let (field, _) = candidates::exactly_one(hashes, "hash field").ok()?;
        let mut preset = loaded.clone();
        preset.fields.extend([
            (cache.clone(), Value::string(SAMPLES[0])),
            (field.clone(), Value::symbolic(Term::Field(field.clone()))),
        ]);
        let ways = run(&preset, SAMPLES[0])?;
        let mut compared = ways
            .iter()
            .flat_map(|way| &way.path.conditions)
            .filter_map(|(condition, _)| compared(condition, field));
        let expected = compared.next()?;
        compared.all(|other| other == expected).then(|| Self {
            field: field.clone(),
            expected,
        })
    }

    /// Returns the cached hash if it agrees across all paths in `ways`.
    fn hash(&self, ways: &[Way<'_>]) -> Option<f64> {
        let mut hashes = ways.iter().map(|way| match way.fields.get(&self.field) {
            Some(Value::Number(hash)) => Some(*hash),
            _ => None,
        });
        let hash = hashes.next()??;
        hashes.all(|other| other == Some(hash)).then_some(hash)
    }
}

/// The number `condition` compares the instance field `field` with, if any.
fn compared(condition: &Term, field: &str) -> Option<f64> {
    let mut number = None;
    condition.visit(&mut |term| {
        if let Term::Binary(
            BinaryOp::EqEqEq | BinaryOp::NotEqEq | BinaryOp::EqEq | BinaryOp::NotEq,
            left,
            right,
        ) = term
            && let (Term::Field(name), Term::Const(Constant::Number(value)))
            | (Term::Const(Constant::Number(value)), Term::Field(name)) = (&**left, &**right)
            && name == field
        {
            number = Some(*value);
        }
    });
    number
}

/// Whether `text` looks like the observed control-flow state names: short and alphanumeric, or
/// the empty initial state.
fn is_state_name(text: &str) -> bool {
    text.len() <= 16 && text.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

/// `[pc, key, cells snapshot, stack depth]`: where the run loop resumes when an exception
/// reaches it.
#[must_use]
pub fn catch_frame(elements: &[Term]) -> Option<Position> {
    match elements {
        [
            Term::Const(Constant::Number(pc)),
            Term::Const(Constant::Number(key)),
            _,
            _,
        ] => Some(Position::new(convert::position(*pc)?, convert::byte(*key)?)),
        _ => None,
    }
}

/// Exception continuations enter without the registers known on the normal path.
pub(super) fn exception_entries(listing: &Listing) -> BTreeSet<u32> {
    let mut entries = BTreeSet::new();
    for instruction in listing.instructions.values() {
        for effect in instruction.effects() {
            effect.visit_terms(&mut |term| {
                if let Term::Array(frame) = term
                    && let Some(position) = catch_frame(frame)
                {
                    entries.insert(position.pc);
                }
            });
        }
    }
    entries
}

/// Rewrites method calls to the form listing readers expect. Some builds call `object[key]`
/// directly; others load the method into a register and later call that register with `object`
/// as receiver.
fn fuse_method_calls(listing: &mut Listing) {
    // Unrecorded entries, such as functions and hidden targets, start with no known loads.
    let functions = listing.functions.iter().map(|function| function.pc);
    let hidden = listing.hidden.iter().map(|hidden| hidden.target.pc);
    let incoming = incoming_loads(listing, functions.chain(hidden));
    // Exception continuations also start with no known loads, without erasing the normal path's.
    let exceptional = incoming_loads(listing, exception_entries(listing));
    for (pc, instruction) in &mut listing.instructions {
        let Some(entry) = incoming.get(pc).or_else(|| exceptional.get(pc)) else {
            continue;
        };
        for path in &mut instruction.paths {
            let mut loads = entry.clone();
            for effect in &mut path.effects {
                if let Effect::Let(_, term) = effect {
                    fuse_call(term, &loads);
                }
                update_loads(&mut loads, effect);
            }
        }
    }
}

/// The loads known on entry to each instruction reachable from `entries`.
fn incoming_loads(
    listing: &Listing,
    entries: impl IntoIterator<Item = u32>,
) -> BTreeMap<u32, Loads> {
    let entries = entries.into_iter().map(|pc| (pc, Loads::default()));
    let ControlFlow::Continue(incoming) = dataflow::forward(listing, entries, |_, path, loads| {
        for effect in &path.effects {
            update_loads(loads, effect);
        }
        ControlFlow::<Infallible, bool>::Continue(true)
    });
    incoming
}

/// Tracks registers holding `object[key]` while the object and key registers remain unchanged.
/// Saves facts at each instruction's entry. Uses a vector because these sets are small.
#[derive(Clone, Default)]
struct Loads(Vec<(u8, Load)>);

impl Loads {
    fn get(&self, register: u8) -> Option<&Load> {
        self.0
            .iter()
            .find_map(|(loaded, load)| (*loaded == register).then_some(load))
    }
}

impl dataflow::Facts for Loads {
    fn meet(&mut self, other: &Self) -> bool {
        let before = self.0.len();
        self.0
            .retain(|(register, load)| other.get(*register) == Some(load));
        self.0.len() < before
    }
}

/// `object[key]`, with `object` in a register.
#[derive(Clone, PartialEq)]
struct Load {
    object: u8,
    key: Term,
}

fn update_loads(loads: &mut Loads, effect: &Effect) {
    let Effect::Set(register, value) = effect else {
        return;
    };
    loads.0.retain(|(loaded, load)| {
        loaded != register && load.object != *register && load.key != Term::Reg(*register)
    });
    if let Term::Get(object, key) = value
        && let Term::Reg(object) = **object
        && object != *register
        && match **key {
            Term::Const(_) => true,
            Term::Reg(key) => key != *register,
            _ => false,
        }
    {
        let key = (**key).clone();
        loads.0.push((*register, Load { object, key }));
    }
}

/// Rewrites a call of a register still holding `object[key]` with `object` as receiver. Calls
/// are recorded as separate temporaries (see `Run::apply`), never nested inside another term.
fn fuse_call(term: &mut Term, loads: &Loads) {
    let Term::Call { callee, this, .. } = term else {
        return;
    };
    if let Term::Reg(function) = **callee
        && let Some(Term::Reg(receiver)) = this.as_deref()
        && let Some(load) = loads.get(function)
        && load.object == *receiver
    {
        **callee = Term::Get(Box::new(Term::Reg(load.object)), Box::new(load.key.clone()));
        *this = None;
    }
}
