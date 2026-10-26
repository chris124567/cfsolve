//! Discovers probes in execution order without classifying their results.
//!
//! Each probe uses three dispatcher states: record creation, collection, and timing completion.
//! Builds rename and physically reorder these states. State transitions determine execution
//! order.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::ops::RangeInclusive;

use anyhow::{Context, Result, ensure};

use crate::candidates;
use crate::js::JsValue;
use crate::listing::{self, Index, query};
use crate::stage2::records::WriteOrder;
use crate::vm::{self, Constant, Effect, Listing, Position, Term};

/// Maximum gap between consecutive dispatcher comparisons. Observed comparisons are a few dozen
/// instructions apart; unrelated hidden branches are thousands apart.
const DISPATCHER_GAP: u32 = 512;
/// A dispatcher compares more states than this; observed programs run 38 or 39 probes, three
/// states each.
const DISPATCHER_STATES: usize = 20;
/// Dispatcher boundary padding before the first and after the last comparison. Probe-state
/// walks must not enter this code.
const DISPATCHER_BEFORE: u32 = 200;
const DISPATCHER_AFTER: u32 = 40;
/// Longer strings are program data rather than names or API strings.
const FEATURE_LENGTH: usize = 2048;

/// One probe, as the program's dispatcher runs it.
pub(super) struct RawProbe {
    /// Its one-based position in the program's order.
    pub index: usize,
    /// The states that create its record, collect its result and finish it.
    pub states: [String; 3],
    pub token: String,
    pub input: JsValue,
    /// Where its collection function starts.
    pub function: Position,
    /// Collection-function strings in order, including duplicates.
    pub features: Vec<String>,
    /// The names it stores into registers or properties.
    pub outputs: BTreeSet<String>,
    pub writes: WriteOrder,
}

/// Discovered probes and instructions from record creation and completion, where envelope names
/// are written.
pub(super) struct ProbeDiscovery {
    pub probes: Vec<RawProbe>,
    pub creation: BTreeSet<u32>,
    pub finish: BTreeSet<u32>,
}

/// One dispatcher state: its code, and the states it sets next.
struct State<'program> {
    code: BTreeSet<u32>,
    next: BTreeSet<&'program str>,
}

/// Returns probes in dispatcher execution order with instructions reached by their
/// record-creation and completion states.
pub(super) fn discover(index: &Index<'_>, pool: &str) -> Result<ProbeDiscovery> {
    let listing = index.listing();
    let strings = index.strings();
    let mut compares: Vec<u32> = listing.hidden.iter().map(|hidden| hidden.compare).collect();
    compares.sort_unstable();
    compares.dedup();
    let group = compares
        .chunk_by(|previous, next| next - previous <= DISPATCHER_GAP)
        .max_by_key(|group| group.len())
        .context("no state dispatcher")?;
    ensure!(group.len() > DISPATCHER_STATES, "no probe dispatcher found");
    let dispatcher =
        group[0].saturating_sub(DISPATCHER_BEFORE)..=group[group.len() - 1] + DISPATCHER_AFTER;
    let states: BTreeMap<&str, u32> = listing
        .hidden
        .iter()
        .filter(|hidden| group.binary_search(&hidden.compare).is_ok())
        .map(|hidden| (hidden.string.as_str(), hidden.target.pc))
        .collect();
    let mut graph = BTreeMap::new();
    let outside = |pc: u32| !dispatcher.contains(&pc);
    for (&name, &start) in &states {
        let mut next = BTreeSet::new();
        let code = query::walk(listing, start, outside, |pc, instruction, pending| {
            pending.extend(instruction.exits());
            pending.extend(index.closures_in(pc..=pc));
            pending.extend(index.hidden_at(pc).iter().map(|hidden| hidden.target.pc));
            if let Some(text) = strings.get(&pc)
                && states.contains_key(text)
            {
                next.insert(*text);
            }
        });
        graph.insert(name, State { code, next });
    }
    let chain = chain(&graph)?;
    let (phase_triples, _) = chain.as_chunks::<3>();
    let mut probes = Vec::new();
    let mut traced = Vec::new();
    for (position, phases) in phase_triples.iter().enumerate() {
        let index_one = position + 1;
        let created = &graph[phases[0]].code;
        let values = descriptors(listing, strings, created, *dispatcher.start(), pool)?;
        let token = values
            .iter()
            .find(|text| text.contains("-1.2.1.1-"))
            .context("probe has no token")?;
        let input: JsValue = values
            .iter()
            .find_map(|text| serde_json::from_str(text).ok())
            .with_context(|| format!("probe {index_one} has no input"))?;
        let body = &listing.instructions[&states[phases[1]]];
        let function = body
            .effects()
            .find_map(|effect| match effect {
                Effect::Set(_, Term::Closure { pc, key, .. }) => Some(Position::new(*pc, *key)),
                _ => None,
            })
            .context("probe has no collection function")?;
        let (features, outputs) = collection_strings(index, function.pc, &dispatcher);
        traced.push(trace_writes(index, function.pc, &dispatcher));
        probes.push(RawProbe {
            index: index_one,
            states: (*phases).map(str::to_owned),
            token: token.clone(),
            input,
            function,
            features,
            outputs,
            writes: WriteOrder::default(),
        });
    }
    // Identify pending work by comparing all probes' writes and array pushes.
    let pending = pending_cell(&traced);
    for (probe, writes) in probes.iter_mut().zip(traced) {
        probe.writes = writes.order(pending);
    }
    let mut code = |name: &str| graph.remove(name).expect("chain states are known").code;
    Ok(ProbeDiscovery {
        probes,
        creation: code(chain[0]),
        finish: code(chain[2]),
    })
}

/// Follows states from the empty initial state. Each transition must select one state with code
/// until the chain ends.
fn chain<'a>(graph: &BTreeMap<&'a str, State<'a>>) -> Result<Vec<&'a str>> {
    let mut state = "";
    let mut chain = Vec::new();
    let mut seen = BTreeSet::new();
    loop {
        ensure!(seen.insert(state), "probe state cycle at {state}");
        chain.push(state);
        let next: Vec<&str> = graph
            .get(state)
            .context("unknown probe state")?
            .next
            .iter()
            .copied()
            .filter(|&name| name != state && !name.is_empty() && graph[name].code.len() > 2)
            .collect();
        if next.is_empty() {
            break;
        }
        state = candidates::exactly_one(next, &format!("next probe state after {state:?}"))?;
    }
    ensure!(
        chain.len() % 3 == 0,
        "incomplete probe chain: {} states",
        chain.len()
    );
    Ok(chain)
}

/// Collects decoded descriptors loaded by the record-creation state, followed by those loaded
/// before the dispatcher. Uses earlier register values only when the state does not overwrite
/// them.
fn descriptors(
    listing: &Listing,
    strings: &BTreeMap<u32, &str>,
    created: &BTreeSet<u32>,
    dispatcher_start: u32,
    pool: &str,
) -> Result<Vec<String>> {
    let mut values: Vec<String> = created
        .iter()
        .filter_map(|pc| listing::decode_string(strings.get(pc)?, pool).ok())
        .collect();
    let effects: Vec<&Effect> = created
        .iter()
        .filter_map(|pc| listing.instructions.get(pc))
        .flat_map(|instruction| instruction.effects())
        .collect();
    let assigned: BTreeSet<u8> = effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Set(register, _) => Some(*register),
            _ => None,
        })
        .collect();
    // The last string constant loaded into `register` before the dispatcher.
    let loaded = |register: u8| {
        listing
            .instructions
            .range(..dispatcher_start)
            .rev()
            .flat_map(|(_, instruction)| instruction.effects())
            .find_map(|effect| match effect {
                Effect::Set(target, Term::Const(Constant::String(text))) if *target == register => {
                    Some(text)
                }
                _ => None,
            })
    };
    for effect in effects {
        if let Some((_, arguments)) = effect.call()
            && let Some(Term::Reg(register)) = arguments.first()
            && !assigned.contains(register)
            && let Some(descriptor) = loaded(*register)
        {
            values.push(listing::decode_string(descriptor, pool)?);
        }
    }
    Ok(values)
}

/// Collects strings in program-counter and effect order, plus stored names. Includes closures,
/// catch handlers, and hidden branches because callbacks or deliberate exceptions may produce
/// results. Excludes dispatcher code.
fn collection_strings(
    index: &Index<'_>,
    entry: u32,
    dispatcher: &RangeInclusive<u32>,
) -> (Vec<String>, BTreeSet<String>) {
    let mut strings: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    let mut outputs = BTreeSet::new();
    let outside = |pc: u32| !dispatcher.contains(&pc);
    query::walk(
        index.listing(),
        entry,
        outside,
        |pc, instruction, pending| {
            pending.extend(instruction.exits());
            for path in &instruction.paths {
                let mut at_pc = Vec::new();
                for effect in &path.effects {
                    let output = match effect {
                        Effect::Set(_, term) => Some(term),
                        Effect::SetProperty { key, .. } => Some(&**key),
                        _ => None,
                    };
                    if let Some(Term::Const(Constant::String(name))) = output {
                        outputs.insert(name.clone());
                    }
                    effect.visit_terms(&mut |term| match term {
                        Term::Const(Constant::String(text)) if text.len() <= FEATURE_LENGTH => {
                            if !at_pc.contains(text) {
                                at_pc.push(text.clone());
                            }
                        }
                        Term::Closure { pc, .. } => pending.push(*pc),
                        // A frame pushed for a catch handler: [pc, key, ...].
                        Term::Array(frame) => {
                            pending.extend(vm::catch_frame(frame).map(|handler| handler.pc));
                        }
                        _ => {}
                    });
                }
                strings.entry(pc).or_default().extend(at_pc);
            }
            for hidden in index.hidden_at(pc) {
                strings.entry(pc).or_default().push(hidden.string.clone());
                pending.push(hidden.target.pc);
            }
        },
    );
    (strings.into_values().flatten().collect(), outputs)
}

/// Writes made by a collection function, in execution order.
#[derive(Default)]
struct Writes {
    /// Stored names.
    fields: Vec<String>,
    /// The synchronous body's stores.
    body_stores: Vec<BodyStore>,
    pushes: Vec<Push>,
}

/// A store in a collection function's synchronous body, with the creation sites of its
/// destination object and of the stored value, where they are known objects.
struct BodyStore {
    key: String,
    object: Option<u32>,
    value: Option<u32>,
}

/// An object the body pushes onto an array held in a cell.
struct Push {
    cell: u32,
    /// Where the pushed object was created.
    object: u32,
    /// How many of the body's stores precede the push.
    stores_before: usize,
}

impl Writes {
    /// Recovers field write order from the cell holding pending-work descriptors. A probe that
    /// queues a descriptor finishes before its callbacks write results. A field counts as
    /// written early only if the synchronous body writes it before queuing, to an object other
    /// than the descriptor's defaults. Writes encountered later belong to fallback paths.
    fn order(self, pending: Option<u32>) -> WriteOrder {
        let descriptor_pushes: Vec<&Push> = self
            .pushes
            .iter()
            .filter(|push| Some(push.cell) == pending)
            .collect();
        let Some(before) = descriptor_pushes
            .iter()
            .map(|push| push.stores_before)
            .min()
        else {
            return WriteOrder {
                fields: self.fields,
                late: Vec::new(),
            };
        };
        let descriptors: HashSet<u32> = descriptor_pushes.iter().map(|push| push.object).collect();
        // Objects stored into a descriptor hold its defaults.
        let defaults: HashSet<u32> = self
            .body_stores
            .iter()
            .filter(|store| {
                store
                    .object
                    .is_some_and(|object| descriptors.contains(&object))
            })
            .filter_map(|store| store.value)
            .collect();
        let is_default = |object: u32| defaults.contains(&object);
        let early: HashSet<&str> = self.body_stores[..before]
            .iter()
            .filter(|store| !store.object.is_some_and(is_default))
            .map(|store| store.key.as_str())
            .collect();
        let late = self
            .fields
            .iter()
            .filter(|field| !early.contains(field.as_str()))
            .cloned()
            .collect();
        WriteOrder {
            fields: self.fields,
            late,
        }
    }
}

/// Finds the cell receiving object pushes from the most probes. Requires at least two probes;
/// this cell holds pending-work descriptors.
fn pending_cell(probes: &[Writes]) -> Option<u32> {
    let mut pushers: HashMap<u32, usize> = HashMap::new();
    for writes in probes {
        let cells: HashSet<u32> = writes.pushes.iter().map(|push| push.cell).collect();
        for cell in cells {
            *pushers.entry(cell).or_default() += 1;
        }
    }
    let (cell, count) = pushers
        .into_iter()
        .max_by_key(|&(cell, count)| (count, cell))?;
    (count >= 2).then_some(cell)
}

/// Follows the collection function at `entry` in execution order. Visits the synchronous body
/// and its branches first, entering functions called at their creation sites. Then visits
/// created callbacks in creation order. Treats exception handlers as callbacks.
fn trace_writes(index: &Index<'_>, entry: u32, dispatcher: &RangeInclusive<u32>) -> Writes {
    let mut stores: HashMap<u32, Vec<&query::Store>> = HashMap::new();
    for store in index.stores() {
        stores.entry(store.pc).or_default().push(store);
    }
    let mut writes = Writes::default();
    let mut in_body = true;
    let mut callbacks = VecDeque::from([entry]);
    // The functions this body created that registers still hold.
    let mut closures: HashMap<u8, u32> = HashMap::new();
    let mut reached = HashSet::new();
    while let Some(start) = callbacks.pop_front() {
        let mut unvisited = vec![start];
        while let Some(pc) = unvisited.pop() {
            if dispatcher.contains(&pc) || !reached.insert(pc) {
                continue;
            }
            let Some(instruction) = index.listing().instructions.get(&pc) else {
                continue;
            };
            for store in stores.get(&pc).into_iter().flatten() {
                if !writes.fields.contains(&store.key) {
                    writes.fields.push(store.key.clone());
                }
                if in_body {
                    writes.body_stores.push(BodyStore {
                        key: store.key.clone(),
                        object: index.created_at(pc, &Term::Reg(store.object)),
                        value: index.created_at(pc, &store.value),
                    });
                }
            }
            let mut next = Vec::new();
            for path in &instruction.paths {
                for effect in &path.effects {
                    if let Some((callee, arguments)) = effect.call() {
                        // A function called where it is created runs synchronously.
                        if let Term::Reg(register) = callee {
                            next.extend(closures.get(register));
                        }
                        let stores_before = writes.body_stores.len();
                        if in_body
                            && let Some(push) =
                                pushed_object(index, pc, callee, arguments, stores_before)
                        {
                            writes.pushes.push(push);
                        }
                    }
                    if let Effect::Set(register, value) = effect {
                        let closure = match value {
                            Term::Closure { pc, .. } => Some(*pc),
                            Term::Reg(source) => closures.get(source).copied(),
                            _ => None,
                        };
                        match closure {
                            Some(closure) => closures.insert(*register, closure),
                            None => closures.remove(register),
                        };
                    }
                    effect.visit_terms(&mut |term| match term {
                        Term::Closure { pc, .. } => callbacks.push_back(*pc),
                        Term::Array(frame) => {
                            callbacks.extend(vm::catch_frame(frame).map(|handler| handler.pc));
                        }
                        _ => {}
                    });
                }
                next.extend(path.exit.continues_at().map(|position| position.pc));
            }
            next.extend(index.hidden_at(pc).iter().map(|hidden| hidden.target.pc));
            unvisited.extend(next.into_iter().rev());
        }
        in_body = false;
    }
    writes
}

/// Recognizes a call that pushes a new object onto an array held in a cell. Uses `callee`,
/// `arguments`, and the instruction position `pc`.
fn pushed_object(
    index: &Index<'_>,
    pc: u32,
    callee: &Term,
    arguments: &[Term],
    stores_before: usize,
) -> Option<Push> {
    let [argument] = arguments else {
        return None;
    };
    let object = index.created_at(pc, argument)?;
    let (at, Term::Get(array, _)) = index.dereference(pc, callee)? else {
        return None;
    };
    if index.method(pc, callee).as_deref() != Some("push") {
        return None;
    }
    let (_, Term::Cell(cell)) = index.dereference(at, &array)? else {
        return None;
    };
    Some(Push {
        cell,
        object,
        stores_before,
    })
}
