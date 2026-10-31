//! Queries value sources, function reachability, and common program reads such as `Date.now()`,
//! challenge options, and record timestamps.
//!
//! [`Index::assignment`] finds the nearest earlier instruction assigning a register and
//! resolves its writes through their own paths, including path-local temporaries.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use swc_core::ecma::ast::BinaryOp;

use super::Index;
use super::fold::{Frame, constant};
use crate::candidates;
use crate::js::JsValue;
use crate::vm::{Constant, Effect, Instruction, Listing, Term};

/// A property write, `object.key = value` or `object[key] = value`. Dynamic keys resolve to the
/// string held by their register.
pub(crate) struct Store {
    pub pc: u32,
    pub object: u8,
    pub key: String,
    pub value: Term,
}

/// An `object[key]` read with a string key, and the program counter where it happens.
pub(crate) struct Member {
    pub pc: u32,
    pub object: Term,
    pub key: String,
}

/// Collects the program counters reachable from `entry` through `successors`, skipping those
/// `enter` rejects. Positions without instructions are reached but have no successors.
pub(crate) fn walk(
    listing: &Listing,
    entry: u32,
    enter: impl Fn(u32) -> bool,
    mut successors: impl FnMut(u32, &Instruction, &mut Vec<u32>),
) -> BTreeSet<u32> {
    let mut reached = BTreeSet::new();
    let mut pending = vec![entry];
    while let Some(pc) = pending.pop() {
        if !enter(pc) || !reached.insert(pc) {
            continue;
        }
        if let Some(instruction) = listing.instructions.get(&pc) {
            successors(pc, instruction, &mut pending);
        }
    }
    reached
}

/// Maximum assignment links followed by [`Index::dereference`].
const DEREFERENCE_FUEL: usize = 8;

impl Index<'_> {
    /// Recovers arrays populated through numeric stores, rejecting holes and conflicting writes.
    pub(crate) fn string_arrays(&self, entry: u32) -> Vec<Vec<String>> {
        let mut arrays = BTreeMap::<u32, BTreeMap<usize, String>>::new();
        let mut invalid = BTreeSet::new();
        for pc in self.reachable(entry) {
            let Some(instruction) = self.listing().instructions.get(&pc) else {
                continue;
            };
            for effect in instruction.effects() {
                let Effect::SetProperty { object, key, value } = effect else {
                    continue;
                };
                let Some((origin, Term::Array(initial))) = self.dereference(pc, object) else {
                    continue;
                };
                if !initial.is_empty() {
                    continue;
                }
                let Some((_, Term::Const(Constant::Number(index)))) = self.dereference(pc, key)
                else {
                    invalid.insert(origin);
                    continue;
                };
                let Some(value) = self.text(pc, value) else {
                    invalid.insert(origin);
                    continue;
                };
                if !index.is_finite() || index < 0.0 || index.fract() != 0.0 {
                    invalid.insert(origin);
                    continue;
                }
                let array = arrays.entry(origin).or_default();
                if array
                    .insert(index as usize, value.clone())
                    .is_some_and(|old| old != value)
                {
                    invalid.insert(origin);
                }
            }
        }
        arrays
            .into_iter()
            .filter(|(origin, array)| {
                !invalid.contains(origin) && array.keys().copied().eq(0..array.len())
            })
            .map(|(_, array)| array.into_values().collect())
            .collect()
    }

    /// Caches property writes in program-counter order. Resolves dynamic keys through the
    /// nearest earlier register assignment and skips stores whose keys are not known strings.
    #[must_use]
    pub(crate) fn stores(&self) -> &[Store] {
        self.stores.get_or_init(|| {
            let mut stores = Vec::new();
            for (pc, effect) in self.effects_in(..) {
                let Effect::SetProperty { object, key, value } = effect else {
                    continue;
                };
                let Term::Reg(object) = **object else {
                    continue;
                };
                let Some(key) = self.text(pc, key) else {
                    continue;
                };
                if stores.last().is_some_and(|store: &Store| {
                    store.pc == pc && store.object == object && store.key == key
                }) {
                    continue;
                }
                stores.push(Store {
                    pc,
                    object,
                    key,
                    value: (**value).clone(),
                });
            }
            stores
        })
    }

    /// Reachable instructions, including created functions, in program-counter order. Follows
    /// opaque exits to their destination, but not hidden branches or exception handlers.
    #[must_use]
    pub(crate) fn reachable(&self, entry: u32) -> BTreeSet<u32> {
        let listing = self.listing();
        let mut reached = walk(
            listing,
            entry,
            |_| true,
            |_, instruction, pending| {
                pending.extend(instruction.exits());
                for effect in instruction.effects() {
                    effect.visit_terms(&mut |term| {
                        if let Term::Closure { pc, .. } = term {
                            pending.push(*pc);
                        }
                    });
                }
            },
        );
        reached.retain(|pc| listing.instructions.contains_key(pc));
        reached
    }

    /// Finds the nearest assignment to `register` before `before`, retaining its program
    /// counter so operands resolve at assignment time. Resolves temporaries only through the
    /// path that computed them; missing path values leave the assignment unknown.
    #[must_use]
    pub(crate) fn assignment(&self, before: u32, register: u8) -> Option<(u32, Term)> {
        let pc = self.assigning_before(before, register)?;
        for path in &self.listing().instructions[&pc].paths {
            let mut temporaries = BTreeMap::new();
            for effect in &path.effects {
                match effect {
                    Effect::Let(temporary, value) => {
                        temporaries.insert(*temporary, value);
                    }
                    Effect::Set(target, value) if *target == register => {
                        let value = match value {
                            Term::Temp(temporary) => (*temporaries.get(temporary)?).clone(),
                            _ => value.clone(),
                        };
                        return Some((pc, value));
                    }
                    _ => {}
                }
            }
        }
        None
    }

    /// Replaces register references with assignments, following at most [`DEREFERENCE_FUEL`]
    /// links. Also returns the last assignment's program counter.
    #[must_use]
    pub(crate) fn dereference(&self, mut pc: u32, term: &Term) -> Option<(u32, Term)> {
        let mut term = term.clone();
        for _ in 0..DEREFERENCE_FUEL {
            let Term::Reg(register) = term else {
                return Some((pc, term));
            };
            (pc, term) = self.assignment(pc, register)?;
        }
        None
    }

    /// The string `term` holds at `pc`.
    #[must_use]
    pub(crate) fn text(&self, pc: u32, term: &Term) -> Option<String> {
        self.literal(pc, term, 16)?.as_str().map(str::to_owned)
    }

    /// Resolves the small constant expressions left in an inline string decoder when a
    /// control-flow join prevents whole-program folding. Every operand must be a literal.
    fn literal(&self, pc: u32, term: &Term, fuel: usize) -> Option<JsValue> {
        if fuel == 0 {
            return None;
        }
        let (pc, term) = self.dereference(pc, term)?;
        let literal = |term: &Term| -> Option<Term> {
            Some(Term::Const(match self.literal(pc, term, fuel - 1)? {
                JsValue::String(text) => Constant::String(text),
                JsValue::Number(number) => Constant::Number(number),
                JsValue::Bool(value) => Constant::Bool(value),
                JsValue::Null => Constant::Null,
                JsValue::Undefined => Constant::Undefined,
                _ => return None,
            }))
        };
        let resolved = match term {
            Term::Const(_) => term,
            Term::Binary(op, left, right) => {
                Term::Binary(op, Box::new(literal(&left)?), Box::new(literal(&right)?))
            }
            Term::Call {
                callee, arguments, ..
            } => {
                let (at, Term::Get(object, method)) = self.dereference(pc, &callee)? else {
                    return None;
                };
                let object = self.literal(at, &object, fuel - 1)?.as_str()?.to_owned();
                let method = self.literal(at, &method, fuel - 1)?.as_str()?.to_owned();
                Term::Call {
                    callee: Box::new(Term::Get(
                        Box::new(Term::Const(Constant::String(object))),
                        Box::new(Term::Const(Constant::String(method))),
                    )),
                    this: None,
                    arguments: arguments.iter().map(literal).collect::<Option<_>>()?,
                }
            }
            _ => return None,
        };
        constant(&Frame::<()>::default(), &resolved)
    }

    /// Resolves `term` to an `object[key]` read with a string key.
    #[must_use]
    pub(crate) fn member(&self, pc: u32, term: &Term) -> Option<Member> {
        match self.dereference(pc, term)? {
            (pc, Term::Get(object, key)) => Some(Member {
                pc,
                object: *object,
                key: self.text(pc, &key)?,
            }),
            _ => None,
        }
    }

    /// Whether `term` holds a read of `property` at `pc`.
    #[must_use]
    pub(crate) fn reads(&self, pc: u32, term: &Term, property: &str) -> bool {
        self.member(pc, term)
            .is_some_and(|member| member.key == property)
    }

    /// Returns the creation site of the object held by `term` at `pc`.
    #[must_use]
    pub(crate) fn created_at(&self, pc: u32, term: &Term) -> Option<u32> {
        match self.dereference(pc, term)? {
            (created, Term::Object(_)) => Some(created),
            _ => None,
        }
    }

    /// The name of the method or function `callee` calls at `pc`.
    #[must_use]
    pub(crate) fn method(&self, pc: u32, callee: &Term) -> Option<String> {
        match self.dereference(pc, callee)? {
            (pc, Term::Get(_, key)) => self.text(pc, &key),
            (_, Term::Const(Constant::String(name))) => Some(name),
            _ => None,
        }
    }

    /// Whether `term` holds a `Date.now()` result at `pc`.
    #[must_use]
    pub(crate) fn is_date_now(&self, pc: u32, term: &Term) -> bool {
        let Some((
            at,
            Term::Call {
                callee, arguments, ..
            },
        )) = self.dereference(pc, term)
        else {
            return false;
        };
        arguments.is_empty()
            && self.member(at, &callee).is_some_and(|member| {
                member.key == "now"
                    && self.method(member.pc, &member.object).as_deref() == Some("Date")
            })
    }

    /// The challenge option `term` reads at `pc`: `name` in `window._cf_chl_opt[name]`.
    #[must_use]
    pub(crate) fn option_read(&self, pc: u32, term: &Term) -> Option<String> {
        let option = self.member(pc, term)?;
        let options = self.member(option.pc, &option.object)?;
        (options.key == "_cf_chl_opt").then_some(option.key)
    }

    /// Finds a record's start, finish, and duration stores. Uses the first `finished - started`
    /// store in program order and the stores supplying its operands.
    pub(crate) fn clock_marks<'s>(&self, stores: &[&'s Store]) -> Result<[&'s Store; 3]> {
        // Where a value comes from, or the value itself when its assignment is unknown.
        let source = |pc: u32, term: &Term| match self.dereference(pc, term) {
            Some((at, term)) => (Some(at), term),
            None => (None, term.clone()),
        };
        let (duration, finished, started) = stores
            .iter()
            .find_map(|store| match source(store.pc, &store.value) {
                (Some(at), Term::Binary(BinaryOp::Sub, finished, started)) => {
                    Some((*store, source(at, &finished), source(at, &started)))
                }
                _ => None,
            })
            .context("record duration field not found")?;
        let writing = |operand: (Option<u32>, Term)| -> Vec<&'s Store> {
            stores
                .iter()
                .copied()
                .filter(|store| source(store.pc, &store.value) == operand)
                .collect()
        };
        let started = candidates::exactly_one(writing(started), "record start mark")?;
        let finished = candidates::exactly_one(writing(finished), "record finish mark")?;
        ensure!(
            started.key != finished.key,
            "record needs two wall-clock marks"
        );
        Ok([started, finished, duration])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{Exit, Path};

    fn text(value: &str) -> Term {
        Term::Const(Constant::String(value.into()))
    }
    fn number(value: f64) -> Term {
        Term::Const(Constant::Number(value))
    }
    fn call(object: Term, method: &str, arguments: Vec<Term>) -> Term {
        Term::Call {
            callee: Box::new(Term::Get(Box::new(object), Box::new(text(method)))),
            this: None,
            arguments,
        }
    }
    fn store(object: u8, key: Term, value: Term) -> Effect {
        Effect::SetProperty {
            object: Box::new(Term::Reg(object)),
            key: Box::new(key),
            value: Box::new(value),
        }
    }
    fn listing(effects: Vec<Effect>) -> Listing {
        let count = effects.len();
        let mut listing = Listing::default();
        for (pc, effect) in effects.into_iter().enumerate() {
            listing.instructions.insert(
                pc as u32,
                Instruction {
                    pc: pc as u32,
                    key: 0,
                    opcode: 0,
                    paths: vec![Path {
                        conditions: vec![],
                        effects: vec![effect],
                        exit: if pc + 1 == count {
                            Exit::Return
                        } else {
                            Exit::Next {
                                pc: pc as u32 + 1,
                                key: 0,
                            }
                        },
                    }],
                },
            );
        }
        listing
    }

    #[test]
    fn resolves_stored_keys_through_inline_string_decoders() {
        let listing = listing(vec![
            Effect::Set(1, text("\0\u{6}Field7padding")),
            Effect::Set(2, number(2.0)),
            Effect::Set(3, number(256.0)),
            Effect::Set(4, call(Term::Reg(1), "charCodeAt", vec![number(0.0)])),
            Effect::Set(5, call(Term::Reg(1), "charCodeAt", vec![number(1.0)])),
            Effect::Set(
                4,
                Term::Binary(
                    BinaryOp::Mul,
                    Box::new(Term::Reg(4)),
                    Box::new(Term::Reg(3)),
                ),
            ),
            Effect::Set(
                4,
                Term::Binary(
                    BinaryOp::Add,
                    Box::new(Term::Reg(4)),
                    Box::new(Term::Reg(5)),
                ),
            ),
            Effect::Set(
                4,
                Term::Binary(
                    BinaryOp::Add,
                    Box::new(Term::Reg(4)),
                    Box::new(Term::Reg(2)),
                ),
            ),
            Effect::Set(
                1,
                call(Term::Reg(1), "slice", vec![Term::Reg(2), Term::Reg(4)]),
            ),
            store(9, Term::Reg(1), number(1.0)),
            store(
                9,
                call(Term::Reg(99), "slice", vec![number(0.0), number(1.0)]),
                number(2.0),
            ),
        ]);
        let index = Index::new(&listing);
        assert_eq!(index.stores().len(), 1);
        assert_eq!(index.stores()[0].key, "Field7");
    }

    #[test]
    fn collects_complete_string_arrays_and_rejects_uncertain_contents() {
        let listing = listing(vec![
            Effect::Set(1, Term::Array(vec![])),
            store(1, number(1.0), text("second")),
            store(1, number(0.0), text("first")),
            Effect::Set(2, Term::Array(vec![])),
            store(2, number(1.0), text("gap")),
            Effect::Set(3, Term::Array(vec![])),
            store(3, number(0.0), text("before")),
            store(3, number(0.0), text("after")),
            Effect::Set(4, Term::Array(vec![])),
            store(4, Term::Reg(99), text("unknown index")),
        ]);
        assert_eq!(
            Index::new(&listing).string_arrays(0),
            [vec!["first", "second"]]
        );
    }
}
