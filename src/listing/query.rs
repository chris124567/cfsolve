//! Queries value sources, function reachability, and common program reads such as `Date.now()`,
//! challenge options, and record timestamps.
//!
//! [`Index::register_before`] finds the nearest earlier instruction assigning a register and
//! returns the first write from any of its paths. [`Index::assignment`] resolves each write
//! through its own path, including path-local temporaries.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use swc_core::ecma::ast::BinaryOp;

use super::Index;
use crate::candidates;
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
                let key = match &**key {
                    Term::Reg(register) => self.register_before(pc, *register),
                    key => Some(key),
                };
                let Some(Term::Const(Constant::String(key))) = key else {
                    continue;
                };
                if stores.last().is_some_and(|store: &Store| {
                    store.pc == pc && store.object == object && store.key == *key
                }) {
                    continue;
                }
                stores.push(Store {
                    pc,
                    object,
                    key: key.clone(),
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

    /// Returns the first write to `register` on any path of the nearest assigning instruction
    /// before `pc`.
    fn register_before(&self, pc: u32, register: u8) -> Option<&Term> {
        let at = self.assigning_before(pc, register)?;
        self.listing().instructions[&at]
            .effects()
            .find_map(|effect| match effect {
                Effect::Set(target, value) if *target == register => Some(value),
                _ => None,
            })
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
        match self.dereference(pc, term)? {
            (_, Term::Const(Constant::String(text))) => Some(text),
            _ => None,
        }
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
