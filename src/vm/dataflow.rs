//! Forward dataflow analysis of listing control flow: [`forward`] follows recorded exits and
//! keeps the facts all incoming paths share, repeating until they stop changing.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, VecDeque};
use std::ops::ControlFlow;

use super::{Listing, Path};

/// Facts known on entry to an instruction.
pub(crate) trait Facts: Clone {
    /// Intersects with `other` and returns whether facts were lost. Facts only shrink, which
    /// ensures termination.
    fn meet(&mut self, other: &Self) -> bool;
}

impl<K: Ord + Clone, V: PartialEq + Clone> Facts for BTreeMap<K, V> {
    fn meet(&mut self, other: &Self) -> bool {
        let before = self.len();
        self.retain(|key, value| other.get(key) == Some(value));
        self.len() < before
    }
}

/// Computes entry facts for instructions reachable from `entries`. `transfer` updates a copy of
/// facts for one instruction path and reports whether it can run, or stops the analysis. Facts
/// propagate through the exit only if the path can run.
///
/// Only recorded exits propagate facts, so function entries and hidden branch targets need
/// explicit entries. Reaching a position without an instruction ends that path.
pub(crate) fn forward<F: Facts, B>(
    listing: &Listing,
    entries: impl IntoIterator<Item = (u32, F)>,
    mut transfer: impl FnMut(u32, &Path, &mut F) -> ControlFlow<B, bool>,
) -> ControlFlow<B, BTreeMap<u32, F>> {
    let mut incoming = BTreeMap::new();
    let mut pending = VecDeque::new();
    for (pc, facts) in entries {
        reach(&mut incoming, &mut pending, pc, facts);
    }
    while let Some(pc) = pending.pop_front() {
        let Some(instruction) = listing.instructions.get(&pc) else {
            continue;
        };
        let entry = incoming[&pc].clone();
        for path in &instruction.paths {
            let mut facts = entry.clone();
            match transfer(pc, path, &mut facts) {
                ControlFlow::Break(stop) => return ControlFlow::Break(stop),
                ControlFlow::Continue(false) => continue,
                ControlFlow::Continue(true) => {}
            }
            if let Some(next) = path.exit.continues_at() {
                reach(&mut incoming, &mut pending, next.pc, facts);
            }
        }
    }
    ControlFlow::Continue(incoming)
}

/// Merges incoming `facts` at `pc`, revisiting `pc` if facts are lost.
fn reach<F: Facts>(
    incoming: &mut BTreeMap<u32, F>,
    pending: &mut VecDeque<u32>,
    pc: u32,
    facts: F,
) {
    match incoming.entry(pc) {
        Entry::Vacant(vacant) => {
            vacant.insert(facts);
            pending.push_back(pc);
        }
        Entry::Occupied(mut known) => {
            if known.get_mut().meet(&facts) {
                pending.push_back(pc);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{Constant, Effect, Exit, Instruction, Term};

    type Constants = BTreeMap<u8, Term>;

    fn set(register: u8, text: &str) -> Effect {
        Effect::Set(register, Term::Const(Constant::String(text.into())))
    }

    fn path(effects: Vec<Effect>, exit: Exit) -> Path {
        Path {
            conditions: Vec::new(),
            effects,
            exit,
        }
    }

    #[test]
    fn facts_are_what_every_way_in_agrees_on() {
        let next = |pc| Exit::Next { pc, key: 0 };
        // Two edges lead from 0 to 1. Instruction 1 loops and exits to 2, past the program.
        let paths = [
            vec![
                path(vec![set(1, "a"), set(2, "x")], next(1)),
                path(vec![set(1, "a"), set(2, "y")], next(1)),
            ],
            vec![
                path(vec![set(3, "loop")], next(1)),
                path(vec![], next(2)),
                path(vec![], Exit::Return),
            ],
        ];
        let mut listing = Listing::default();
        for (pc, paths) in (0..).zip(paths) {
            let instruction = Instruction {
                pc,
                key: 0,
                opcode: 0,
                paths,
            };
            listing.instructions.insert(pc, instruction);
        }
        let constants = |_, path: &Path, facts: &mut Constants| {
            for effect in &path.effects {
                if let Effect::Set(register, value) = effect {
                    facts.insert(*register, value.clone());
                }
            }
            ControlFlow::<(), bool>::Continue(true)
        };
        let incoming = forward(&listing, [(0, Constants::new())], constants);
        let a = || Constants::from([(1, Term::Const(Constant::String("a".into())))]);
        assert_eq!(
            incoming,
            ControlFlow::Continue(BTreeMap::from([(0, Constants::new()), (1, a()), (2, a())])),
            "the two ways in from 0 disagree on register 2, only the loop's way in knows \
             register 3, and a position past the program is reached with what leads there"
        );
    }
}
