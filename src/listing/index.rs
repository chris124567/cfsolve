//! Caches common listing lookups for analysis.

use std::cell::OnceCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::{Bound, Range, RangeBounds};

use anyhow::{Context, Result};

use super::query::Store;
use crate::candidates;
use crate::vm::{Constant, Effect, Hidden, Listing, Term};

/// A listing with cached lookups for analysis. Builds inexpensive indexes immediately, and the
/// global register and property stores ([`Index::stores`]) on demand.
pub(crate) struct Index<'listing> {
    listing: &'listing Listing,
    strings: BTreeMap<u32, &'listing str>,
    entries: BTreeSet<u32>,
    hidden: HashMap<u32, Vec<&'listing Hidden>>,
    assignments: HashMap<u8, Vec<u32>>,
    header: BTreeMap<u8, String>,
    global: OnceCell<Option<u8>>,
    pub(super) stores: OnceCell<Vec<Store>>,
}

impl<'listing> Index<'listing> {
    #[must_use]
    pub(crate) fn new(listing: &'listing Listing) -> Self {
        let mut strings = BTreeMap::new();
        let mut header = BTreeMap::new();
        let mut in_header = true;
        let mut assignments: HashMap<u8, Vec<u32>> = HashMap::new();
        for (&pc, instruction) in &listing.instructions {
            for effect in instruction.effects() {
                if let Effect::Set(register, value) = effect {
                    match value {
                        // The header ends where the first closure is created.
                        Term::Closure { .. } => in_header = false,
                        // Keep the last string loaded at each program counter.
                        Term::Const(Constant::String(text)) => {
                            strings.insert(pc, text.as_str());
                            if in_header {
                                header.insert(*register, text.clone());
                            }
                        }
                        _ => {}
                    }
                    let pcs = assignments.entry(*register).or_default();
                    if pcs.last() != Some(&pc) {
                        pcs.push(pc);
                    }
                }
            }
        }
        let entries: BTreeSet<u32> = listing.functions.iter().map(|entry| entry.pc).collect();
        let mut hidden: HashMap<u32, Vec<&Hidden>> = HashMap::new();
        for branch in &listing.hidden {
            hidden.entry(branch.compare).or_default().push(branch);
        }
        Self {
            listing,
            strings,
            entries,
            hidden,
            assignments,
            header,
            global: OnceCell::new(),
            stores: OnceCell::new(),
        }
    }

    #[must_use]
    pub(crate) fn listing(&self) -> &'listing Listing {
        self.listing
    }

    /// String constants loaded by each instruction, indexed by program counter.
    #[must_use]
    pub(crate) fn strings(&self) -> &BTreeMap<u32, &'listing str> {
        &self.strings
    }

    /// The longest string constant by UTF-16 length, the last on ties, and its load position.
    pub(crate) fn pool(&self) -> Result<(u32, &'listing str)> {
        self.strings
            .iter()
            .max_by_key(|(_, text)| text.encode_utf16().count())
            .map(|(&pc, &pool)| (pc, pool))
            .context("program contains no string pool")
    }

    /// Maps registers to common names loaded before the first function definition.
    #[must_use]
    pub(crate) fn header(&self) -> &BTreeMap<u8, String> {
        &self.header
    }

    /// The global-object register: the one with the most `window` reads, the highest on ties.
    #[must_use]
    pub(crate) fn global(&self) -> Option<u8> {
        *self.global.get_or_init(|| {
            let is_window = |key: &Term| match key {
                Term::Const(Constant::String(text)) => text == "window",
                Term::Reg(register) => self
                    .header
                    .get(register)
                    .is_some_and(|text| text == "window"),
                _ => false,
            };
            let mut reads: HashMap<u8, usize> = HashMap::new();
            for effect in self.effects() {
                effect.visit_terms(&mut |term| {
                    if let Term::Get(object, key) = term
                        && let Term::Reg(register) = **object
                        && is_window(key)
                    {
                        *reads.entry(register).or_default() += 1;
                    }
                });
            }
            reads
                .into_iter()
                .max_by_key(|&(register, count)| (count, register))
                .map(|(register, _)| register)
        })
    }

    /// Returns function entry points in program-counter order.
    #[must_use]
    pub(crate) fn entries(&self) -> &BTreeSet<u32> {
        &self.entries
    }

    #[must_use]
    pub(crate) fn is_entry(&self, pc: u32) -> bool {
        self.entries.contains(&pc)
    }

    /// The entry of the function containing `pc`, as functions run from their entry to the next.
    #[must_use]
    pub(crate) fn entry_at_or_before(&self, pc: u32) -> Option<u32> {
        self.entries.range(..=pc).next_back().copied()
    }

    /// The first function entry after `pc`, which ends `pc`'s function.
    fn entry_after(&self, pc: u32) -> Option<u32> {
        let after = (Bound::Excluded(pc), Bound::Unbounded);
        self.entries.range(after).next().copied()
    }

    /// Returns instructions from the containing function's entry to the next function entry.
    /// Returns no range for the final function because its end is unknown.
    #[must_use]
    pub(crate) fn function_range(&self, pc: u32) -> Option<Range<u32>> {
        Some(self.entry_at_or_before(pc)?..self.entry_after(pc)?)
    }

    /// Like [`Index::function_range`], but runs the final function to the end of the listing.
    #[must_use]
    pub(crate) fn function_at(&self, pc: u32) -> Range<u32> {
        let start = self.entry_at_or_before(pc).unwrap_or(0);
        start..self.entry_after(pc).unwrap_or(u32::MAX)
    }

    /// The declared parameter count of the function at `entry`, from the closures creating it.
    #[must_use]
    pub(crate) fn arity(&self, entry: u32) -> Option<usize> {
        let mut arities = BTreeSet::new();
        for effect in self.effects() {
            effect.visit_terms(&mut |term| {
                if let Term::Closure { pc, arity, .. } = term
                    && *pc == entry
                {
                    arities.insert(usize::from(*arity));
                }
            });
        }
        candidates::exactly_one(arities, "declared arity").ok()
    }

    /// Closure entries created in the range, in pc order, with duplicates from multiple paths.
    pub(crate) fn closures_in(&self, range: impl RangeBounds<u32>) -> impl Iterator<Item = u32> {
        self.effects_in(range)
            .filter_map(|(_, effect)| match effect {
                Effect::Set(_, Term::Closure { pc, .. }) => Some(*pc),
                _ => None,
            })
    }

    /// Returns hidden branches compared at `pc`, in discovery order.
    #[must_use]
    pub(crate) fn hidden_at(&self, pc: u32) -> &[&'listing Hidden] {
        self.hidden.get(&pc).map_or(&[], Vec::as_slice)
    }

    /// The instruction assigning `register` on some path nearest before `pc`.
    pub(super) fn assigning_before(&self, pc: u32, register: u8) -> Option<u32> {
        let pcs = self.assignments.get(&register)?;
        let before = pcs.partition_point(|&assigned| assigned < pc);
        pcs[..before].last().copied()
    }

    /// Iterates all path effects in program-counter order.
    pub(crate) fn effects(&self) -> impl Iterator<Item = &'listing Effect> {
        self.effects_in(..).map(|(_, effect)| effect)
    }

    /// Effects in an instruction range with their instruction's pc, in path and effect order.
    pub(crate) fn effects_in(
        &self,
        range: impl RangeBounds<u32>,
    ) -> impl Iterator<Item = (u32, &'listing Effect)> {
        self.listing
            .instructions
            .range(range)
            .flat_map(|(&pc, instruction)| instruction.effects().map(move |effect| (pc, effect)))
    }
}
