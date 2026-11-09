//! Listing queries for challenge-specific reads: challenge options and record clock marks.

use anyhow::{Context, Result, ensure};
use oxc::syntax::operator::BinaryOperator;

use crate::candidates;
use crate::listing::Index;
use crate::listing::query::Store;
use crate::vm::Term;

/// The challenge option `term` reads at `pc`: `name` in `window._cf_chl_opt[name]`.
#[must_use]
pub(crate) fn option_read(index: &Index<'_>, pc: u32, term: &Term) -> Option<String> {
    let option = index.member(pc, term)?;
    let options = index.member(option.pc, &option.object)?;
    (options.key == "_cf_chl_opt").then_some(option.key)
}

/// Finds a record's start, finish, and duration stores. Uses the first `finished - started`
/// store in program order and the stores supplying its operands.
pub(crate) fn clock_marks<'s>(index: &Index<'_>, stores: &[&'s Store]) -> Result<[&'s Store; 3]> {
    // Where a value comes from, or the value itself when its assignment is unknown.
    let source = |pc: u32, term: &Term| match index.dereference(pc, term) {
        Some((at, term)) => (Some(at), term),
        None => (None, term.clone()),
    };
    let (duration, finished, started) = stores
        .iter()
        .find_map(|store| match source(store.pc, &store.value) {
            (Some(at), Term::Binary(BinaryOperator::Subtraction, finished, started)) => {
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
