//! Recovers field names for the envelope around each probe result.

use std::collections::BTreeSet;

use anyhow::{Context, Result};

use crate::js::JsValue;
use crate::listing::fold::{Frame, Known};
use crate::listing::query::Store;
use crate::listing::{Index, query};
use crate::stage2::payload::RecordLiteral;
use crate::stage2::queries;
use crate::stage2::records::{Completion, Envelope, INITIAL_STATUS, Probe};
use crate::vm::{Effect, Term};

/// Recovers record-envelope fields: creation counter, literal token and input, wrapper status
/// and message, and completion timestamps and duration.
pub(super) fn recover(
    index: &Index<'_>,
    probes: &[Probe],
    first_function: u32,
    creation: &BTreeSet<u32>,
    finish: &BTreeSet<u32>,
    literals: &[RecordLiteral],
) -> Result<Envelope> {
    let listing = index.listing();
    let header = index.header();
    // The counter's key is a header register, or, in programs that unpack names where they
    // use them, a register loaded in the creation state.
    let keys = || {
        let instructions = creation
            .iter()
            .filter_map(|pc| listing.instructions.get(pc));
        instructions.flat_map(|instruction| {
            instruction
                .effects()
                .filter_map(move |effect| match effect {
                    Effect::SetProperty { key, .. } if let Term::Reg(register) = **key => {
                        Some((instruction.pc, register))
                    }
                    _ => None,
                })
        })
    };
    let counter = keys()
        .find_map(|(_, register)| header.get(&register).cloned())
        .or_else(|| keys().find_map(|(pc, register)| index.text(pc, &Term::Reg(register))))
        .context("record counter field not found")?;
    let written_from = |matches: &dyn Fn(&Probe, &JsValue) -> bool| {
        literals
            .iter()
            .find(|literal| {
                literal.created && probes.iter().any(|probe| matches(probe, &literal.value))
            })
            .map(|literal| literal.field.clone())
    };
    let token = written_from(&|probe, value| value.as_str() == Some(probe.token.as_str()))
        .context("record token field not found")?;
    let input = written_from(&|probe, value| *value == probe.input)
        .context("record input field not found")?;
    // Inspect only the wrapper body, excluding created functions and exception handlers.
    let main = query::walk(
        listing,
        first_function,
        |_| true,
        |_, instruction, pending| {
            pending.extend(instruction.exits());
        },
    );
    let wrapper = property_values(index, &main);
    // Prefers header names, as for the counter.
    let wrapper_field = |what: &str, wanted: fn(&Known<Term>) -> bool| {
        let mut fields = wrapper
            .iter()
            .filter(|(_, value)| wanted(value))
            .map(|(field, _)| field);
        fields
            .clone()
            .find(|field| header.values().any(|name| name == *field))
            .or_else(|| fields.next())
            .cloned()
            .with_context(|| format!("record {what} field not found"))
    };
    let status = wrapper_field("status", |value| {
        matches!(value, Known::Literal(status)
            if status.as_f64() == Some(f64::from(INITIAL_STATUS)))
    })?;
    let message = wrapper_field(
        "message",
        |value| matches!(value, Known::Literal(JsValue::String(text)) if text.is_empty()),
    )?;
    let finishing: Vec<&Store> = index
        .stores()
        .iter()
        .filter(|store| finish.contains(&store.pc))
        .collect();
    let [started, finished, duration] = queries::clock_marks(index, &finishing)?;
    Ok(Envelope {
        counter,
        token,
        input,
        completion: Completion {
            status,
            message,
            started: started.key.clone(),
            finished: finished.key.clone(),
            duration: duration.key.clone(),
        },
    })
}

/// Propagates local values to identify wrapper property names. Preserves register-dependent
/// expressions without executing them.
fn property_values(index: &Index<'_>, pcs: &BTreeSet<u32>) -> Vec<(String, Known<Term>)> {
    let mut frame: Frame<Term> = Frame::seeded(index.header());
    let mut writes = Vec::new();
    for pc in pcs {
        let Some(instruction) = index.listing().instructions.get(pc) else {
            continue;
        };
        for effect in instruction.effects() {
            let resolve = |term: &Term| {
                frame
                    .resolve(term)
                    .unwrap_or_else(|| Known::Ext(term.clone()))
            };
            match effect {
                Effect::Set(register, value) => frame.set(*register, Some(resolve(value))),
                Effect::SetProperty { key, value, .. } => {
                    if let Known::Literal(JsValue::String(field)) = resolve(key) {
                        writes.push((field, resolve(value)));
                    }
                }
                _ => {}
            }
        }
    }
    writes
}
