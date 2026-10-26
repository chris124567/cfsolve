//! The click callback's stack, console getter marker and click-origin flag.

use std::collections::BTreeSet;
use std::ops::Range;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::candidates;
use crate::js::{JsObject, JsValue};
use crate::listing::Index;
use crate::vm::{Effect, Term};

/// Click diagnostic record keys and markers produced by the console helper and stack getter.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Plan {
    pub stack: String,
    /// The opcode of the instruction that constructs the click's `new Error()`.
    pub construct: u8,
    /// How many parameters the program's click callback takes.
    pub callback_arity: usize,
    pub console: String,
    pub stack_untouched: String,
    pub stack_touched: String,
    pub programmatic: String,
}

impl Plan {
    /// Builds diagnostics for a trusted native click whose stack was not read beforehand.
    #[must_use]
    pub fn collect(&self, stack: String) -> JsObject {
        JsObject::from_iter([
            (self.stack.clone(), JsValue::String(stack)),
            (
                self.console.clone(),
                JsValue::String(self.stack_untouched.clone()),
            ),
            (self.programmatic.clone(), JsValue::Bool(false)),
        ])
    }
}

pub(super) fn recover(index: &Index<'_>) -> Result<Plan> {
    let listing = index.listing();
    let stores = index.stores();
    let (position, construct) = stores
        .iter()
        .enumerate()
        .find_map(|(position, store)| {
            if let (pc, Term::Get(error, key)) = index.dereference(store.pc, &store.value)?
                && key.string() == Some("stack")
                && let (pc, Term::New { callee, arguments }) = index.dereference(pc, &error)?
                && arguments.is_empty()
                && index.method(pc, &callee).as_deref() == Some("Error")
            {
                return Some((position, listing.instructions[&pc].opcode));
            }
            None
        })
        .context("click has no new Error().stack record write")?;
    let stack = &stores[position];
    let callback_arity = index
        .entry_at_or_before(stack.pc)
        .and_then(|entry| index.arity(entry))
        .context("the click's new Error() is in no closure of the program")?;
    let console = stores
        .get(position + 1)
        .context("click has no console marker write")?;
    let programmatic = stores
        .get(position + 2)
        .context("click has no origin flag write")?;
    ensure!(
        console.object == stack.object && programmatic.object == stack.object,
        "click diagnostics change record object"
    );
    ensure!(
        matches!(
            index.dereference(programmatic.pc, &programmatic.value),
            Some((_, Term::Cell(_)))
        ),
        "click origin flag is not cell-held"
    );
    let (pc, Term::Call { callee, .. }) = index
        .dereference(console.pc, &console.value)
        .context("console marker has no assignment")?
    else {
        bail!("console marker is not a function result");
    };
    let (_, Term::Closure { pc: entry, .. }) = index
        .dereference(pc, &callee)
        .context("console marker has no callee assignment")?
    else {
        bail!("console marker has no helper closure");
    };
    let helper = index
        .function_range(entry)
        .context("console helper has no end")?;
    let cell_strings = |function: Range<u32>| -> BTreeSet<(u32, String)> {
        index
            .effects_in(function)
            .filter_map(|(pc, effect)| {
                let Effect::SetCell(cell, value) = effect else {
                    return None;
                };
                Some((*cell, index.text(pc, value)?))
            })
            .collect()
    };
    let (cell, untouched) = candidates::exactly_one(
        cell_strings(helper.clone()),
        "console helper initial marker",
    )?;
    // Multiple creation sites for the same getter do not make it ambiguous.
    let getters: BTreeSet<u32> = index.closures_in(helper).collect();
    let getter = candidates::exactly_one(getters, "console helper stack getter")?;
    let getter = index
        .function_range(getter)
        .context("stack getter has no end")?;
    let touched = candidates::exactly_one(
        cell_strings(getter)
            .into_iter()
            .filter(|(candidate, _)| *candidate == cell)
            .map(|(_, text)| text),
        "stack getter touched marker",
    )?;
    Ok(Plan {
        stack: stack.key.clone(),
        construct,
        callback_arity,
        console: console.key.clone(),
        programmatic: programmatic.key.clone(),
        stack_untouched: untouched,
        stack_touched: touched,
    })
}
