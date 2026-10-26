//! Recovers the stack probe's output field and the VM calls leading to `new Error()`. Sessions
//! pass those calls to [`crate::stage2::call_stack::recover_probe`] to rebuild the frames.

use std::collections::BTreeSet;
use std::ops::RangeBounds;

use serde::{Deserialize, Serialize};

use crate::candidates;
use crate::js::{JsObject, json};
use crate::listing::Index;
use crate::stage2::analysis::recognize::ProbeView;
use crate::stage2::call_stack::ProbeCalls;
use crate::vm::Term;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fields {
    pub result: String,
    /// Absent when the probe's calls have another shape.
    pub calls: Option<ProbeCalls>,
}

impl Fields {
    /// The record holding the rebuilt `stack`.
    #[must_use]
    pub fn collect(&self, stack: &str) -> JsObject {
        JsObject::from_iter([(self.result.clone(), json!(stack))])
    }
}

/// A VM call of a closure the program created.
#[derive(Clone, Copy)]
struct ClosureCall {
    /// Where the called closure starts.
    closure: u32,
    opcode: u8,
    arguments: usize,
}

/// Returns closure calls in `range`, in program-counter order.
fn closure_calls(
    index: &Index<'_>,
    range: impl RangeBounds<u32>,
) -> impl Iterator<Item = ClosureCall> {
    let instructions = &index.listing().instructions;
    index.effects_in(range).filter_map(move |(pc, effect)| {
        let (callee, arguments) = effect.call()?;
        let (_, Term::Closure { pc: closure, .. }) = index.dereference(pc, callee)? else {
            return None;
        };
        Some(ClosureCall {
            closure,
            opcode: instructions[&pc].opcode,
            arguments: arguments.len(),
        })
    })
}

/// Reads the calls from the program through the probe function at `entry` to `new Error()`.
fn calls(index: &Index<'_>, entry: u32) -> Option<ProbeCalls> {
    let (inner, construct) = closure_calls(index, index.function_range(entry)?)
        .find_map(|call| Some((call, construction(index, call.closure)?)))?;
    let dispatch = closure_calls(index, ..).find(|call| call.closure == entry)?;
    Some(ProbeCalls {
        construct,
        inner: index.arity(inner.closure)?,
        call: inner.opcode,
        passed: inner.arguments,
        outer: index.arity(entry)?,
        dispatch: dispatch.opcode,
        dispatched: dispatch.arguments,
    })
}

/// The opcode with which the function at `entry` constructs `new Error()`.
fn construction(index: &Index<'_>, entry: u32) -> Option<u8> {
    let instructions = &index.listing().instructions;
    index
        .effects_in(index.function_range(entry)?)
        .find_map(|(pc, effect)| {
            let mut constructs = false;
            effect.visit_terms(&mut |term| {
                if let Term::New { callee, arguments } = term
                    && arguments.is_empty()
                    && index.method(pc, callee).as_deref() == Some("Error")
                {
                    constructs = true;
                }
            });
            constructs.then(|| instructions[&pc].opcode)
        })
}

/// Finds the output field in the string table by excluding the header's record-counter name,
/// `stack`, and checksum numbers. Supports reversed entries.
fn result_field(features: &[String], header: &BTreeSet<String>) -> Option<String> {
    for table in features {
        // The separator is the character that splits out `stack`.
        let separators: BTreeSet<char> = table.chars().collect();
        for separator in separators {
            let parts: Vec<&str> = table.split(separator).collect();
            let reversed = parts.contains(&"kcats");
            if parts.len() < 8 || !reversed && !parts.contains(&"stack") {
                continue;
            }
            let names = parts.iter().map(|part| {
                if reversed {
                    part.chars().rev().collect()
                } else {
                    part.to_string()
                }
            });
            let results = names.filter(|name| {
                name.starts_with(|first: char| first.is_ascii_alphabetic())
                    && name != "stack"
                    && !header.contains(name)
            });
            if let Ok(result) = candidates::exactly_one(results, "stack result field") {
                return Some(result);
            }
        }
    }
    None
}

pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<Fields> {
    result_field(probe.session_features, probe.header).map(|result| Fields {
        result,
        calls: calls(probe.index, probe.entry),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// String-table fixtures from `oct07` and `auto07`, with reversed entries, different
    /// separators, record counter `MpnR7`, and output `KtSk9` among checksums.
    const TABLES: [&str; 2] = [
        "jofSiE30008083BkkWNuT7448403BdopMzg44061BNGFZaZ261BkcatsB9kStKBfLtcHj96832BgaTDbY4BpXQttP25B7RnpMBmUhSIX36BDVzmUR5929603BYmhrYo9141BEaIFAp045194BjnyEXu464181BUJSbfj21",
        "9kStKdcbIlPD41905061dwyaOcj8d7RnpMdYyBnCs01dXDFpnl1dkcatsdkqJgKK4841dsslBLo4138912dnxktDj04102605dumXLnH6dNwsxWl1479dFzWAcA5127017dMcaZve4139676dAWAbss1932682",
    ];

    /// Both string orders identify the output field. Without header names, the record counter
    /// remains a competing candidate and recovery must fail.
    #[test]
    fn reads_the_one_name_besides_the_header() {
        let in_order: String = TABLES[0].chars().rev().collect();
        for table in [TABLES[0], TABLES[1], in_order.as_str()] {
            let features = ["stack".to_owned(), table.to_owned()];
            let result = result_field(&features, &BTreeSet::from(["MpnR7".to_owned()]));
            assert_eq!(result.as_deref(), Some("KtSk9"), "{table}");
        }
        assert!(result_field(&[TABLES[0].to_owned()], &BTreeSet::new()).is_none());
    }
}
