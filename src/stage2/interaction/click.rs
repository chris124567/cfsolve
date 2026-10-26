//! Builds the click record from browser measurements.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use swc_core::ecma::ast::BinaryOp;

use crate::js::{self, JsObject, JsValue};
use crate::listing::Index;
use crate::vm::{Effect, Term};

/// The measured object a click field reads.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Event,
    Rect,
    Window,
    Document,
    Element,
    Style,
    Derived,
}

/// A measured property converted to a string in the click record.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Read {
    pub source: Source,
    pub property: String,
}

/// Click record output key and measurement source for each field.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Plan {
    pub output: String,
    pub fields: IndexMap<String, Read>,
}

impl Plan {
    /// Builds the record from `sources` measured at the click, before the UI changes. Applies
    /// `String(value)`; DOM values must already have their string representations.
    pub fn collect(&self, sources: &BTreeMap<Source, JsObject>) -> Result<JsValue> {
        let mut record = JsObject::new();
        for (field, read) in &self.fields {
            let source = sources
                .get(&read.source)
                .with_context(|| format!("missing click source {:?}", read.source))?;
            // Missing event properties represent `undefined`. Other measurement sources are
            // required.
            let value = source.get(&read.property);
            ensure!(
                value.is_some() || read.source == Source::Event,
                "missing click measurement {:?}.{}",
                read.source,
                read.property
            );
            record.insert(field.clone(), JsValue::String(js::string(value)));
        }
        Ok(JsValue::Object(record))
    }
}

/// The argument of the `String(argument)` call `value` holds at `pc`.
fn string_argument(index: &Index<'_>, pc: u32, value: &Term) -> Option<(u32, Term)> {
    let (
        pc,
        Term::Call {
            callee, arguments, ..
        },
    ) = index.dereference(pc, value)?
    else {
        return None;
    };
    let argument = arguments.into_iter().next()?;
    (index.method(pc, &callee)? == "String").then_some((pc, argument))
}

/// The register holding the click event, and the assignment that set it. Later instructions may
/// reuse that register for other objects.
#[derive(Clone, Copy)]
struct Event {
    register: u8,
    binding: Option<u32>,
}

/// Resolves the measured object held by `value` at `pc`.
fn scope(index: &Index<'_>, pc: u32, value: &Term, event: Event, element: u32) -> Option<Source> {
    if *value == Term::Reg(event.register)
        && index.assignment(pc, event.register).map(|(at, _)| at) == event.binding
    {
        return Some(Source::Event);
    }
    let (pc, value) = index.dereference(pc, value)?;
    match value {
        Term::Cell(cell) if cell == element => Some(Source::Element),
        Term::Get(_, key) => match index.text(pc, &key)?.as_str() {
            "window" => Some(Source::Window),
            "document" => Some(Source::Document),
            _ => None,
        },
        Term::Call { callee, .. } => match index.method(pc, &callee)?.as_str() {
            "getBoundingClientRect" => Some(Source::Rect),
            "getComputedStyle" => Some(Source::Style),
            _ => None,
        },
        _ => None,
    }
}

/// The value converted to a string for a click field.
fn read(index: &Index<'_>, pc: u32, argument: &Term, event: Event, element: u32) -> Option<Read> {
    let (pc, argument) = index.dereference(pc, argument)?;
    match argument {
        Term::Get(object, property) => Some(Read {
            source: scope(index, pc, &object, event, element)?,
            property: index.text(pc, &property)?,
        }),
        Term::Call {
            callee, arguments, ..
        } => {
            let property = match index.method(pc, &callee)?.as_str() {
                "Boolean" => "is_touch",
                "elementFromPoint" => "element_from_point",
                "floor" => {
                    let (at, difference) = index.dereference(pc, arguments.first()?)?;
                    let Term::Binary(BinaryOp::Sub, point, _) = difference else {
                        return None;
                    };
                    let coordinate = index.member(at, &point)?;
                    match coordinate.key.as_str() {
                        "clientX" => "relative_x",
                        "clientY" => "relative_y",
                        _ => return None,
                    }
                }
                _ => return None,
            };
            Some(Read {
                source: Source::Derived,
                property: property.into(),
            })
        }
        _ => None,
    }
}

pub(super) fn recover(index: &Index<'_>) -> Result<Plan> {
    let stores = index.stores();
    let (anchor, read_pc, argument) = stores
        .iter()
        .find_map(|store| {
            let (pc, argument) = string_argument(index, store.pc, &store.value)?;
            let read = index.member(pc, &argument)?;
            (read.key == "isTrusted").then_some((store, read.pc, read.object))
        })
        .context("click recorder has no String(event.isTrusted) projection")?;
    let Term::Reg(register) = argument else {
        bail!("click event is not register-held");
    };
    let event = Event {
        register,
        binding: index.assignment(read_pc, register).map(|(at, _)| at),
    };
    let (creation, _) = index
        .assignment(anchor.pc, anchor.object)
        .context("click record has no object construction")?;
    let element = index
        .listing()
        .instructions
        .range(..creation)
        .rev()
        .find_map(|(&pc, instruction)| {
            instruction.effects().find_map(|effect| {
                if let Effect::Let(_, Term::Call { callee, .. }) = effect
                    && let member = index.member(pc, callee)?
                    && member.key == "getBoundingClientRect"
                    && let (_, Term::Cell(cell)) = index.dereference(member.pc, &member.object)?
                {
                    return Some(cell);
                }
                None
            })
        })
        .context("click recorder has no checkbox bounds measurement")?;
    let mut fields = IndexMap::new();
    let record_writes = stores
        .iter()
        .filter(|store| store.pc > creation && store.object == anchor.object);
    for store in record_writes {
        if index.assignment(store.pc, store.object).map(|(pc, _)| pc) != Some(creation) {
            break;
        }
        let (pc, argument) = string_argument(index, store.pc, &store.value)
            .with_context(|| format!("click field {} does not stringify its input", store.key))?;
        fields.insert(
            store.key.clone(),
            read(index, pc, &argument, event, element).with_context(|| {
                format!("unrecognized click input for {} at {}", store.key, store.pc)
            })?,
        );
    }
    ensure!(fields.len() >= 60, "incomplete click property projection");
    let output = stores
        .iter()
        .find_map(|store| {
            let (pc, _) = index.dereference(store.pc, &store.value)?;
            (pc == creation).then_some(store.key.clone())
        })
        .context("click record is not published")?;
    Ok(Plan { output, fields })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js::json;

    #[test]
    fn absent_event_properties_stringify_undefined_but_measurements_are_required() {
        let plan: Plan = js::from_value(json!({"output": "click", "fields": {
            "unknown": {"source": "event", "property": "unknown"},
            "trusted": {"source": "event", "property": "isTrusted"},
            "width": {"source": "rect", "property": "width"}
        }}))
        .unwrap();
        let sources: BTreeMap<Source, JsObject> = js::from_value(json!({
            "event": {"isTrusted": true}, "rect": {"width": 30}
        }))
        .unwrap();
        assert_eq!(
            plan.collect(&sources).unwrap(),
            json!({"unknown":"undefined","trusted":"true","width":"30"})
        );
        assert!(plan.collect(&BTreeMap::new()).is_err());
    }
}
