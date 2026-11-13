//! Builds a probe record from the embedding page's signals.
//!
//! The probe reads the `wPr` array the embedding page sent (see [`PageSignals::elements`]),
//! which the iframe keeps in a `_cf_chl_opt` option, and copies some of its elements into its
//! record: as they are, with `""` for falsy values, or joined into a string. Recognition follows
//! the probe's code to recover each output field's element and treatment.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::ops::ControlFlow;

use indexmap::IndexMap;
use oxc::syntax::operator::{BinaryOperator, UnaryOperator};
use serde::{Deserialize, Serialize};

use crate::embedding_page::page::PageSignals;
use crate::js::{self, JsObject, JsValue, json};
use crate::stage2::analysis::recognize::ProbeView;
use crate::vm::dataflow::{self, Facts};
use crate::vm::{Constant, Effect, Path, Term};

/// The option holding the signals.
const OPTIONS: &str = "_cf_chl_opt";

/// The fewest copied elements that identify the probe. The probe copies 26.
const MINIMUM_READS: usize = 20;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fields {
    /// Each output field and what it holds, in the order the probe writes them.
    pub reads: IndexMap<String, Read>,
}

/// What an output field holds, from the signals array `signals`.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Read {
    /// `signals[index]`.
    Element { index: usize },
    /// `signals[index] || ""`.
    OrEmpty { index: usize },
    /// `signals[index] && signals[index].join ? signals[index].join(separator) : ""`.
    Joined { index: usize, separator: String },
}

impl Fields {
    /// The record the probe writes from `signals`. Fields holding `undefined` are left out, as
    /// the payload's JSON leaves them out.
    #[must_use]
    pub(crate) fn collect(&self, signals: &PageSignals) -> JsObject {
        let elements = signals.elements();
        let element = |index: usize| elements.get(index).cloned().unwrap_or(JsValue::Undefined);
        let mut record = JsObject::new();
        for (field, read) in &self.reads {
            let value = match read {
                Read::Element { index } => element(*index),
                Read::OrEmpty { index } => {
                    let value = element(*index);
                    if js::truthy(&value) { value } else { json!("") }
                }
                // Only arrays have `join`, which writes `null` and `undefined` as empty strings.
                Read::Joined { index, separator } => match element(*index) {
                    JsValue::Array(items) => {
                        let items: Vec<String> = items
                            .iter()
                            .map(|item| match item {
                                JsValue::Undefined | JsValue::Null => String::new(),
                                item => js::string(Some(item)),
                            })
                            .collect();
                        json!(items.join(separator))
                    }
                    _ => json!(""),
                },
            };
            if !value.is_undefined() {
                record.insert(field.clone(), value);
            }
        }
        record
    }
}

pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<Fields> {
    let index = probe.index;
    let listing = index.listing();
    // The probe copies the signals in a function it creates.
    let entries = (index.reachable(probe.entry).into_iter())
        .filter(|&pc| pc == probe.entry || index.is_entry(pc))
        .map(|pc| (pc, Registers::default()));
    let ControlFlow::Continue(incoming) = dataflow::forward(listing, entries, |_, path, known| {
        ControlFlow::<Infallible, bool>::Continue(transfer(path, known).is_some())
    });
    // Every read must come from the same option.
    let mut signals = None;
    // Each stored field's read and the first instruction storing it.
    let mut stores: BTreeMap<String, (u32, Read)> = BTreeMap::new();
    for (&pc, known) in &incoming {
        for path in &listing.instructions[&pc].paths {
            let Some(temporaries) = transfer(path, &mut known.clone()) else {
                continue;
            };
            for effect in &path.effects {
                let Effect::SetProperty { key, value, .. } = effect else {
                    continue;
                };
                let held = |term| held(term, known, &temporaries);
                let (Some(Held::Text(field)), Some(Held::Read(option, read))) =
                    (held(key), held(value))
                else {
                    continue;
                };
                if *signals.get_or_insert_with(|| option.clone()) != option {
                    return None;
                }
                let (_, stored) = stores.entry(field).or_insert_with(|| (pc, read.clone()));
                if *stored != read {
                    return None;
                }
            }
        }
    }
    let mut stores: Vec<(String, (u32, Read))> = stores.into_iter().collect();
    stores.sort_by_key(|(_, (pc, _))| *pc);
    let joined = (stores.iter())
        .filter(|(_, (_, read))| matches!(read, Read::Joined { .. }))
        .count();
    if stores.len() < MINIMUM_READS || joined != 1 {
        return None;
    }
    let reads = stores
        .into_iter()
        .map(|(field, (_, read))| (field, read))
        .collect();
    Some(Fields { reads })
}

/// What a register or temporary holds.
#[derive(Clone, Debug, PartialEq)]
enum Held {
    Undefined,
    Text(String),
    Number(f64),
    /// `_cf_chl_opt`.
    Options,
    /// The signals array, by the option holding it.
    Signals(String),
    /// An element or a value made from one, by the option holding the array.
    Read(String, Read),
    /// `signals[index].join`.
    Join(String, usize),
}

/// What registers hold on entry to an instruction.
#[derive(Clone, Debug, Default, PartialEq)]
struct Registers(BTreeMap<u8, Held>);

impl Facts for Registers {
    /// Keeps what both sides agree on. An element on one side and `""` on the other, where
    /// `x || ""` and its compiled `x ? x : ""` meet, hold `x || ""`.
    fn meet(&mut self, other: &Self) -> bool {
        let before = self.0.clone();
        self.0.retain(|register, held| {
            let Some(other) = other.0.get(register) else {
                return false;
            };
            if held != other {
                let Some(met) = either(held, other) else {
                    return false;
                };
                *held = met;
            }
            true
        });
        self.0 != before
    }
}

/// The value `x || ""` when one side holds `x` and the other `""` or `x || ""`.
fn either(left: &Held, right: &Held) -> Option<Held> {
    let or_empty = |held: &Held| match held {
        Held::Read(option, Read::Element { index } | Read::OrEmpty { index }) => {
            Some(Held::Read(option.clone(), Read::OrEmpty { index: *index }))
        }
        Held::Read(_, Read::Joined { .. }) => Some(held.clone()),
        _ => None,
    };
    match (left, right) {
        (read, other) | (other, read) if *other == Held::Text(String::new()) => or_empty(read),
        _ => or_empty(left).filter(|met| or_empty(right).as_ref() == Some(met)),
    }
}

/// Applies `path` to `known`, returning its temporaries, or `None` if the path cannot run.
/// Terms read registers as they were when the instruction started.
fn transfer(path: &Path, known: &mut Registers) -> Option<BTreeMap<usize, Held>> {
    let mut temporaries = BTreeMap::new();
    let mut writes = Vec::new();
    for effect in &path.effects {
        match effect {
            Effect::Let(temporary, term) => {
                let value = held(term, known, &temporaries);
                dataflow::assign(&mut temporaries, *temporary, value);
            }
            Effect::Set(register, term) => {
                writes.push((*register, held(term, known, &temporaries)));
            }
            _ => {}
        }
    }
    for (condition, expected) in &path.conditions {
        if undefined(condition, known, &temporaries).is_some_and(|actual| actual != *expected) {
            return None;
        }
    }
    for (register, value) in writes {
        dataflow::assign(&mut known.0, register, value);
    }
    Some(temporaries)
}

/// Decides `x === undefined` and its negations when `x` holds something known. Everything held
/// besides `undefined` is taken to be defined: the probe reads the options and checks the
/// signals before copying them, so these comparisons are its call handlers choosing the
/// receiverless call form, and its missing-signals branch, which copies no elements.
fn undefined(
    condition: &Term,
    known: &Registers,
    temporaries: &BTreeMap<usize, Held>,
) -> Option<bool> {
    match condition {
        Term::Unary(UnaryOperator::LogicalNot, inner) => {
            undefined(inner, known, temporaries).map(|value| !value)
        }
        Term::Binary(
            operator @ (BinaryOperator::StrictEquality | BinaryOperator::StrictInequality),
            left,
            right,
        ) => {
            let operand = match (&**left, &**right) {
                (operand, Term::Const(Constant::Undefined))
                | (Term::Const(Constant::Undefined), operand) => operand,
                _ => return None,
            };
            let equal = held(operand, known, temporaries)? == Held::Undefined;
            Some(equal == (*operator == BinaryOperator::StrictEquality))
        }
        _ => None,
    }
}

fn held(term: &Term, known: &Registers, temporaries: &BTreeMap<usize, Held>) -> Option<Held> {
    let held = |term| held(term, known, temporaries);
    Some(match term {
        Term::Const(Constant::Undefined) => Held::Undefined,
        Term::Const(Constant::String(text)) => Held::Text(text.clone()),
        Term::Const(Constant::Number(number)) => Held::Number(*number),
        Term::Reg(register) => known.0.get(register)?.clone(),
        Term::Temp(temporary) => temporaries.get(temporary)?.clone(),
        Term::Get(object, key) => match (held(object), held(key)?) {
            (_, Held::Text(key)) if key == OPTIONS => Held::Options,
            (Some(Held::Options), Held::Text(option)) => Held::Signals(option),
            (Some(Held::Signals(option)), Held::Number(index))
                if index >= 0.0 && index.fract() == 0.0 =>
            {
                Held::Read(
                    option,
                    Read::Element {
                        index: index as usize,
                    },
                )
            }
            (Some(Held::Read(option, Read::Element { index })), Held::Text(key))
                if key == "join" =>
            {
                Held::Join(option, index)
            }
            _ => return None,
        },
        Term::Call {
            callee, arguments, ..
        } => match (held(callee)?, arguments.as_slice()) {
            (Held::Join(option, index), [separator]) => match held(separator)? {
                Held::Text(separator) => Held::Read(option, Read::Joined { index, separator }),
                _ => return None,
            },
            _ => return None,
        },
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::*;
    use crate::embedding_page::page::{Layout, RenderedPage};

    #[test]
    fn copies_elements_as_the_probe_reads_them() {
        let page = RenderedPage::render(
            "<html><body><div class=\"cf-turnstile\" data-sitekey=\"k\"></div></body></html>",
            Url::parse("https://example.com/").unwrap(),
            "w",
            None,
        )
        .unwrap();
        let layout = Layout {
            referrer: "https://example.com/from".into(),
            ..Layout::default()
        };
        let mut signals = page.signals(&layout, None);
        signals.parent.reasons = vec!["new".into(), "api".into()];
        let fields = Fields {
            reads: IndexMap::from([
                ("referrer".into(), Read::OrEmpty { index: 2 }),
                ("hidden".into(), Read::Element { index: 23 }),
                ("scripts".into(), Read::Element { index: 10 }),
                ("mode".into(), Read::OrEmpty { index: 20 }),
                ("mount".into(), Read::OrEmpty { index: 21 }),
                (
                    "reasons".into(),
                    Read::Joined {
                        index: 22,
                        separator: "~".into(),
                    },
                ),
                ("past".into(), Read::Element { index: 30 }),
            ]),
        };
        assert_eq!(
            JsValue::Object(fields.collect(&signals)),
            json!({"referrer": "https://example.com/from", "hidden": false, "scripts": 0,
                "mode": "", "mount": "wrapper", "reasons": "new~api"}),
            "a falsy mode reads as empty, and an element past the end is left out"
        );
    }

    fn get(object: Term, key: Term) -> Term {
        Term::Get(Box::new(object), Box::new(key))
    }

    #[test]
    fn an_element_and_an_empty_string_meeting_are_the_element_or_empty() {
        let option = || "_a6e6c612eb1e0cc1f917227c".to_owned();
        let element = Held::Read(option(), Read::Element { index: 21 });
        let mut left = Registers(BTreeMap::from([(1, element.clone()), (2, element.clone())]));
        let right = Registers(BTreeMap::from([
            (1, Held::Text(String::new())),
            (2, Held::Text("x".into())),
        ]));
        assert!(left.meet(&right));
        assert_eq!(
            left,
            Registers(BTreeMap::from([(
                1,
                Held::Read(option(), Read::OrEmpty { index: 21 })
            )]))
        );
        let known = Registers(BTreeMap::from([
            (12, Held::Options),
            (13, Held::Text(option())),
            (14, Held::Number(22.0)),
        ]));
        let signals = get(Term::Reg(12), Term::Reg(13));
        assert_eq!(
            held(&get(signals, Term::Reg(14)), &known, &BTreeMap::new()),
            Some(Held::Read(option(), Read::Element { index: 22 }))
        );
        assert_eq!(
            held(
                &get(Term::Reg(9), Term::Const(Constant::String(OPTIONS.into()))),
                &known,
                &BTreeMap::new()
            ),
            Some(Held::Options)
        );
    }
}
