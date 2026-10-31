//! Recovers options and globals installed by the iframe's initial VM program.
//!
//! Some installed options have `toJSON` methods returning constants, but the payload encoder
//! never calls `toJSON` and skips function members, so it sends the other members. The window
//! globals include a build marker, a selector log, and functions built from constants, such as
//! the key transform's `window[name] = factory(secret)`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use anyhow::Result;
use indexmap::IndexMap;

use crate::js::{JsObject, JsValue, Options, Window, json};
use crate::listing::fold::{Frame, Known, constant};
use crate::listing::query;
use crate::script::Source;
use crate::vm::{Effect, Exit, Listing, Term};

/// Values tracked beyond literals while recovering installed options.
#[derive(Clone)]
enum Held {
    EmptyArray,
    Options,
    Window,
    /// The result of a call with one string-constant argument.
    Built(String),
    Function,
}

/// Options and globals left by the initial program.
#[derive(Clone, Debug, Default)]
pub struct Installed {
    /// Option objects as the payload encoder serializes them.
    pub options: Options,
    /// Literal window globals. If several paths assign a global, the ordinary path is processed
    /// last and wins.
    pub window: Window,
    /// Window globals created by calls with one string constant, mapped to that constant.
    pub built: BTreeMap<String, String>,
    /// Global value classes, in installation order, for matching captured namespace properties.
    pub(crate) audit: IndexMap<String, String>,
    /// Global factories called to create installed functions.
    pub(crate) factories: BTreeSet<String>,
}

/// Recovers values installed by the initial `program`, decoded from its program runner call.
pub fn read(source: &Source, program: &[u8]) -> Result<Installed> {
    let mut listing = source.disassemble(program)?;
    crate::listing::normalize::constants(&mut listing);
    Ok(read_listing(&listing))
}

fn read_listing(listing: &Listing) -> Installed {
    let initialization = initialization(listing);
    let mut frame: Frame<Held> = Frame::default();
    let mut objects: HashMap<u32, JsObject> = HashMap::new();
    let mut installed = Installed::default();
    for (&pc, instruction) in &listing.instructions {
        if !initialization.contains(&pc) {
            continue;
        }
        for path in &instruction.paths {
            frame.begin();
            frame.follow(pc, &path.effects, evaluate, |frame, effect| {
                let Effect::SetProperty { object, key, value } = effect else {
                    return;
                };
                let (Some(object), Some(Known::Literal(JsValue::String(key)))) =
                    (frame.resolve(object), frame.resolve(key))
                else {
                    return;
                };
                let value = evaluate(frame, value);
                if matches!(object, Known::Ext(Held::Window)) {
                    let group = match &value {
                        Some(Known::Object(_)) => "o".to_owned(),
                        Some(Known::Ext(Held::Function | Held::Built(_))) => "N".to_owned(),
                        Some(Known::Ext(Held::EmptyArray)) => "".to_owned(),
                        Some(Known::Literal(JsValue::String(value))) => value.clone(),
                        Some(Known::Literal(JsValue::Number(value))) => value.to_string(),
                        Some(Known::Literal(JsValue::Bool(value))) => {
                            if *value { "T" } else { "F" }.to_owned()
                        }
                        _ => "?".to_owned(),
                    };
                    if group != "?" || !installed.audit.contains_key(&key) {
                        installed.audit.insert(key.clone(), group);
                    }
                }
                let Some(value) = value else {
                    return;
                };
                match (object, value) {
                    // The encoder skips function members, such as `toJSON`.
                    (Known::Object(id), Known::Literal(value)) => {
                        objects.entry(id).or_default().insert(key, value);
                    }
                    (
                        Known::Ext(Held::Window),
                        Known::Literal(value @ (JsValue::String(_) | JsValue::Number(_))),
                    ) => {
                        installed.window.insert(key, value);
                    }
                    (Known::Ext(Held::Window), Known::Ext(Held::EmptyArray)) => {
                        installed.window.insert(key, json!([]));
                    }
                    (Known::Ext(Held::Window), Known::Ext(Held::Built(constant))) => {
                        installed.built.insert(key, constant);
                    }
                    (Known::Ext(Held::Options), Known::Object(id)) => {
                        let members = objects.get(&id).cloned().unwrap_or_default();
                        installed.options.insert(key, JsValue::Object(members));
                    }
                    _ => {}
                }
            });
        }
    }
    let index = crate::listing::Index::new(listing);
    for store in index.stores() {
        let Some((at, Term::Get(_, key))) = index.dereference(store.pc, &Term::Reg(store.object))
        else {
            continue;
        };
        if index.text(at, &key).as_deref() != Some("window") {
            continue;
        }
        let Some((_, value)) = index.dereference(store.pc, &store.value) else {
            continue;
        };
        let kind = match value {
            Term::Closure { .. } => "N",
            Term::Object(_) => "o",
            Term::Array(_) => "",
            Term::Binary(_, _, _) | Term::Unary(_, _) => "number",
            Term::Call { .. } => "call",
            Term::Get(_, _) => "get",
            _ => "?",
        };
        if installed
            .audit
            .get(&store.key)
            .is_none_or(|value| value == "?")
        {
            installed.audit.insert(store.key.clone(), kind.into());
        }
    }
    for (pc, effect) in index.effects_in(..) {
        effect.visit_terms(&mut |term| {
            if let Term::Call {
                callee, arguments, ..
            } = term
                && let [argument] = arguments.as_slice()
                && let Some(value) = index.text(pc, argument)
                && installed.built.values().any(|secret| secret == &value)
                && let Some(factory) = index.member(pc, callee)
                && matches!(factory.object, Term::Reg(global) if Some(global) == index.global())
            {
                installed.factories.insert(factory.key);
            }
        });
    }
    installed
}

/// The value an assignment writes. Recognizes calls with one string constant, such as the key
/// transform `factory(secret)`.
fn evaluate(frame: &Frame<Held>, value: &Term) -> Option<Known<Held>> {
    if let Some(value) = constant(frame, value) {
        return Some(Known::Literal(value));
    }
    Some(match value {
        Term::Closure { .. } => Known::Ext(Held::Function),
        Term::Array(elements) if elements.is_empty() => Known::Ext(Held::EmptyArray),
        Term::Get(_, key) => match frame.resolve(key)?.text()? {
            "_cf_chl_opt" => Known::Ext(Held::Options),
            "window" => Known::Ext(Held::Window),
            _ => return None,
        },
        Term::Call { arguments, .. } => {
            let [argument] = arguments.as_slice() else {
                return None;
            };
            Known::Ext(Held::Built(frame.resolve(argument)?.text()?.to_owned()))
        }
        value => frame.resolve(value)?,
    })
}

/// Finds startup instructions reachable from the entry, the returned function called by the
/// iframe, and their callees. Excludes exception handlers and callbacks that are installed
/// without being called.
fn initialization(listing: &Listing) -> BTreeSet<u32> {
    let returned = return_register(listing);
    let entry = listing.functions.first().map(|function| function.pc);
    let mut reached = BTreeSet::new();
    let mut functions: Vec<u32> = entry.into_iter().collect();
    let mut entered = HashSet::new();
    while let Some(function) = functions.pop() {
        if !entered.insert(function) {
            continue;
        }
        let entry_function = Some(function) == entry;
        let mut closures: HashMap<u8, u32> = HashMap::new();
        let unreached = |pc: u32| !reached.contains(&pc);
        let walked = query::walk(listing, function, unreached, |_, instruction, pending| {
            for path in &instruction.paths {
                for effect in &path.effects {
                    match effect {
                        Effect::Set(register, Term::Closure { pc, .. }) => {
                            closures.insert(*register, *pc);
                        }
                        Effect::Set(register, Term::Reg(source))
                            if entry_function && Some(*register) == returned =>
                        {
                            functions.extend(closures.get(source));
                        }
                        _ => {
                            if let Some((Term::Reg(register), _)) = effect.call()
                                && let Some(&function) = closures.get(register)
                            {
                                functions.push(function);
                            }
                        }
                    }
                }
                if let Exit::Next { pc, .. } | Exit::Unfollowed { pc, .. } = path.exit {
                    pending.push(pc);
                }
            }
        });
        reached.extend(walked);
    }
    reached
}

/// Finds the register that most return instructions write last.
fn return_register(listing: &Listing) -> Option<u8> {
    let mut counts: HashMap<u8, usize> = HashMap::new();
    let returns = listing
        .instructions
        .values()
        .flat_map(|instruction| &instruction.paths)
        .filter(|path| path.exit == Exit::Return);
    for path in returns {
        // Newer instruction layouts restore the VM stack after assigning the return value.
        let written = path.effects.iter().rev().find_map(|effect| match effect {
            Effect::Set(register, _) => Some(*register),
            _ => None,
        });
        if let Some(register) = written {
            *counts.entry(register).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .max_by_key(|&(register, count)| (count, register))
        .map(|(register, _)| register)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{Constant, Instruction, Path, Position};
    use swc_core::ecma::ast::BinaryOp;

    fn text(value: &str) -> Term {
        Term::Const(Constant::String(value.into()))
    }

    fn number(value: f64) -> Term {
        Term::Const(Constant::Number(value))
    }

    fn method(object: Term, name: &str, arguments: Vec<Term>) -> Term {
        Term::Call {
            callee: Box::new(Term::Get(Box::new(object), Box::new(text(name)))),
            this: None,
            arguments,
        }
    }

    #[test]
    fn records_the_global_factory_that_built_an_installed_function() {
        let effects = vec![
            Effect::Set(
                1,
                Term::Get(Box::new(Term::Reg(99)), Box::new(text("window"))),
            ),
            Effect::Set(
                2,
                method(Term::Reg(99), "factory", vec![text("synthetic-secret")]),
            ),
            Effect::SetProperty {
                object: Box::new(Term::Reg(1)),
                key: Box::new(text("transform")),
                value: Box::new(Term::Reg(2)),
            },
            Effect::Set(
                3,
                method(Term::Reg(99), "unrelated", vec![text("different-value")]),
            ),
        ];
        let mut listing = Listing::default();
        listing.functions.push(Position::new(0, 0));
        let count = effects.len() as u32;
        for (pc, effect) in (0..).zip(effects) {
            listing.instructions.insert(
                pc,
                Instruction {
                    pc,
                    key: 0,
                    opcode: 0,
                    paths: vec![Path {
                        conditions: vec![],
                        effects: vec![effect],
                        exit: if pc + 1 == count {
                            Exit::Return
                        } else {
                            Exit::Next { pc: pc + 1, key: 0 }
                        },
                    }],
                },
            );
        }
        let installed = read_listing(&listing);
        assert_eq!(installed.factories, BTreeSet::from(["factory".into()]));
        assert_eq!(
            installed.built,
            BTreeMap::from([("transform".into(), "synthetic-secret".into())])
        );
    }

    #[test]
    fn recovers_a_key_transform_with_an_inline_decoded_global_name() {
        let effects = vec![
            Effect::Set(
                1,
                Term::Get(
                    Box::new(Term::Global("self".into())),
                    Box::new(text("window")),
                ),
            ),
            Effect::Set(2, text("\0\u{9}fresh_key\0padding")),
            Effect::Set(3, method(Term::Reg(2), "charCodeAt", vec![number(0.0)])),
            Effect::Set(4, method(Term::Reg(2), "charCodeAt", vec![number(1.0)])),
            Effect::Set(
                3,
                Term::Binary(
                    BinaryOp::Mul,
                    Box::new(Term::Reg(3)),
                    Box::new(number(256.0)),
                ),
            ),
            Effect::Set(
                3,
                Term::Binary(
                    BinaryOp::Add,
                    Box::new(Term::Reg(3)),
                    Box::new(Term::Reg(4)),
                ),
            ),
            Effect::Set(
                3,
                Term::Binary(BinaryOp::Add, Box::new(Term::Reg(3)), Box::new(number(2.0))),
            ),
            Effect::Set(
                2,
                method(Term::Reg(2), "slice", vec![number(2.0), Term::Reg(3)]),
            ),
            Effect::Set(
                5,
                Term::Call {
                    callee: Box::new(Term::Reg(99)),
                    this: None,
                    arguments: vec![text("synthetic-secret")],
                },
            ),
            Effect::SetProperty {
                object: Box::new(Term::Reg(1)),
                key: Box::new(Term::Reg(2)),
                value: Box::new(Term::Reg(5)),
            },
        ];
        let mut listing = Listing::default();
        listing.functions.push(Position::new(0, 0));
        listing.instructions.insert(
            0,
            Instruction {
                pc: 0,
                key: 0,
                opcode: 0,
                paths: vec![Path {
                    conditions: vec![],
                    effects,
                    exit: Exit::Return,
                }],
            },
        );
        assert_eq!(
            read_listing(&listing).built,
            BTreeMap::from([("fresh_key".into(), "synthetic-secret".into())])
        );
    }

    #[test]
    fn constant_string_operations_use_javascript_utf16_indexes() {
        let frame: Frame<Held> = Frame::default();
        assert_eq!(
            constant(
                &frame,
                &method(text("a😀z"), "charCodeAt", vec![number(1.0)])
            ),
            Some(JsValue::Number(0xd83d as f64))
        );
        assert_eq!(
            constant(
                &frame,
                &method(text("a😀z"), "slice", vec![number(1.0), number(3.0)])
            ),
            Some(json!("😀"))
        );
        assert_eq!(
            constant(
                &frame,
                &method(text("abcdef"), "slice", vec![number(-3.0), number(99.0)])
            ),
            Some(json!("def"))
        );
        assert_eq!(
            constant(
                &frame,
                &method(text("abc"), "slice", vec![number(2.0), number(1.0)])
            ),
            Some(json!(""))
        );
        assert_eq!(
            constant(
                &frame,
                &method(text("a😀z"), "slice", vec![number(1.0), number(2.0)])
            ),
            None
        );
        let outside = constant(
            &frame,
            &method(text("abc"), "charCodeAt", vec![number(-1.0)]),
        )
        .unwrap();
        assert!(outside.as_f64().unwrap().is_nan());
        assert!(
            constant(
                &frame,
                &method(Term::Reg(99), "slice", vec![number(0.0), number(2.0)])
            )
            .is_none()
        );
    }
}
