//! Recovers options and globals installed by the iframe's initial VM program.
//!
//! Some installed options have `toJSON` methods returning constants, but the payload encoder
//! never calls `toJSON` and skips function members, so it sends the other members. The window
//! globals include a build marker, a selector log, and functions built from constants, such as
//! the key transform's `window[name] = factory(secret)`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use anyhow::Result;

use crate::js::{JsObject, JsValue, Options, Window, json};
use crate::listing::fold::{Frame, Known};
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
}

/// Recovers values installed by the initial `program`, decoded from its program runner call.
pub fn read(source: &Source, program: &[u8]) -> Result<Installed> {
    let listing = source.disassemble(program)?;
    let initialization = initialization(&listing);
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
                let (Some(object), Some(Known::Literal(JsValue::String(key))), Some(value)) = (
                    frame.resolve(object),
                    frame.resolve(key),
                    frame.resolve(value),
                ) else {
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
    Ok(installed)
}

/// The value an assignment writes. Recognizes calls with one string constant, such as the key
/// transform `factory(secret)`.
fn evaluate(frame: &Frame<Held>, value: &Term) -> Option<Known<Held>> {
    Some(match value {
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
