//! Recovers options and globals installed by the iframe's initial VM program.
//!
//! Some installed options have `toJSON` methods returning constants, but the payload encoder
//! never calls `toJSON` and skips function members, so it sends the other members. The window
//! globals include a build marker, a selector log, and functions built from constants, such as
//! the key transform's `window[name] = factory(secret)`.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;

use anyhow::Result;
use oxc::syntax::operator::BinaryOperator;

use crate::js::{JsObject, JsValue, Options, Window, json};
use crate::listing::fold::{Frame, Known};
use crate::listing::query;
use crate::script::Source;
use crate::vm::{Effect, Exit, Listing, Term};

mod audit;

/// Values tracked beyond literals while recovering installed options.
#[derive(Clone)]
enum Held {
    EmptyArray,
    Options,
    Window,
    /// The result of a call with one string-constant argument.
    Built(String),
    /// An array the audit fills by index, holding native function sources where known.
    AuditArray(Rc<RefCell<BTreeMap<usize, Option<String>>>>),
    NativeFunction(String),
    /// The result of a `now()` call.
    Clock,
    ClockDelta,
    GpuPromise,
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
    /// Initial global values as classified by the environment audit.
    pub audit: BTreeMap<String, String>,
    /// Semantic roles for globals whose values alone do not identify their definitions.
    pub audit_roles: BTreeMap<String, String>,
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
                if matches!(object, Known::Ext(Held::Window)) {
                    let audit = match &value {
                        Known::Literal(JsValue::String(text)) => Some(text.clone()),
                        Known::Literal(JsValue::Number(number)) => Some(number.to_string()),
                        Known::Literal(JsValue::Bool(true)) => Some("T".into()),
                        Known::Literal(JsValue::Bool(false)) => Some("F".into()),
                        Known::Object(_) => Some("o".into()),
                        Known::Ext(Held::Built(_)) => Some("N".into()),
                        _ => None,
                    };
                    if let Some(audit) = audit {
                        installed.audit.insert(key.clone(), audit);
                    }
                }
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
    audit::read(&listing, &mut installed);
    Ok(installed)
}

/// The value an assignment writes. Recognizes calls with one string constant, such as the key
/// transform `factory(secret)`, and folds the arithmetic and string methods that unpack
/// length-prefixed names.
fn evaluate(frame: &Frame<Held>, value: &Term) -> Option<Known<Held>> {
    Some(match value {
        Term::Array(elements) if elements.is_empty() => Known::Ext(Held::EmptyArray),
        Term::Get(_, key) => match frame.resolve(key)?.text()? {
            "_cf_chl_opt" => Known::Ext(Held::Options),
            "window" => Known::Ext(Held::Window),
            _ => return None,
        },
        Term::Call {
            callee,
            this,
            arguments,
        } => {
            if this.is_none()
                && let Some(folded) = string_method(frame, callee, arguments)
            {
                return Some(folded);
            }
            let [argument] = arguments.as_slice() else {
                return None;
            };
            Known::Ext(Held::Built(frame.resolve(argument)?.text()?.to_owned()))
        }
        Term::Binary(BinaryOperator::Addition, left, right) => {
            Known::Literal(json!(number(frame, left)? + number(frame, right)?))
        }
        Term::Binary(BinaryOperator::Multiplication, left, right) => {
            Known::Literal(json!(number(frame, left)? * number(frame, right)?))
        }
        value => frame.resolve(value)?,
    })
}

/// Folds `charCodeAt` and `slice` on a known string. Some programs store names as
/// length-prefixed constants padded with NULs and unpack them with
/// `text.slice(2, 2 + 256 * text.charCodeAt(0) + text.charCodeAt(1))`.
fn string_method(frame: &Frame<Held>, callee: &Term, arguments: &[Term]) -> Option<Known<Held>> {
    let Term::Get(receiver, method) = callee else {
        return None;
    };
    let text: Vec<u16> = frame.resolve(receiver)?.text()?.encode_utf16().collect();
    let index = |argument: &Term| {
        let index = number(frame, argument)?;
        // Negative indexes count from the end; the unpacking never uses them.
        (index >= 0.0 && index.fract() == 0.0).then_some(index as usize)
    };
    Some(match (frame.resolve(method)?.text()?, arguments) {
        ("charCodeAt", [position]) => {
            Known::Literal(json!(f64::from(*text.get(index(position)?)?)))
        }
        ("slice", [start, end]) => {
            let end = index(end)?.min(text.len());
            let start = index(start)?.min(end);
            Known::Literal(json!(String::from_utf16(&text[start..end]).ok()?))
        }
        _ => return None,
    })
}

fn number(frame: &Frame<Held>, term: &Term) -> Option<f64> {
    match frame.resolve(term)? {
        Known::Literal(value) => value.as_f64(),
        _ => None,
    }
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
    use crate::vm::Constant;

    #[test]
    fn unpacks_length_prefixed_names() {
        let mut frame: Frame<Held> = Frame::default();
        frame.set(1, Some(Known::Literal(json!("\0\u{3}abc\0\0\0"))));
        let register = |register| Box::new(Term::Reg(register));
        let number = |value| Term::Const(Constant::Number(value));
        let method = |name: &str, arguments| Term::Call {
            callee: Box::new(Term::Get(
                register(1),
                Box::new(Term::Const(Constant::String(name.into()))),
            )),
            this: None,
            arguments,
        };
        let mut set = |target, term: Term| {
            let value = evaluate(&frame, &term);
            frame.set(target, value);
        };
        // `text.slice(2, 256 * text.charCodeAt(0) + text.charCodeAt(1) + 2)`
        set(2, method("charCodeAt", vec![number(0.0)]));
        set(3, method("charCodeAt", vec![number(1.0)]));
        set(
            4,
            Term::Binary(
                BinaryOperator::Multiplication,
                Box::new(number(256.0)),
                register(2),
            ),
        );
        set(
            4,
            Term::Binary(BinaryOperator::Addition, register(4), register(3)),
        );
        set(
            4,
            Term::Binary(BinaryOperator::Addition, register(4), Box::new(number(2.0))),
        );
        set(5, method("slice", vec![number(2.0), Term::Reg(4)]));
        assert_eq!(frame.register(5).and_then(Known::text), Some("abc"));

        // A call with one string argument still builds a global.
        let built = evaluate(&frame, &method("factory", vec![Term::Reg(5)]));
        assert!(matches!(built, Some(Known::Ext(Held::Built(secret))) if secret == "abc"));
        // Out-of-range and negative indexes stay unknown.
        assert!(evaluate(&frame, &method("charCodeAt", vec![number(9.0)])).is_none());
        assert!(evaluate(&frame, &method("slice", vec![number(-1.0), number(2.0)])).is_none());
    }
}
