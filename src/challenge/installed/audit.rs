//! Audit-only recovery includes initialization's timer callbacks. It does not change the
//! options, key material, or globals used by the payload encoder.

use std::rc::Rc;

use oxc::syntax::operator::BinaryOperator;

use super::{Held, Installed};
use crate::challenge;
use crate::js::{JsValue, json};
use crate::listing::fold::{Frame, Known};
use crate::vm::{Effect, Listing, Term};

pub(super) fn read(listing: &Listing, installed: &mut Installed) {
    let mut frame = Frame::<Held>::default();
    for (&pc, instruction) in &listing.instructions {
        for path in &instruction.paths {
            frame.begin();
            frame.follow(pc, &path.effects, evaluate, |frame, effect| {
                // The key factory is declared by evaluating a literal function definition,
                // after a Trusted Types wrapper has returned that same source string.
                for argument in effect.call().map_or(&[][..], |(_, arguments)| arguments) {
                    if let Some(known) = frame.resolve(argument)
                        && let Some(text) = known.text()
                        && let Some(function) = text.strip_prefix("function ")
                        && let Some((name, _)) = function.split_once('(')
                        && challenge::is_hex_name(name)
                    {
                        installed.audit.insert(name.into(), "N".into());
                        installed
                            .audit_roles
                            .insert(name.into(), "function-factory".into());
                    }
                }
                let Effect::SetProperty { object, key, value } = effect else {
                    return;
                };
                let (Some(object), Some(key)) = (frame.resolve(object), frame.resolve(key)) else {
                    return;
                };
                let value = frame.resolve(value);
                if let Known::Ext(Held::AuditArray(array)) = &object
                    && let Known::Literal(JsValue::Number(index)) = &key
                    && *index >= 0.0
                    && index.fract() == 0.0
                {
                    let native = match &value {
                        Some(Known::Ext(Held::NativeFunction(name))) => {
                            Some(format!("function {name}() {{ [native code] }}"))
                        }
                        _ => None,
                    };
                    array.borrow_mut().insert(*index as usize, native);
                }
                if !matches!(object, Known::Ext(Held::Window)) {
                    return;
                }
                let Some(name) = key.text().filter(|name| challenge::is_hex_name(name)) else {
                    return;
                };
                let (role, audit) = match value {
                    Some(Known::Ext(Held::AuditArray(array))) => {
                        let members: Option<Vec<String>> =
                            array.borrow().values().cloned().collect();
                        let Some(members) = members else {
                            return;
                        };
                        let role = if members.is_empty() {
                            "empty-array"
                        } else {
                            "native-array"
                        };
                        (role, members.join(","))
                    }
                    Some(Known::Ext(Held::GpuPromise)) => ("gpu-adapter", "o".into()),
                    Some(Known::Ext(Held::ClockDelta)) => ("clock-delta", String::new()),
                    _ => return,
                };
                installed.audit.insert(name.into(), audit);
                installed.audit_roles.insert(name.into(), role.into());
            });
        }
    }
}

fn evaluate(frame: &Frame<Held>, value: &Term) -> Option<Known<Held>> {
    let string = |term: &Term| match frame.resolve(term) {
        Some(Known::Literal(JsValue::String(text))) => Some(text),
        _ => None,
    };
    match value {
        Term::Array(elements) if elements.is_empty() => {
            return Some(Known::Ext(Held::AuditArray(Rc::default())));
        }
        Term::Get(_, key) => {
            if let Some(name @ ("querySelector" | "querySelectorAll")) =
                frame.resolve(key).as_ref().and_then(Known::text)
            {
                return Some(Known::Ext(Held::NativeFunction(name.into())));
            }
        }
        Term::Call {
            callee, arguments, ..
        } => {
            if let Term::Get(_, method) = &**callee {
                match frame.resolve(method).as_ref().and_then(Known::text) {
                    Some("now") => return Some(Known::Ext(Held::Clock)),
                    Some("requestAdapter") => return Some(Known::Ext(Held::GpuPromise)),
                    _ => {}
                }
            }
            if let [argument] = arguments.as_slice()
                && let Some(text) = string(argument)
                && text.starts_with("function ")
            {
                return Some(Known::Literal(json!(text)));
            }
        }
        Term::Binary(BinaryOperator::Subtraction, _, right)
            if matches!(frame.resolve(right), Some(Known::Ext(Held::Clock))) =>
        {
            return Some(Known::Ext(Held::ClockDelta));
        }
        Term::Binary(BinaryOperator::Addition, left, right) => {
            if let (Some(left), Some(right)) = (string(left), string(right)) {
                return Some(Known::Literal(json!(format!("{left}{right}"))));
            }
        }
        _ => {}
    }
    super::evaluate(frame, value)
}
