//! Recovers the trace frame reported by the environment audit.
//!
//! The preceding probe creates a helper that pushes a trace frame through a window function.
//! The audit reports this frame in place of the iframe callback frame.

use std::collections::{BTreeMap, BTreeSet};

use crate::candidates;
use crate::listing::fold::Frame;
use crate::listing::{Index, query};
use crate::vm::{Effect, Exit, Term};

/// Returns the frame pushed by the helper created at `entry`. Requires exactly one helper and
/// one frame pushed through the window's push helper.
#[must_use]
pub(super) fn controller_trace(index: &Index<'_>, push: &str, entry: u32) -> Option<String> {
    let global = index.global()?;
    if !index.is_entry(entry) {
        return None;
    }
    let preceding = body(index, entry);
    // Where each function is created.
    let mut sites: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for (pc, effect) in index.effects_in(..) {
        effect.visit_terms(&mut |term| {
            if let Term::Closure { pc: function, .. } = term {
                sites.entry(*function).or_default().push(pc);
            }
        });
    }
    // A helper belongs to the probe only if all its creation sites belong exclusively to the
    // probe body. Shared sites may run elsewhere.
    let own = |pc: &u32| {
        preceding.contains(pc)
            && !index
                .entries()
                .iter()
                .any(|&other| other != entry && body(index, other).contains(pc))
    };
    let mut frames = BTreeSet::new();
    for (helper, sites) in sites {
        if index.is_entry(helper) && sites.iter().all(own) {
            frames.extend(pushed_frames(index, &body(index, helper), global, push));
        }
    }
    candidates::exactly_one(frames, "controller frame").ok()
}

/// Follows straight-line control flow without entering callees. Attributes pushed frames to the
/// function whose instructions push them.
fn body(index: &Index<'_>, entry: u32) -> BTreeSet<u32> {
    let own = |pc: u32| pc == entry || !index.is_entry(pc);
    query::walk(index.listing(), entry, own, |_, instruction, pending| {
        pending.extend(instruction.paths.iter().filter_map(|path| match path.exit {
            Exit::Next { pc, .. } => Some(pc),
            _ => None,
        }));
    })
}

/// Frames pushed through the window inside one straight-line body.
fn pushed_frames(
    index: &Index<'_>,
    body: &BTreeSet<u32>,
    global: u8,
    push: &str,
) -> BTreeSet<String> {
    fn text(registers: &Frame, term: &Term) -> Option<String> {
        registers.resolve(term)?.text().map(str::to_owned)
    }
    let mut registers: Frame = Frame::seeded(index.header());
    let mut window = BTreeSet::new();
    let mut frames = BTreeSet::new();
    for &pc in body {
        let Some(instruction) = index.listing().instructions.get(&pc) else {
            continue;
        };
        for effect in instruction.effects() {
            effect.visit_terms(&mut |term| {
                if let Term::Call {
                    callee, arguments, ..
                } = term
                    && let Term::Get(object, key) = &**callee
                    && arguments.len() == 1
                    && text(&registers, key).as_deref() == Some(push)
                    && let Term::Reg(target) = &**object
                    && window.contains(target)
                    && let Some(frame) = text(&registers, &arguments[0])
                    && frame.len() > 40
                    && frame.contains('$')
                {
                    frames.insert(frame);
                }
            });
        }
        for effect in instruction.effects() {
            if let Effect::Set(register, value) = effect {
                window.remove(register);
                let known = registers.resolve(value);
                let unknown = known.is_none();
                registers.set(*register, known);
                if unknown
                    && let Term::Get(object, key) = value
                    && let Term::Reg(holder) = &**object
                    && *holder == global
                    && text(&registers, key).as_deref() == Some("window")
                {
                    window.insert(*register);
                }
            }
        }
    }
    frames
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::vm::{Constant, Instruction, Listing, Path, Position};

    /// Builds a probe at pc 100 that pushes its own frame and creates helpers that push theirs.
    /// `stubs` maps helper entries to frame names.
    fn trace_listing(stubs: &[(u32, &str)]) -> Listing {
        let string = |text: String| Term::Const(Constant::String(text));
        let closure = |pc| Term::Closure {
            pc,
            key: 0,
            parameters: Vec::new(),
            arity: 0,
        };
        let frame = |name: &str| string(format!("0123456789abcdef$0123456789abcdef{name}"));
        let get = |object, key| Term::Get(Box::new(Term::Reg(object)), Box::new(Term::Reg(key)));
        // `window` from the global register 228, then `window[pushTrace](frame)`.
        let window = || Effect::Set(20, get(228, 0));
        let call = || {
            let call = Term::Call {
                callee: Box::new(get(20, 16)),
                this: None,
                arguments: vec![Term::Reg(18)],
            };
            Effect::Let(0, call)
        };
        let mut instructions = BTreeMap::new();
        // Straight-line code from `start`, one effect per instruction.
        let mut run = |start: u32, effects: Vec<Effect>| {
            let last = start + effects.len() as u32 - 1;
            for (pc, effect) in (start..).zip(effects) {
                let exit = if pc == last {
                    Exit::Return
                } else {
                    Exit::Next { pc: pc + 1, key: 0 }
                };
                let paths = vec![Path {
                    conditions: vec![],
                    effects: vec![effect],
                    exit,
                }];
                let instruction = Instruction {
                    pc,
                    key: 0,
                    opcode: 0,
                    paths,
                };
                instructions.insert(pc, instruction);
            }
        };
        run(
            1,
            vec![
                Effect::Set(0, string("window".into())),
                Effect::Set(16, string("pushTrace".into())),
                Effect::Set(99, closure(50)),
            ],
        );
        // The probe body pushes its own transient frame, then creates each helper in turn.
        let mut body = vec![window(), Effect::Set(18, frame("own-body-frame")), call()];
        body.extend(
            stubs
                .iter()
                .map(|&(stub, _)| Effect::Set(90, closure(stub))),
        );
        run(100, body);
        let mut functions = vec![Position::new(100, 0)];
        for &(stub, name) in stubs {
            run(stub, vec![window(), Effect::Set(18, frame(name)), call()]);
            functions.push(Position::new(stub, 0));
        }
        Listing {
            instructions,
            functions,
            ..Listing::default()
        }
    }

    #[test]
    fn controller_frame_is_the_one_created_helper_frame() {
        let one: &[(u32, &str)] = &[(150, "stub-frame")];
        let listing = trace_listing(one);
        assert_eq!(
            controller_trace(&Index::new(&listing), "pushTrace", 100).as_deref(),
            Some("0123456789abcdef$0123456789abcdefstub-frame")
        );
        // An unknown push helper or entry recovers nothing. Neither the probe's own transient
        // frame nor one of two competing helpers' frames takes the iframe's place.
        let two: &[(u32, &str)] = &[(150, "first-frame"), (160, "second-frame")];
        for (stubs, push, entry) in [
            (one, "otherHelper", 100),
            (one, "pushTrace", 999),
            (&[], "pushTrace", 100),
            (two, "pushTrace", 100),
        ] {
            let listing = trace_listing(stubs);
            assert_eq!(
                controller_trace(&Index::new(&listing), push, entry),
                None,
                "{stubs:?} {push} {entry}"
            );
        }
    }
}
