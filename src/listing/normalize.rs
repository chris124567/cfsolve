//! Exposes constant expressions to structural readers without executing calls.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::ops::ControlFlow;

use super::Index;
use super::fold::{self, Frame, Known};
use crate::js::JsValue;
use crate::vm::{Constant, Effect, Listing, Term, dataflow};

fn evaluate(frame: &Frame, term: &Term) -> Option<Known> {
    if let Some(known) = frame.resolve(term) {
        return Some(known);
    }
    let value = fold::constant(frame, term);
    if matches!(term, Term::Binary(_, _, _)) && matches!(value, Some(JsValue::String(_))) {
        return None;
    }
    value.map(|value| {
        if matches!(value, JsValue::String(_)) {
            Known::Decoded(value)
        } else {
            Known::Literal(value)
        }
    })
}

/// Fold only values agreed on by every incoming path. Function and dispatcher
/// entries start with common header facts, never another function's registers.
pub(crate) fn constants(listing: &mut Listing) {
    let setup = Frame::seeded(Index::new(listing).header());
    let mut entries: BTreeSet<_> = listing
        .functions
        .iter()
        .map(|entry| entry.pc)
        .chain(listing.hidden.iter().map(|branch| branch.target.pc))
        .collect();
    for instruction in listing.instructions.values() {
        for effect in instruction.effects() {
            effect.visit_terms(&mut |term| {
                if let Term::Array(frame) = term {
                    entries.extend(crate::vm::catch_frame(frame).map(|handler| handler.pc));
                }
            });
        }
    }
    let entries = entries.into_iter().map(|pc| (pc, setup.clone()));
    let ControlFlow::<Infallible, _>::Continue(incoming) =
        dataflow::forward(listing, entries, |pc, path, frame| {
            frame.begin();
            if !fold::feasible(path, |term| evaluate(frame, term)) {
                return ControlFlow::Continue(false);
            }
            frame.follow(pc, &path.effects, evaluate, |_, _| {});
            ControlFlow::Continue(true)
        });
    for (&pc, instruction) in &mut listing.instructions {
        let Some(entry) = incoming.get(&pc) else {
            continue;
        };
        for path in &mut instruction.paths {
            let mut frame = entry.clone();
            frame.begin();
            for effect in &mut path.effects {
                if let Effect::SetProperty { key, .. } = effect
                    && let Some(Known::Decoded(JsValue::String(text))) = frame.resolve(key)
                {
                    **key = Term::Const(Constant::String(text));
                }
                let folded = match &*effect {
                    Effect::Let(_, value) | Effect::Set(_, value) => evaluate(&frame, value),
                    _ => None,
                };
                frame.follow(pc, std::slice::from_ref(effect), evaluate, |_, _| {});
                if let Effect::Let(_, value) | Effect::Set(_, value) = effect {
                    match folded {
                        Some(Known::Decoded(JsValue::String(text))) => {
                            *value = Term::Const(Constant::String(text))
                        }
                        Some(Known::Literal(JsValue::Number(number)))
                            if matches!(value, Term::Call { .. } | Term::Binary(_, _, _)) =>
                        {
                            *value = Term::Const(Constant::Number(number))
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{Exit, Instruction, Path, Position};

    fn text(value: &str) -> Term {
        Term::Const(Constant::String(value.into()))
    }

    fn slice(register: u8) -> Term {
        Term::Call {
            callee: Box::new(Term::Get(
                Box::new(Term::Reg(register)),
                Box::new(text("slice")),
            )),
            this: Some(Box::new(Term::Reg(register))),
            arguments: vec![
                Term::Const(Constant::Number(2.0)),
                Term::Const(Constant::Number(7.0)),
            ],
        }
    }

    fn path(effects: Vec<Effect>, exit: Exit) -> Path {
        Path {
            conditions: vec![],
            effects,
            exit,
        }
    }

    fn program(paths: Vec<Vec<Path>>) -> Listing {
        let mut listing = Listing::default();
        listing.functions.push(Position::new(0, 0));
        for (pc, paths) in (0..).zip(paths) {
            listing.instructions.insert(
                pc,
                Instruction {
                    pc,
                    key: 0,
                    opcode: 0,
                    paths,
                },
            );
        }
        // End the common header before any branch-specific constants.
        listing.instructions.get_mut(&0).unwrap().paths[0]
            .effects
            .insert(
                0,
                Effect::Set(
                    255,
                    Term::Closure {
                        pc: 100,
                        key: 0,
                        parameters: vec![],
                        arity: 0,
                    },
                ),
            );
        listing
    }

    #[test]
    fn decoded_strings_survive_temporaries_and_instruction_boundaries() {
        let mut listing = program(vec![
            vec![path(
                vec![Effect::Set(1, text("\0\u{5}freshpadding"))],
                Exit::Next { pc: 1, key: 0 },
            )],
            vec![path(
                vec![Effect::Let(0, slice(1)), Effect::Set(2, Term::Temp(0))],
                Exit::Next { pc: 2, key: 0 },
            )],
            vec![path(vec![Effect::Set(3, Term::Reg(2))], Exit::Return)],
        ]);
        constants(&mut listing);
        assert_eq!(
            listing.instructions[&1].paths[0].effects[1],
            Effect::Set(2, text("fresh"))
        );
        assert_eq!(
            listing.instructions[&2].paths[0].effects[0],
            Effect::Set(3, text("fresh"))
        );
    }

    #[test]
    fn disagreement_and_unknown_writes_leave_calls_unfolded() {
        let mut listing = program(vec![
            vec![path(vec![], Exit::Next { pc: 1, key: 0 })],
            vec![
                path(
                    vec![Effect::Set(1, text("\0\u{5}first"))],
                    Exit::Next { pc: 2, key: 0 },
                ),
                path(
                    vec![Effect::Set(1, text("\0\u{5}other"))],
                    Exit::Next { pc: 2, key: 0 },
                ),
            ],
            vec![path(
                vec![
                    Effect::Set(2, slice(1)),
                    Effect::Set(1, Term::Global("unknown".into())),
                    Effect::Set(3, slice(1)),
                ],
                Exit::Return,
            )],
        ]);
        let expected = listing.instructions[&2].paths[0].effects.clone();
        constants(&mut listing);
        assert_eq!(listing.instructions[&2].paths[0].effects, expected);
    }

    #[test]
    fn ordinary_register_copies_and_string_assembly_keep_their_shape() {
        use swc_core::ecma::ast::BinaryOp;
        let mut listing = program(vec![vec![path(
            vec![
                Effect::Set(1, text("window")),
                Effect::Set(2, Term::Reg(1)),
                Effect::Set(
                    3,
                    Term::Binary(
                        BinaryOp::Add,
                        Box::new(text("prefix")),
                        Box::new(text("suffix")),
                    ),
                ),
            ],
            Exit::Return,
        )]]);
        let expected = listing.instructions[&0].paths[0].effects.clone();
        constants(&mut listing);
        assert_eq!(listing.instructions[&0].paths[0].effects, expected);
    }

    #[test]
    fn exception_handlers_start_with_header_facts_and_decode_their_own_strings() {
        let frame = Term::Array(vec![
            Term::Const(Constant::Number(1.0)),
            Term::Const(Constant::Number(0.0)),
            Term::Cells,
            Term::Const(Constant::Number(0.0)),
        ]);
        let mut listing = program(vec![
            vec![path(
                vec![Effect::Set(2, text("\0\u{5}prior")), Effect::Let(0, frame)],
                Exit::Return,
            )],
            vec![path(
                vec![
                    Effect::Set(3, slice(2)),
                    Effect::Set(1, text("\0\u{5}catch")),
                ],
                Exit::Next { pc: 2, key: 0 },
            )],
            vec![path(vec![Effect::Set(4, slice(1))], Exit::Return)],
        ]);
        constants(&mut listing);
        assert_eq!(
            listing.instructions[&1].paths[0].effects[0],
            Effect::Set(3, slice(2))
        );
        assert_eq!(
            listing.instructions[&2].paths[0].effects[0],
            Effect::Set(4, text("catch"))
        );
    }
}
