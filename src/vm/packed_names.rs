//! Folds names the program unpacks at run time. Some programs store a name as
//! `"\0\x19" + name + NUL padding` and unpack it with
//! `text.slice(2, 256 * text.charCodeAt(0) + text.charCodeAt(1) + 2)`. Folding `charCodeAt`,
//! `slice`, `+` and `*` on constant registers rewrites each unpacking call to the resulting
//! string, so readers of the listing see an ordinary string load.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::Infallible;
use std::ops::ControlFlow;
use std::rc::Rc;

use oxc::syntax::operator::BinaryOperator;

use super::output::{Constant, Effect, Listing, Path, Term};
use super::{dataflow, disassemble};

/// Constant registers on entry to an instruction, shared as the dataflow copies them per path.
type Registers = BTreeMap<u8, Rc<Constant>>;

/// Constants held by temporaries.
type Temporaries = HashMap<usize, Rc<Constant>>;

pub(super) fn fold(listing: &mut Listing) {
    // Unrecorded entries, such as functions and hidden targets, start with nothing known.
    let functions = listing.functions.iter().map(|function| function.pc);
    let hidden = listing.hidden.iter().map(|hidden| hidden.target.pc);
    let incoming = forward(listing, functions.chain(hidden));
    // A catch path must not erase facts already recovered on the normal path.
    // Fold its exclusive instructions separately with unknown entry registers.
    let exceptional = forward(listing, disassemble::exception_entries(listing));
    for (pc, instruction) in &mut listing.instructions {
        let Some(entry) = incoming.get(pc).or_else(|| exceptional.get(pc)) else {
            continue;
        };
        for path in &mut instruction.paths {
            rewrite(path, entry.clone());
        }
    }
}

/// The constant registers on entry to each instruction reachable from `entries`.
fn forward(listing: &Listing, entries: impl IntoIterator<Item = u32>) -> BTreeMap<u32, Registers> {
    let entries = entries.into_iter().map(|pc| (pc, Registers::new()));
    let ControlFlow::Continue(incoming) = dataflow::forward(listing, entries, |_, path, known| {
        let mut temporaries = Temporaries::new();
        for effect in &path.effects {
            step(effect, known, &mut temporaries);
        }
        ControlFlow::<Infallible, bool>::Continue(true)
    });
    incoming
}

/// Rewrites folded string-method results in `path` to constants.
fn rewrite(path: &mut Path, mut known: Registers) {
    let mut temporaries = Temporaries::new();
    // Temporaries holding a folded call.
    let mut folded_temporaries = HashSet::new();
    for effect in &mut path.effects {
        let folded = match &*effect {
            // Only `charCodeAt` and `slice` calls fold.
            Effect::Let(_, term @ Term::Call { .. }) | Effect::Set(_, term @ Term::Call { .. }) => {
                value(term, &known, &temporaries)
            }
            Effect::Set(_, Term::Temp(temporary)) if folded_temporaries.contains(temporary) => {
                temporaries.get(temporary).cloned()
            }
            _ => None,
        };
        step(effect, &mut known, &mut temporaries);
        if let Effect::Let(temporary, _) = effect {
            if folded.is_some() {
                folded_temporaries.insert(*temporary);
            } else {
                folded_temporaries.remove(temporary);
            }
        }
        if let (Some(constant), Effect::Let(_, term) | Effect::Set(_, term)) = (folded, effect) {
            *term = Term::Const(Rc::unwrap_or_clone(constant));
        }
    }
}

/// Records the constant an effect writes, if any. As in the other listing folds, calls leave the
/// caller's registers alone.
fn step(effect: &Effect, known: &mut Registers, temporaries: &mut Temporaries) {
    match effect {
        Effect::Let(temporary, term) => match value(term, known, temporaries) {
            Some(constant) => temporaries.insert(*temporary, constant),
            None => temporaries.remove(temporary),
        },
        Effect::Set(register, term) => match value(term, known, temporaries) {
            Some(constant) => known.insert(*register, constant),
            None => known.remove(register),
        },
        _ => None,
    };
}

/// The string or number `term` evaluates to, if constant.
fn value(term: &Term, known: &Registers, temporaries: &Temporaries) -> Option<Rc<Constant>> {
    let value = |term| value(term, known, temporaries);
    let number = |term| match *value(term)? {
        Constant::Number(number) => Some(number),
        _ => None,
    };
    let number_constant = |number| Some(Rc::new(Constant::Number(number)));
    match term {
        Term::Const(constant @ (Constant::String(_) | Constant::Number(_))) => {
            Some(Rc::new(constant.clone()))
        }
        Term::Reg(register) => known.get(register).cloned(),
        Term::Temp(temporary) => temporaries.get(temporary).cloned(),
        Term::Binary(BinaryOperator::Addition, left, right) => {
            number_constant(number(left)? + number(right)?)
        }
        Term::Binary(BinaryOperator::Multiplication, left, right) => {
            number_constant(number(left)? * number(right)?)
        }
        Term::Call {
            callee,
            this: None,
            arguments,
        } => {
            let Term::Get(receiver, method) = &**callee else {
                return None;
            };
            let receiver = value(receiver)?;
            let (Constant::String(text), Term::Const(Constant::String(method))) =
                (&*receiver, &**method)
            else {
                return None;
            };
            let text: Vec<u16> = text.encode_utf16().collect();
            // Negative and fractional indexes never occur in the unpacking.
            let index = |term| {
                let index = number(term)?;
                (index >= 0.0 && index.fract() == 0.0).then_some(index as usize)
            };
            match (method.as_str(), arguments.as_slice()) {
                ("charCodeAt", [position]) => {
                    number_constant(f64::from(*text.get(index(position)?)?))
                }
                ("slice", [start, end]) => {
                    let end = index(end)?.min(text.len());
                    let start = index(start)?.min(end);
                    Some(Rc::new(Constant::String(
                        String::from_utf16(&text[start..end]).ok()?,
                    )))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::output::{Exit, Instruction, Position};

    fn string(text: &str) -> Term {
        Term::Const(Constant::String(text.into()))
    }

    fn number(value: f64) -> Term {
        Term::Const(Constant::Number(value))
    }

    fn method(receiver: u8, name: &str, arguments: Vec<Term>) -> Term {
        Term::Call {
            callee: Box::new(Term::Get(
                Box::new(Term::Reg(receiver)),
                Box::new(string(name)),
            )),
            this: None,
            arguments,
        }
    }

    fn binary(op: BinaryOperator, left: u8, right: u8) -> Term {
        Term::Binary(op, Box::new(Term::Reg(left)), Box::new(Term::Reg(right)))
    }

    fn insert(listing: &mut Listing, pc: u32, effects: Vec<Effect>, exit: Exit) {
        let path = Path {
            conditions: Vec::new(),
            effects,
            exit,
        };
        let instruction = Instruction {
            pc,
            key: 0,
            opcode: 0,
            paths: vec![path],
        };
        listing.instructions.insert(pc, instruction);
    }

    #[test]
    fn folds_unpacked_names_to_string_loads() {
        // r1 = packed; r2 = 0; r3 = 1; r4 = 2; r5 = 256;
        // r6 = r1.charCodeAt(r2); r2 = r1.charCodeAt(r3); r6 = r6 * r5 + r2 + r4;
        // r1 = r1.slice(r4, r6); payload[r1] = 0
        let effects = vec![
            vec![Effect::Set(1, string("\0\u{3}abc\0\0\0\0"))],
            vec![
                Effect::Set(2, number(0.0)),
                Effect::Set(3, number(1.0)),
                Effect::Set(4, number(2.0)),
                Effect::Set(5, number(256.0)),
            ],
            vec![
                Effect::Let(0, method(1, "charCodeAt", vec![Term::Reg(2)])),
                Effect::Set(6, Term::Temp(0)),
            ],
            vec![
                Effect::Let(0, method(1, "charCodeAt", vec![Term::Reg(3)])),
                Effect::Set(2, Term::Temp(0)),
            ],
            vec![Effect::Set(6, binary(BinaryOperator::Multiplication, 6, 5))],
            vec![Effect::Set(6, binary(BinaryOperator::Addition, 6, 2))],
            vec![Effect::Set(6, binary(BinaryOperator::Addition, 6, 4))],
            vec![
                Effect::Let(0, method(1, "slice", vec![Term::Reg(4), Term::Reg(6)])),
                Effect::Set(1, Term::Temp(0)),
            ],
        ];
        let count = u32::try_from(effects.len()).unwrap();
        let mut listing = Listing {
            functions: vec![Position::new(0, 0)],
            ..Listing::default()
        };
        for (pc, effects) in (0..).zip(effects) {
            let exit = if pc + 1 == count {
                Exit::Return
            } else {
                Exit::Next { pc: pc + 1, key: 0 }
            };
            insert(&mut listing, pc, effects, exit);
        }
        fold(&mut listing);
        let last = &listing.instructions[&(count - 1)].paths[0].effects;
        assert_eq!(
            last,
            &[Effect::Let(0, string("abc")), Effect::Set(1, string("abc"))]
        );
        let first_code = &listing.instructions[&2].paths[0].effects;
        assert_eq!(
            first_code,
            &[Effect::Let(0, number(0.0)), Effect::Set(6, number(0.0))]
        );
    }

    #[test]
    fn catch_names_fold_without_erasing_normal_path_names() {
        let mut listing = Listing {
            functions: vec![Position::new(0, 0)],
            ..Listing::default()
        };
        insert(
            &mut listing,
            0,
            vec![
                Effect::Set(1, string("\0\u{3}abc\0")),
                Effect::Set(2, number(2.0)),
                Effect::Set(3, number(5.0)),
                Effect::Set(
                    9,
                    Term::Array(vec![Term::Array(vec![
                        number(100.0),
                        number(0.0),
                        Term::Cells,
                        number(0.0),
                    ])]),
                ),
            ],
            Exit::Next { pc: 1, key: 0 },
        );
        insert(
            &mut listing,
            1,
            vec![Effect::Set(
                1,
                method(1, "slice", vec![Term::Reg(2), Term::Reg(3)]),
            )],
            Exit::Return,
        );
        insert(
            &mut listing,
            100,
            vec![
                Effect::Set(1, string("\0\u{3}xyz\0")),
                Effect::Set(2, number(2.0)),
                Effect::Set(3, number(5.0)),
                Effect::Set(4, method(1, "slice", vec![Term::Reg(2), Term::Reg(3)])),
            ],
            Exit::Next { pc: 1, key: 0 },
        );
        fold(&mut listing);
        assert_eq!(
            listing.instructions[&1].paths[0].effects[0],
            Effect::Set(1, string("abc"))
        );
        assert_eq!(
            listing.instructions[&100].paths[0].effects[3],
            Effect::Set(4, string("xyz"))
        );
    }
}
