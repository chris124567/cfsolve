//! Recovers result fields whose reference names are held in header registers rather than
//! appearing among a probe's collection strings.

use std::collections::{BTreeMap, BTreeSet};

use indexmap::IndexMap;
use swc_core::ecma::ast::BinaryOp;

use crate::listing::Index;
use crate::stage2::reference::{
    COMPUTED_STYLE_MAP, FONT_CANVAS_OUTPUTS, FONT_DOM_OUTPUTS, FONT_FACE_OUTPUTS,
    NATIVE_INSPECTION_OUTPUTS,
};
use crate::stage2::{registry::Kind, vocabulary::hashed_name};
use crate::vm::{Constant, Term};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Object {
    Created(u32),
    Property(u32),
    Cell(u32),
}

#[derive(Default)]
struct Fields(IndexMap<String, Vec<Term>>);

impl Fields {
    fn push(&mut self, name: &str, value: Option<Term>) {
        self.0.entry(name.to_owned()).or_default().extend(value);
    }

    fn has(&self, position: usize, predicate: impl Fn(&Term) -> bool) -> bool {
        self.0
            .get_index(position)
            .is_some_and(|(_, values)| values.iter().any(predicate))
    }
}

pub(super) fn names(
    index: &Index<'_>,
    entry: u32,
    reference: usize,
    common: &BTreeSet<String>,
) -> Vec<(String, &'static str)> {
    let Some(
        kind @ (Kind::NativeInspection
        | Kind::FontEnumeration
        | Kind::ComputedStyleHash
        | Kind::Rects),
    ) = Kind::from_reference(reference)
    else {
        return Vec::new();
    };
    let reached = index.reachable(entry);
    if kind == Kind::Rects {
        let roles = [
            ("bottom", "Cmnj0"),
            ("height", "VwYDD8"),
            ("left", "knUS7"),
            ("right", "cyNU4"),
            ("top", "nCLYc7"),
            ("width", "UCluM4"),
            ("x", "YptYf3"),
            ("y", "wAVRH3"),
        ];
        return roles
            .into_iter()
            .filter_map(|(property, reference)| {
                let names: BTreeSet<_> = index
                    .stores()
                    .iter()
                    .filter(|store| {
                        reached.contains(&store.pc)
                            && hashed_name(&store.key)
                            && index.method(store.pc, &store.value).as_deref() == Some(property)
                    })
                    .map(|store| store.key.clone())
                    .collect();
                (names.len() == 1).then(|| (names.into_iter().next().unwrap(), reference))
            })
            .collect();
    }
    let mut groups = BTreeMap::<Object, Fields>::new();
    for store in index
        .stores()
        .iter()
        .filter(|store| reached.contains(&store.pc))
    {
        if !hashed_name(&store.key) || common.contains(&store.key) {
            continue;
        }
        let Some((origin, object)) = index.dereference(store.pc, &Term::Reg(store.object)) else {
            continue;
        };
        let object = match object {
            Term::Object(_) => Object::Created(origin),
            Term::Get(_, _) => Object::Property(origin),
            Term::Cell(cell) => Object::Cell(cell),
            _ => continue,
        };
        let value = index
            .dereference(store.pc, &store.value)
            .map(|(_, value)| value);
        groups.entry(object).or_default().push(&store.key, value);
    }
    let mut pairs = Vec::new();
    let mut pin = |candidates: Vec<&Fields>, names: &[&'static str]| {
        if let [fields] = candidates.as_slice() {
            pairs.extend(
                fields
                    .0
                    .keys()
                    .take(names.len())
                    .cloned()
                    .zip(names.iter().copied()),
            );
        }
    };
    match kind {
        Kind::NativeInspection => pin(
            groups
                .iter()
                .filter_map(|(object, fields)| {
                    (matches!(object, Object::Property(_)) && fields.0.len() == 5).then_some(fields)
                })
                .collect(),
            &NATIVE_INSPECTION_OUTPUTS,
        ),
        Kind::ComputedStyleHash => pin(
            groups
                .iter()
                .filter_map(|(object, fields)| {
                    (matches!(object, Object::Property(_)) && fields.0.len() == 1).then_some(fields)
                })
                .collect(),
            &[COMPUTED_STYLE_MAP],
        ),
        Kind::FontEnumeration => {
            // FontFace's fallback is a list, a count, a status, a hash and an error.
            pin(
                groups
                    .iter()
                    .filter_map(|(object, fields)| {
                        (matches!(object, Object::Created(_))
                            && fields.0.len() == 5
                            && fields.has(
                                0,
                                |value| matches!(value, Term::Array(values) if values.is_empty()),
                            )
                            && fields.has(1, |value| {
                                matches!(value, Term::Const(Constant::Number(0.0)))
                            }))
                        .then_some(fields)
                    })
                    .collect(),
                &FONT_FACE_OUTPUTS,
            );
            // Canvas measurements have three array defaults.
            pin(
                groups
                    .iter()
                    .filter_map(|(object, fields)| {
                        let arrays = (0..3).all(|position| {
                            fields.has(
                                position,
                                |value| matches!(value, Term::Array(values) if values.is_empty()),
                            )
                        });
                        (matches!(object, Object::Created(_)) && fields.0.len() == 3 && arrays)
                            .then_some(fields)
                    })
                    .collect(),
                &FONT_CANVAS_OUTPUTS,
            );
            // The DOM measurement callback writes an array and a sum into its shared result.
            pin(
                groups
                    .iter()
                    .filter_map(|(object, fields)| {
                        (matches!(object, Object::Cell(_))
                            && fields.0.len() == 2
                            && fields.has(
                                0,
                                |value| matches!(value, Term::Array(values) if values.is_empty()),
                            )
                            && fields.has(1, |value| {
                                matches!(value, Term::Binary(BinaryOp::Add, _, _))
                            }))
                        .then_some(fields)
                    })
                    .collect(),
                &FONT_DOM_OUTPUTS,
            );
        }
        _ => {}
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{Effect, Exit, Instruction, Listing, Path};

    fn listing(groups: &[(Term, Vec<Term>)]) -> Listing {
        let mut effects = Vec::new();
        for (group, (object, values)) in groups.iter().enumerate() {
            effects.push(Effect::Set(1, object.clone()));
            for (position, value) in values.iter().enumerate() {
                effects.push(Effect::SetProperty {
                    object: Box::new(Term::Reg(1)),
                    key: Box::new(Term::Const(Constant::String(format!(
                        "_{:024x}",
                        group * 10 + position
                    )))),
                    value: Box::new(value.clone()),
                });
            }
        }
        let count = effects.len();
        let instructions = effects
            .into_iter()
            .enumerate()
            .map(|(pc, effect)| {
                (
                    pc as u32,
                    Instruction {
                        pc: pc as u32,
                        key: 0,
                        opcode: 0,
                        paths: vec![Path {
                            conditions: vec![],
                            effects: vec![effect],
                            exit: if pc + 1 == count {
                                Exit::Return
                            } else {
                                Exit::Next {
                                    pc: pc as u32 + 1,
                                    key: 0,
                                }
                            },
                        }],
                    },
                )
            })
            .collect();
        Listing {
            instructions,
            ..Listing::default()
        }
    }

    #[test]
    fn recovers_font_roles_from_distinct_object_shapes_and_rejects_ambiguity() {
        let empty = Term::Array(vec![]);
        let zero = Term::Const(Constant::Number(0.0));
        let face = (
            Term::Object(vec![]),
            vec![
                empty.clone(),
                zero.clone(),
                zero.clone(),
                zero.clone(),
                zero.clone(),
            ],
        );
        let mut groups = vec![
            face.clone(),
            (Term::Object(vec![]), vec![empty.clone(); 3]),
            (
                Term::Cell(8),
                vec![
                    empty,
                    Term::Binary(BinaryOp::Add, Box::new(Term::Reg(9)), Box::new(zero)),
                ],
            ),
        ];
        let reference = Kind::FontEnumeration.references()[0];
        let program = listing(&groups);
        let pairs = names(&Index::new(&program), 0, reference, &BTreeSet::new());
        let expected: Vec<_> = FONT_FACE_OUTPUTS
            .into_iter()
            .chain(FONT_CANVAS_OUTPUTS)
            .chain(FONT_DOM_OUTPUTS)
            .collect();
        assert_eq!(
            pairs
                .iter()
                .map(|(_, reference)| *reference)
                .collect::<Vec<_>>(),
            expected
        );
        groups.push(face);
        let program = listing(&groups);
        let pairs = names(&Index::new(&program), 0, reference, &BTreeSet::new());
        assert!(
            pairs
                .iter()
                .all(|(_, field)| !FONT_FACE_OUTPUTS.contains(field))
        );
        assert_eq!(
            pairs.len(),
            FONT_CANVAS_OUTPUTS.len() + FONT_DOM_OUTPUTS.len()
        );
    }

    #[test]
    fn native_inspection_requires_a_unique_result_object() {
        let object = Term::Get(
            Box::new(Term::Cell(8)),
            Box::new(Term::Const(Constant::String("result".into()))),
        );
        let group = (object, vec![Term::Const(Constant::Null); 5]);
        let program = listing(std::slice::from_ref(&group));
        let reference = Kind::NativeInspection.references()[0];
        let pairs = names(&Index::new(&program), 0, reference, &BTreeSet::new());
        assert_eq!(
            pairs
                .iter()
                .map(|(_, reference)| *reference)
                .collect::<Vec<_>>(),
            NATIVE_INSPECTION_OUTPUTS
        );
        let program = listing(&[group.clone(), group]);
        assert!(names(&Index::new(&program), 0, reference, &BTreeSet::new()).is_empty());
    }
}
