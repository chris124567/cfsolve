//! Recovers result fields whose reference names are held in header registers rather than
//! appearing among a probe's collection strings.

use std::collections::{BTreeMap, BTreeSet};

use swc_core::ecma::ast::BinaryOp;

use crate::listing::Index;
use crate::stage2::reference::{
    COMPUTED_STYLE_MAP, FONT_CANVAS_OUTPUTS, FONT_DOM_OUTPUTS, FONT_FACE_OUTPUTS,
    NATIVE_INSPECTION_OUTPUTS,
};
use crate::vm::{Constant, Term};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Object {
    Created(u32),
    Property(u32),
    Cell(u32),
}

#[derive(Default)]
struct Fields {
    names: Vec<String>,
    values: Vec<Vec<Term>>,
}

impl Fields {
    fn push(&mut self, name: &str, value: Option<Term>) {
        let position = self
            .names
            .iter()
            .position(|field| field == name)
            .unwrap_or_else(|| {
                self.names.push(name.to_owned());
                self.values.push(Vec::new());
                self.names.len() - 1
            });
        self.values[position].extend(value);
    }

    fn has(&self, position: usize, predicate: impl Fn(&Term) -> bool) -> bool {
        self.values
            .get(position)
            .is_some_and(|values| values.iter().any(predicate))
    }
}

pub(super) fn names(
    index: &Index<'_>,
    entry: u32,
    reference: usize,
    common: &BTreeSet<String>,
) -> Vec<(String, &'static str)> {
    if !matches!(reference, 22 | 23 | 27 | 37) {
        return Vec::new();
    }
    let reached = index.reachable(entry);
    if reference == 37 {
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
                            && store.key.starts_with('_')
                            && store.key.len() == 25
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
        if !store.key.starts_with('_') || store.key.len() != 25 || common.contains(&store.key) {
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
                    .names
                    .iter()
                    .take(names.len())
                    .cloned()
                    .zip(names.iter().copied()),
            );
        }
    };
    match reference {
        22 => pin(
            groups
                .iter()
                .filter_map(|(object, fields)| {
                    (matches!(object, Object::Property(_)) && fields.names.len() == 5)
                        .then_some(fields)
                })
                .collect(),
            &NATIVE_INSPECTION_OUTPUTS,
        ),
        27 => pin(
            groups
                .iter()
                .filter_map(|(object, fields)| {
                    (matches!(object, Object::Property(_)) && fields.names.len() == 1)
                        .then_some(fields)
                })
                .collect(),
            &[COMPUTED_STYLE_MAP],
        ),
        23 => {
            // FontFace's fallback is a list, a count, a status, a hash and an error.
            pin(
                groups
                    .iter()
                    .filter_map(|(object, fields)| {
                        (matches!(object, Object::Created(_))
                            && fields.names.len() == 5
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
            pin(groups.iter().filter_map(|(object, fields)| {
                (matches!(object, Object::Created(_)) && fields.names.len() == 3
                    && (0..3).all(|position| fields.has(position, |value| matches!(value, Term::Array(values) if values.is_empty()))))
                    .then_some(fields)
            }).collect(), &FONT_CANVAS_OUTPUTS);
            // The DOM measurement callback writes an array and a sum into its shared result.
            pin(
                groups
                    .iter()
                    .filter_map(|(object, fields)| {
                        (matches!(object, Object::Cell(_))
                            && fields.names.len() == 2
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
