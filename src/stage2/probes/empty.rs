//! The wrapper whose successful path only changes status and timing.

use std::collections::BTreeSet;
use std::ops::ControlFlow;

use crate::js::JsValue;
use crate::listing::fold::{Frame, Known};
use crate::stage2::analysis::recognize::ProbeView;
use crate::stage2::records::{COMPLETED_STATUS, INITIAL_STATUS};
use crate::vm::{Constant, Effect, Exit, Listing, Term, dataflow};

/// Array methods the wrapper calls on its own state.
const ARRAY_METHODS: [&str; 5] = ["eval", "slice", "push", "pop", "length"];

pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<()> {
    empty_probe(probe.index.listing(), probe.entry, probe.wrapper).then_some(())
}

/// Recognizes probes whose successful path writes only status and timing. Requires a positive
/// match because an unknown probe family may still produce results. `wrapper` contains the shared
/// strings used for wrapper reads and writes. Builds rename these strings together.
fn empty_probe(listing: &Listing, entry: u32, wrapper: &BTreeSet<String>) -> bool {
    let mut closures = BTreeSet::new();
    let registers: Frame = Frame::default();
    let reached = dataflow::forward(listing, [(entry, registers)], |_, path, registers| {
        // A path that throws, such as a check that a callee is a function,
        // is not the successful one.
        if path.exit == Exit::Throw {
            return ControlFlow::Continue(true);
        }
        for effect in &path.effects {
            if let Effect::SetProperty { object, key, value } = effect {
                // A return restores the VM's register stack length.
                let stack_restore = path.exit == Exit::Return
                    && matches!(**object, Term::Reg(_))
                    && matches!(&**key, Term::Const(Constant::String(name)) if name == "length");
                let key = registers.resolve(key);
                let value = registers.resolve(value);
                let wrapper_write = matches!(&key,
                        Some(Known::Literal(JsValue::String(name))) if wrapper.contains(name))
                    || matches!(&value, Some(Known::Literal(JsValue::Number(number)))
                    if [INITIAL_STATUS, COMPLETED_STATUS].map(f64::from).contains(number))
                    || matches!(&value, Some(Known::Literal(JsValue::String(text)))
                        if text.len() <= 16
                            && text.bytes().all(|byte| byte.is_ascii_alphanumeric()));
                if !stack_restore && !wrapper_write {
                    return ControlFlow::Break(());
                }
            }
            let mut extra_work = false;
            effect.visit_terms(&mut |term| match term {
                Term::Closure { pc, .. } => {
                    closures.insert(*pc);
                }
                Term::Get(_, key) if let Term::Const(Constant::String(name)) = &**key => {
                    extra_work |=
                        !wrapper.contains(name) && !ARRAY_METHODS.contains(&name.as_str());
                }
                Term::New { .. } => extra_work = true,
                _ => {}
            });
            if extra_work {
                return ControlFlow::Break(());
            }
            if let Effect::Set(register, value) = effect {
                registers.set(*register, registers.resolve(value));
            }
        }
        ControlFlow::Continue(true)
    });
    // Every wrapper path must stay within decoded instructions.
    matches!(reached, ControlFlow::Continue(reached)
        if reached.keys().all(|pc| listing.instructions.contains_key(pc)))
        && closures.len() == 1
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::vm::{Instruction, Path};

    #[test]
    fn empty_wrapper_resolves_register_constants_but_rejects_collection_work() {
        let set_property = |key, value| Effect::SetProperty {
            object: Box::new(Term::Reg(9)),
            key: Box::new(key),
            value: Box::new(value),
        };
        let effects = vec![
            Effect::Set(
                1,
                Term::Closure {
                    pc: 100,
                    key: 0,
                    parameters: Vec::new(),
                    arity: 0,
                },
            ),
            Effect::Set(2, Term::Const(Constant::String("collector".into()))),
            set_property(Term::Reg(2), Term::Reg(1)),
            Effect::Set(3, Term::Const(Constant::Number(3.0))),
            set_property(Term::Reg(7), Term::Reg(3)),
        ];
        let mut listing = Listing {
            instructions: BTreeMap::from([(
                0,
                Instruction {
                    pc: 0,
                    key: 0,
                    opcode: 0,
                    paths: vec![Path {
                        conditions: Vec::new(),
                        effects,
                        exit: Exit::Return,
                    }],
                },
            )]),
            ..Listing::default()
        };
        let wrapper = BTreeSet::from(["collector".to_owned()]);
        assert!(empty_probe(&listing, 0, &wrapper));
        let path = &mut listing.instructions.get_mut(&0).unwrap().paths[0];
        path.effects.push(set_property(
            Term::Const(Constant::String("collected".into())),
            Term::Reg(20),
        ));
        assert!(!empty_probe(&listing, 0, &wrapper));
    }
}
